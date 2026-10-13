package sshbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type ptyReqMsg struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

type winChangeMsg struct {
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
}

type execMsg struct {
	Command string
}

type envMsg struct {
	Name  string
	Value string
}

type Server struct {
	Config        *Config
	SSHConfig     *ssh.ServerConfig
	WorkDir       string
	Verbose       bool
	EnableSCP     bool
	EnableGPU     bool
	EnableNet     bool
	EnableForward bool
	OpenPortMode  OpenPortMode
	Port          int
	Monitor       Monitor
	PortForwarder *PortForwarder
}

type ServerOption func(*Server)

func WithVerbose(v bool) ServerOption {
	return func(s *Server) { s.Verbose = v }
}

func WithPort(p int) ServerOption {
	return func(s *Server) { s.Port = p }
}

func WithSCP(enable bool) ServerOption {
	return func(s *Server) { s.EnableSCP = enable }
}

func WithGPU(enable bool) ServerOption {
	return func(s *Server) { s.EnableGPU = enable }
}

func WithNet(enable bool) ServerOption {
	return func(s *Server) { s.EnableNet = enable }
}

func WithForward(enable bool) ServerOption {
	return func(s *Server) { s.EnableForward = enable }
}

func WithOpenPort(mode OpenPortMode) ServerOption {
	return func(s *Server) { s.OpenPortMode = mode }
}

func WithMonitor(m Monitor) ServerOption {
	return func(s *Server) { s.Monitor = m }
}

func NewServer(workDir string, opts ...ServerOption) (*Server, error) {
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("determine absolute path for %s: %w", workDir, err)
	}

	cfg, hostSigner, err := LoadOrInitConfig(absWorkDir)
	if err != nil {
		return nil, fmt.Errorf("initialize config: %w", err)
	}

	srv := &Server{
		Config:  cfg,
		WorkDir: absWorkDir,
		Port:    cfg.GetPort(),
	}

	if cfg.SCP != nil {
		srv.EnableSCP = *cfg.SCP
	}
	if cfg.GPU != nil {
		srv.EnableGPU = *cfg.GPU
	}
	if cfg.Net != nil {
		srv.EnableNet = *cfg.Net
	}
	if cfg.Forward != nil {
		srv.EnableForward = *cfg.Forward
	}
	srv.OpenPortMode = cfg.GetOpenPortMode()

	for _, opt := range opts {
		opt(srv)
	}

	if srv.Monitor == nil {
		srv.Monitor = NewPlainMonitor(srv.Verbose)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if cfg.Authenticate(key) {
				srv.Monitor.Log("Accepted public key authentication for user %q (%s)", conn.User(), key.Type())
				return nil, nil
			}
			srv.Monitor.Log("Rejected authentication for user %q from %s: public key not in .sshbox.toml", conn.User(), conn.RemoteAddr())
			return nil, fmt.Errorf("public key authentication failed")
		},
	}
	sshConfig.AddHostKey(hostSigner)
	srv.SSHConfig = sshConfig

	fingerprint := ssh.FingerprintSHA256(hostSigner.PublicKey())
	srv.Monitor.Log("Host key fingerprint: %s", fingerprint)

	pkgs := cfg.Packages
	if srv.EnableSCP {
		hasOpenSSH := false
		for _, p := range pkgs {
			if p == "openssh" {
				hasOpenSSH = true
				break
			}
		}
		if !hasOpenSSH {
			pkgs = append([]string{"openssh"}, pkgs...)
		}
	}

	if len(pkgs) > 0 {
		binPath, err := BuildNixEnv(pkgs)
		if err != nil {
			srv.Monitor.Log("Warning: failed to build nix packages environment: %v", err)
			if srv.EnableSCP && cfg.PackageBinPath == "" {
				if hostSCP, err := exec.LookPath("scp"); err == nil {
					cfg.PackageBinPath = filepath.Dir(hostSCP)
				}
			}
		} else if binPath != "" {
			cfg.PackageBinPath = binPath
			srv.Monitor.Log("Nix environment prepared: %s", binPath)
		}
	} else if srv.EnableSCP {
		if hostSCP, err := exec.LookPath("scp"); err == nil {
			cfg.PackageBinPath = filepath.Dir(hostSCP)
		}
	}

	return srv, nil
}

func (s *Server) OpenPortForward() {
	if s.OpenPortMode == OpenPortNone {
		return
	}
	if s.PortForwarder == nil {
		s.PortForwarder = NewPortForwarder(s.Port, s.OpenPortMode, s.Monitor)
	}
	s.PortForwarder.Open()
}

func (s *Server) ClosePortForward() {
	if s.PortForwarder != nil {
		s.PortForwarder.Close()
	}
}

func (s *Server) Serve(listener net.Listener) error {
	if s.OpenPortMode != OpenPortNone {
		s.OpenPortForward()
		defer s.ClosePortForward()
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		sess := s.Monitor.NewSession(conn.RemoteAddr().String())
		sess.SetJail(s.WorkDir, s.Port)
		go handleConn(conn, s, sess)
	}
}

func handleConn(tcpConn net.Conn, srv *Server, sess SessionHandle) {
	defer tcpConn.Close()
	defer sess.Close()

	serverConn, chans, reqs, err := ssh.NewServerConn(tcpConn, srv.SSHConfig)
	if err != nil {
		sess.Log("SSH handshake failed: %v", err)
		return
	}
	defer serverConn.Close()

	sess.SetUser(serverConn.User())
	sess.Log("Connection established (user: %q)", serverConn.User())
	sess.SetCloseFunc(func() {
		_ = serverConn.Close()
		_ = tcpConn.Close()
	})

	if srv.EnableForward {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go handleGlobalRequests(ctx, serverConn, reqs, srv, sess)
	} else {
		go ssh.DiscardRequests(reqs)
	}

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			sess.Log("Failed to accept session channel: %v", err)
			return
		}

		go handleSession(channel, requests, srv, sess)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, srv *Server, sess SessionHandle) {
	defer channel.Close()

	winCh := make(chan WindowChange, 16)
	var winChMu sync.Mutex
	winChClosed := false
	closeWinCh := func() {
		winChMu.Lock()
		defer winChMu.Unlock()
		if !winChClosed {
			winChClosed = true
			close(winCh)
		}
	}
	defer closeWinCh()

	drainRequests := func() {
		for r := range requests {
			if r.Type == "window-change" {
				var msg winChangeMsg
				if err := ssh.Unmarshal(r.Payload, &msg); err == nil {
					winChMu.Lock()
					if !winChClosed {
						select {
						case winCh <- WindowChange{Rows: msg.Rows, Cols: msg.Cols}:
						default:
						}
					}
					winChMu.Unlock()
					_ = r.Reply(true, nil)
				} else {
					_ = r.Reply(false, nil)
				}
			} else {
				_ = r.Reply(false, nil)
			}
		}
	}

	sCtx := SessionContext{
		WinCh:          winCh,
		Binds:          srv.Config.ParsedBinds,
		PackageBinPath: srv.Config.PackageBinPath,
		EnableGPU:      srv.EnableGPU,
		EnableNet:      srv.EnableNet,
		SessionHandle:  sess,
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			var msg ptyReqMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				sCtx.IsPty = true
				sCtx.Term = msg.Term
				sCtx.Cols = msg.Cols
				sCtx.Rows = msg.Rows
				sess.Log("Allocated PTY (%s, %dx%d)", msg.Term, msg.Cols, msg.Rows)
				_ = req.Reply(true, nil)
			} else {
				_ = req.Reply(false, nil)
			}

		case "window-change":
			var msg winChangeMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				sCtx.Cols = msg.Cols
				sCtx.Rows = msg.Rows
				winChMu.Lock()
				if !winChClosed {
					select {
					case winCh <- WindowChange{Rows: msg.Rows, Cols: msg.Cols}:
					default:
					}
				}
				winChMu.Unlock()
				_ = req.Reply(true, nil)
			} else {
				_ = req.Reply(false, nil)
			}

		case "env":
			var msg envMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				sCtx.Env = append(sCtx.Env, fmt.Sprintf("%s=%s", msg.Name, msg.Value))
				_ = req.Reply(true, nil)
			} else {
				_ = req.Reply(false, nil)
			}

		case "shell":
			_ = req.Reply(true, nil)
			sess.SetType("shell")
			sess.Log("Executing interactive shell in jail")
			go drainRequests()
			if err := runInBwrap(channel, srv.WorkDir, sCtx); err != nil {
				sess.Log("Bubblewrap interactive shell exited with error: %v", err)
			} else {
				sess.Log("Bubblewrap interactive shell exited successfully")
			}
			return

		case "exec":
			var msg execMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)

			cmdArgs := tokenizeCommand(msg.Command)
			if len(cmdArgs) > 0 && cmdArgs[0] == "scp" {
				sess.SetType("scp")
			} else {
				sess.SetType(fmt.Sprintf("exec: %s", msg.Command))
			}
			sess.Log("Executing command: %s", msg.Command)

			if len(cmdArgs) > 0 && cmdArgs[0] == "scp" && !srv.EnableSCP {
				sess.Log("SCP command rejected: scp is disabled (enable with --scp)")
				sendExitStatus(channel, errors.New("scp is disabled on this server (enable with --scp)"))
				return
			}

			go drainRequests()
			sCtx.Command = msg.Command
			if err := runInBwrap(channel, srv.WorkDir, sCtx); err != nil {
				sess.Log("Bubblewrap exec command %q exited with error: %v", msg.Command, err)
			} else {
				sess.Log("Bubblewrap exec command %q completed successfully", msg.Command)
			}
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
}

func tokenizeCommand(cmd string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	escaped := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = true
			quoteChar = c
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteByte(c)
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

type tcpipForwardMsg struct {
	BindAddr string
	BindPort uint32
}

type tcpipForwardSuccessMsg struct {
	BindPort uint32
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func forwardKey(addr string, port uint32) string {
	return fmt.Sprintf("%s:%d", addr, port)
}

func formatHostPort(addr string, port uint32) string {
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return fmt.Sprintf("%s:%d", addr, port)
	}
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func handleGlobalRequests(ctx context.Context, serverConn *ssh.ServerConn, reqs <-chan *ssh.Request, srv *Server, sess SessionHandle) {
	var mu sync.Mutex
	listeners := make(map[string][]net.Listener)

	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		closed := make(map[net.Listener]bool)
		for _, list := range listeners {
			for _, l := range list {
				if !closed[l] {
					closed[l] = true
					_ = l.Close()
				}
			}
		}
		listeners = make(map[string][]net.Listener)
	}

	defer closeAll()

	go func() {
		<-ctx.Done()
		closeAll()
	}()

	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var msg tcpipForwardMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				_ = req.Reply(false, nil)
				continue
			}

			// Enforce security: only localhost/127.0.0.1/loopback is permitted to prevent
			// using the jail or forwarded ports to escape or expose the local network.
			var bindAddrs []string
			switch msg.BindAddr {
			case "", "localhost":
				bindAddrs = []string{"127.0.0.1", "[::1]"}
			case "127.0.0.1":
				bindAddrs = []string{"127.0.0.1"}
			case "::1", "[::1]":
				bindAddrs = []string{"[::1]"}
			default:
				sess.Log("Rejected remote forward on non-localhost address %q (only localhost/127.0.0.1 allowed)", msg.BindAddr)
				_ = req.Reply(false, nil)
				continue
			}

			var opened []net.Listener
			allocatedPort := msg.BindPort

			for _, addr := range bindAddrs {
				hostPort := formatHostPort(addr, allocatedPort)
				l, err := net.Listen("tcp", hostPort)
				if err != nil {
					if len(opened) > 0 {
						continue
					}
					continue
				}

				if allocatedPort == 0 {
					if tcpAddr, ok := l.Addr().(*net.TCPAddr); ok {
						allocatedPort = uint32(tcpAddr.Port)
					}
				}
				opened = append(opened, l)
			}

			if len(opened) == 0 {
				sess.Log("Failed to bind remote forward on %s:%d", msg.BindAddr, msg.BindPort)
				_ = req.Reply(false, nil)
				continue
			}

			sess.SetType(fmt.Sprintf("fwd: %d", allocatedPort))
			for _, l := range opened {
				sess.Log("Remote forward listening on %s (port %d)", l.Addr(), allocatedPort)
				go acceptForwardedConn(serverConn, l, msg.BindAddr, allocatedPort, srv.Verbose, sess)
			}

			key := forwardKey(msg.BindAddr, msg.BindPort)
			mu.Lock()
			listeners[key] = append(listeners[key], opened...)
			if msg.BindPort == 0 && allocatedPort != 0 {
				allocKey := forwardKey(msg.BindAddr, allocatedPort)
				listeners[allocKey] = append(listeners[allocKey], opened...)
			}
			mu.Unlock()

			var replyPayload []byte
			if msg.BindPort == 0 {
				replyPayload = ssh.Marshal(&tcpipForwardSuccessMsg{BindPort: allocatedPort})
			}
			_ = req.Reply(true, replyPayload)

		case "cancel-tcpip-forward":
			var msg tcpipForwardMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				_ = req.Reply(false, nil)
				continue
			}

			key := forwardKey(msg.BindAddr, msg.BindPort)
			mu.Lock()
			list, ok := listeners[key]
			if ok {
				delete(listeners, key)
				for _, l := range list {
					_ = l.Close()
				}
			}
			mu.Unlock()

			sess.Log("Cancelled remote forward on %s:%d (found: %v)", msg.BindAddr, msg.BindPort, ok)
			_ = req.Reply(ok, nil)

		default:
			_ = req.Reply(false, nil)
		}
	}
}

func acceptForwardedConn(serverConn *ssh.ServerConn, l net.Listener, bindAddr string, boundPort uint32, verbose bool, sess SessionHandle) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go forwardTCPConn(serverConn, conn, bindAddr, boundPort, verbose, sess)
	}
}

func forwardTCPConn(serverConn *ssh.ServerConn, localConn net.Conn, bindAddr string, boundPort uint32, verbose bool, sess SessionHandle) {
	defer localConn.Close()

	connectedAddr := bindAddr
	if connectedAddr == "" {
		if tcpAddr, ok := localConn.LocalAddr().(*net.TCPAddr); ok {
			connectedAddr = tcpAddr.IP.String()
		} else {
			connectedAddr = "127.0.0.1"
		}
	}

	originIP := "127.0.0.1"
	var originPort uint32 = 0
	if tcpAddr, ok := localConn.RemoteAddr().(*net.TCPAddr); ok {
		originIP = tcpAddr.IP.String()
		originPort = uint32(tcpAddr.Port)
	}

	payload := ssh.Marshal(&forwardedTCPPayload{
		Addr:       connectedAddr,
		Port:       boundPort,
		OriginAddr: originIP,
		OriginPort: originPort,
	})

	channel, reqs, err := serverConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		sess.Log("Failed to open forwarded-tcpip channel to client: %v", err)
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(reqs)

	sess.Log("Forwarding connection from %s to client via forwarded-tcpip (port %d)", localConn.RemoteAddr(), boundPort)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, localConn)
		_ = channel.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, channel)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
