package sshbox

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"

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
	Config    *Config
	SSHConfig *ssh.ServerConfig
	WorkDir   string
}

func NewServer(workDir string) (*Server, error) {
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("determine absolute path for %s: %w", workDir, err)
	}

	cfg, hostSigner, err := LoadOrInitConfig(absWorkDir)
	if err != nil {
		return nil, fmt.Errorf("initialize config: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if cfg.Authenticate(key) {
				log.Printf("Accepted public key authentication for user %q (%s)", conn.User(), key.Type())
				return nil, nil
			}
			log.Printf("Rejected authentication for user %q: public key not in .bashbox.toml", conn.User())
			return nil, fmt.Errorf("public key authentication failed")
		},
	}
	sshConfig.AddHostKey(hostSigner)

	fingerprint := ssh.FingerprintSHA256(hostSigner.PublicKey())
	log.Printf("Host key fingerprint: %s", fingerprint)

	return &Server{
		Config:    cfg,
		SSHConfig: sshConfig,
		WorkDir:   absWorkDir,
	}, nil
}

func (s *Server) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn, s.SSHConfig, s.WorkDir)
	}
}

func handleConn(tcpConn net.Conn, sshConfig *ssh.ServerConfig, workDir string) {
	defer tcpConn.Close()

	serverConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
	if err != nil {
		log.Printf("SSH handshake failed from %s: %v", tcpConn.RemoteAddr(), err)
		return
	}
	defer serverConn.Close()

	log.Printf("Connection established from %s (user: %q)", serverConn.RemoteAddr(), serverConn.User())
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Failed to accept session channel: %v", err)
			return
		}

		go handleSession(channel, requests, workDir)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, workDir string) {
	defer channel.Close()

	winCh := make(chan WindowChange, 16)
	sCtx := SessionContext{
		WinCh: winCh,
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
				_ = req.Reply(true, nil)
			} else {
				_ = req.Reply(false, nil)
			}

		case "window-change":
			var msg winChangeMsg
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				sCtx.Cols = msg.Cols
				sCtx.Rows = msg.Rows
				select {
				case winCh <- WindowChange{Rows: msg.Rows, Cols: msg.Cols}:
				default:
				}
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
			if err := runInBwrap(channel, workDir, sCtx); err != nil {
				log.Printf("Bubblewrap interactive shell finished with error: %v", err)
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
				log.Printf("Handling SCP request: %s", msg.Command)
				if err := handleSCP(channel, workDir, cmdArgs[1:]); err != nil {
					log.Printf("SCP command %q finished with error: %v", msg.Command, err)
				}
				return
			}

			sCtx.Command = msg.Command
			if err := runInBwrap(channel, workDir, sCtx); err != nil {
				log.Printf("Bubblewrap exec command %q finished with error: %v", msg.Command, err)
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
