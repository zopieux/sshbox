package sshbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

type SessionContext struct {
	Command        string
	IsPty          bool
	Term           string
	Rows           uint32
	Cols           uint32
	WinCh          <-chan WindowChange
	Env            []string
	Binds          []BindMount
	PackageBinPath string
	EnableGPU      bool
	EnableNet      bool
}

type WindowChange struct {
	Rows uint32
	Cols uint32
}

func getBwrapPath() (string, error) {
	if custom := os.Getenv("BWRAP"); custom != "" {
		return custom, nil
	}
	for _, p := range []string{
		"bwrap",
		"/run/current-system/sw/bin/bwrap",
		"/bin/bwrap",
		"/usr/bin/bwrap",
	} {
		if path, err := exec.LookPath(p); err == nil {
			return path, nil
		}
	}
	return "", errors.New("bubblewrap (bwrap) not found in PATH")
}

func runInBwrap(channel ssh.Channel, dir string, sCtx SessionContext) error {
	bwrapPath, err := getBwrapPath()
	if err != nil {
		return err
	}

	containerHome := filepath.Join(dir, ".home")
	if err := os.MkdirAll(containerHome, 0755); err != nil {
		return fmt.Errorf("create container home: %w", err)
	}

	// Prepare passwd and group data for bubblewrap FDs 3 and 4
	uid := os.Getuid()
	gid := os.Getgid()
	passwdContent := fmt.Sprintf(
		"root:x:0:0:root:/root:/bin/sh\nsshbox:x:%d:%d:Sshbox User:/home/sshbox:/bin/sh\nnobody:x:65534:65534:Nobody:/:/bin/false\n",
		uid, gid,
	)
	groupContent := fmt.Sprintf(
		"root:x:0:\nsshbox:x:%d:\nnogroup:x:65534:\n",
		gid,
	)

	rPasswd, wPasswd, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create passwd pipe: %w", err)
	}
	defer rPasswd.Close()
	go func() {
		defer wPasswd.Close()
		_, _ = wPasswd.WriteString(passwdContent)
	}()

	rGroup, wGroup, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create group pipe: %w", err)
	}
	defer rGroup.Close()
	go func() {
		defer wGroup.Close()
		_, _ = wGroup.WriteString(groupContent)
	}()

	// Empty read pipe for masking files via FD 5 with --ro-bind-data
	rEmpty, wEmpty, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create empty pipe: %w", err)
	}
	defer rEmpty.Close()
	_ = wEmpty.Close()

	// Build PATH for the sandbox
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/run/current-system/sw/bin:/bin:/usr/bin"
	} else if !strings.Contains(pathEnv, "/bin") {
		pathEnv = pathEnv + ":/run/current-system/sw/bin:/bin:/usr/bin"
	}
	if sCtx.PackageBinPath != "" {
		pathEnv = sCtx.PackageBinPath + ":" + pathEnv
	}

	term := sCtx.Term
	if term == "" {
		term = "xterm-256color"
	}

	args := []string{
		"--die-with-parent",
	}
	if !sCtx.IsPty {
		args = append(args, "--new-session")
	}
	args = append(args,
		"--hostname", "sshbox",
	)

	if sCtx.EnableGPU {
		args = append(args,
			"--dev-bind", "/dev", "/dev",
			"--ro-bind-try", "/run/opengl-driver", "/run/opengl-driver",
			"--ro-bind-try", "/run/opengl-driver-32", "/run/opengl-driver-32",
		)
	} else {
		args = append(args,
			"--dev", "/dev",
		)
	}

	args = append(args,
		"--proc", "/proc",
		"--ro-bind-try", "/sys", "/sys",
		"--tmpfs", "/tmp",
		"--ro-bind-try", "/nix/store", "/nix/store",
		"--ro-bind-try", "/nix/var", "/nix/var",
		"--ro-bind-try", "/run/current-system", "/run/current-system",
		"--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/usr/bin", "/usr/bin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/usr/lib", "/usr/lib",
		"--ro-bind-try", "/usr/lib64", "/usr/lib64",
		"--ro-bind-try", "/usr/share", "/usr/share",
		"--ro-bind-try", "/.host-etc", "/.host-etc",
		"--tmpfs", "/etc",
		"--perms", "0444", "--bind-data", "3", "/etc/passwd",
		"--perms", "0444", "--bind-data", "4", "/etc/group",
		"--ro-bind-try", "/etc/static", "/etc/static",
		"--ro-bind-try", "/etc/nix", "/etc/nix",
		"--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/hosts", "/etc/hosts",
		"--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl",
		"--ro-bind-try", "/etc/pki", "/etc/pki",
		"--ro-bind-try", "/etc/localtime", "/etc/localtime",
		"--remount-ro", "/etc",
		// Read-write bind of current directory to /work
		"--bind", dir, "/work",
		// Container home directory
		"--dir", "/home/sshbox",
		"--bind", containerHome, "/home/sshbox",
	)

	// Apply custom bind mounts from configuration
	for _, bm := range sCtx.Binds {
		args = append(args, "--dir", filepath.Dir(bm.JailPath))
		if bm.ReadWrite {
			args = append(args, "--bind-try", bm.HostPath, bm.JailPath)
		} else {
			args = append(args, "--ro-bind-try", bm.HostPath, bm.JailPath)
		}
	}

	args = append(args,
		// Hide .home inside /work by mounting an empty read-only tmpfs over it
		"--tmpfs", "/work/.home",
		"--remount-ro", "/work/.home",
		// Bind .sshbox.toml read-only to empty data via FD 5
		"--perms", "0444", "--ro-bind-data", "5", "/work/.sshbox.toml",
		"--chdir", "/work",
		"--clearenv",
		"--setenv", "USER", "sshbox",
		"--setenv", "LOGNAME", "sshbox",
		"--setenv", "HOME", "/home/sshbox",
		"--setenv", "PWD", "/work",
		"--setenv", "SHELL", "/bin/sh",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "TERM", term,
		"--setenv", "LANG", "C.UTF-8",
		"--setenv", "PATH", pathEnv,
	)

	if colorTerm := os.Getenv("COLORTERM"); colorTerm != "" {
		args = append(args, "--setenv", "COLORTERM", colorTerm)
	}

	hasNix := false
	if _, err := os.Stat("/nix/store"); err == nil {
		hasNix = true
	} else if sCtx.PackageBinPath != "" {
		hasNix = true
	} else if _, err := exec.LookPath("nix"); err == nil {
		hasNix = true
	}

	// SSL certificates
	sslCertFile := os.Getenv("SSL_CERT_FILE")
	if sslCertFile == "" {
		for _, certPath := range []string{
			"/etc/ssl/certs/ca-bundle.crt",
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
		} {
			if _, err := os.Stat(certPath); err == nil {
				sslCertFile = certPath
				break
			}
		}
	}
	if sslCertFile != "" {
		args = append(args, "--setenv", "SSL_CERT_FILE", sslCertFile)
	}

	// Nix-specific environment variables: only set if non-empty or when Nix is present
	if hasNix {
		nixSSLCert := os.Getenv("NIX_SSL_CERT_FILE")
		if nixSSLCert == "" {
			nixSSLCert = sslCertFile
		}
		if nixSSLCert != "" {
			args = append(args, "--setenv", "NIX_SSL_CERT_FILE", nixSSLCert)
		}

		nixConfig := os.Getenv("NIX_CONFIG")
		if nixConfig == "" {
			nixConfig = "extra-experimental-features = nix-command flakes"
		}
		args = append(args, "--setenv", "NIX_CONFIG", nixConfig)
	} else {
		if nixSSLCert := os.Getenv("NIX_SSL_CERT_FILE"); nixSSLCert != "" {
			args = append(args, "--setenv", "NIX_SSL_CERT_FILE", nixSSLCert)
		}
		if nixConfig := os.Getenv("NIX_CONFIG"); nixConfig != "" {
			args = append(args, "--setenv", "NIX_CONFIG", nixConfig)
		}
	}

	if nixPath := os.Getenv("NIX_PATH"); nixPath != "" {
		args = append(args, "--setenv", "NIX_PATH", nixPath)
	}

	args = append(args, "--unshare-all")

	if sCtx.EnableNet {
		args = append(args, "--share-net")
	}

	// Choose shell
	shell := "sh"
	if _, err := exec.LookPath("bash"); err == nil {
		shell = "bash"
	}

	if sCtx.Command != "" {
		args = append(args, shell, "-c", sCtx.Command)
	} else {
		args = append(args, shell, "-l")
	}

	cmd := exec.Command(bwrapPath, args...)
	// ExtraFiles are mapped to file descriptors 3 (passwd), 4 (group), 5 (empty)
	cmd.ExtraFiles = []*os.File{rPasswd, rGroup, rEmpty}

	if sCtx.IsPty {
		ws := &pty.Winsize{
			Rows: uint16(sCtx.Rows),
			Cols: uint16(sCtx.Cols),
		}
		if ws.Rows == 0 {
			ws.Rows = 24
		}
		if ws.Cols == 0 {
			ws.Cols = 80
		}

		ptmx, err := pty.StartWithSize(cmd, ws)
		if err != nil {
			return fmt.Errorf("start pty: %w", err)
		}
		defer ptmx.Close()

		if sCtx.WinCh != nil {
			go func() {
				for win := range sCtx.WinCh {
					_ = pty.Setsize(ptmx, &pty.Winsize{
						Rows: uint16(win.Rows),
						Cols: uint16(win.Cols),
					})
				}
			}()
		}

		// Pipe PTY to/from SSH channel
		go func() {
			_, _ = io.Copy(ptmx, channel)
		}()
		_, _ = io.Copy(channel, ptmx)

		waitErr := cmd.Wait()
		sendExitStatus(channel, waitErr)
		return waitErr
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()

	if err := cmd.Start(); err != nil {
		_ = stdinPipe.Close()
		return fmt.Errorf("start process: %w", err)
	}

	go func() {
		_, _ = io.Copy(stdinPipe, channel)
		_ = stdinPipe.Close()
	}()

	waitErr := cmd.Wait()
	sendExitStatus(channel, waitErr)
	return waitErr
}

func sendExitStatus(channel ssh.Channel, err error) {
	status := uint32(0)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				status = uint32(ws.ExitStatus())
			} else {
				status = 1
			}
		} else {
			status = 1
		}
	}

	msg := struct {
		Status uint32
	}{
		Status: status,
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&msg))
}
