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

func getEmptyFilePath() (string, error) {
	emptyPath := filepath.Join(os.TempDir(), "sshbox-empty-bind")
	if _, err := os.Stat(emptyPath); err == nil {
		return emptyPath, nil
	}
	if err := os.WriteFile(emptyPath, []byte{}, 0644); err != nil {
		return "", fmt.Errorf("create empty mask file: %w", err)
	}
	return emptyPath, nil
}

func getEmptyDirPath() (string, error) {
	emptyDir := filepath.Join(os.TempDir(), "sshbox-empty-dir")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		return "", fmt.Errorf("create empty mask dir: %w", err)
	}
	return emptyDir, nil
}

func runInBwrap(channel ssh.Channel, dir string, sCtx SessionContext) error {
	bwrapPath, err := getBwrapPath()
	if err != nil {
		return err
	}

	emptyMaskFile, err := getEmptyFilePath()
	if err != nil {
		return err
	}

	emptyMaskDir, err := getEmptyDirPath()
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
		"root:x:0:0:root:/root:/bin/sh\nbashbox:x:%d:%d:Bashbox User:/home/bashbox:/bin/sh\nnobody:x:65534:65534:Nobody:/:/bin/false\n",
		uid, gid,
	)
	groupContent := fmt.Sprintf(
		"root:x:0:\nbashbox:x:%d:\nnogroup:x:65534:\n",
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
		"--hostname", "bashbox",
		"--dev-bind", "/dev", "/dev",
		"--proc", "/proc",
		"--ro-bind-try", "/sys", "/sys",
		"--tmpfs", "/tmp",
		"--ro-bind", "/nix/store", "/nix/store",
		"--ro-bind-try", "/nix/var", "/nix/var",
		"--ro-bind-try", "/run/current-system", "/run/current-system",
		"--ro-bind-try", "/run/opengl-driver", "/run/opengl-driver",
		"--ro-bind-try", "/run/opengl-driver-32", "/run/opengl-driver-32",
		"--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/usr/bin", "/usr/bin",
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
		// Read-write bind of current directory to /work
		"--bind", dir, "/work",
		// Container home directory
		"--dir", "/home/bashbox",
		"--bind", containerHome, "/home/bashbox",
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
		// Hide .home inside /work by binding an empty read-only directory over it
		"--ro-bind", emptyMaskDir, "/work/.home",
		// Bind .bashbox.toml read-only to an empty file so it's inaccessible inside the sandbox
		"--ro-bind", emptyMaskFile, "/work/.bashbox.toml",
		"--chdir", "/work",
		"--clearenv",
		"--setenv", "USER", "bashbox",
		"--setenv", "LOGNAME", "bashbox",
		"--setenv", "HOME", "/home/bashbox",
		"--setenv", "PWD", "/work",
		"--setenv", "SHELL", "/bin/sh",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "TERM", term,
		"--setenv", "COLORTERM", os.Getenv("COLORTERM"),
		"--setenv", "LANG", "C.UTF-8",
		"--setenv", "SSL_CERT_FILE", "/etc/ssl/certs/ca-bundle.crt",
		"--setenv", "NIX_SSL_CERT_FILE", "/etc/ssl/certs/ca-bundle.crt",
		"--setenv", "NIX_PATH", os.Getenv("NIX_PATH"),
		"--setenv", "PATH", pathEnv,
		"--setenv", "NIX_CONFIG", "extra-experimental-features = nix-command flakes",
		"--unshare-all",
		"--share-net",
	)

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
	// ExtraFiles are mapped to file descriptors 3, 4, ...
	cmd.ExtraFiles = []*os.File{rPasswd, rGroup}

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

	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start process: %w", err)
	}

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
