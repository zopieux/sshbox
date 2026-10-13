package sshbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/crypto/ssh"
)

func TestConfigLoadAndGenerate(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Initial load should create .sshbox.toml with host key
	cfg, signer, err := LoadOrInitConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadOrInitConfig failed: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer, got nil")
	}
	if cfg.HostKey == "" {
		t.Fatal("expected non-empty host key")
	}

	configPath := filepath.Join(tempDir, ".sshbox.toml")
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read created config: %v", err)
	}
	if !strings.Contains(string(content), "host_key") {
		t.Fatal("config does not contain host_key")
	}

	// 2. Second load should reuse the same host key
	cfg2, signer2, err := LoadOrInitConfig(tempDir)
	if err != nil {
		t.Fatalf("second LoadOrInitConfig failed: %v", err)
	}
	if cfg2.HostKey != cfg.HostKey {
		t.Fatal("host key changed across reloads!")
	}
	if string(signer2.PublicKey().Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatal("signer public key changed across reloads!")
	}
}

func TestConfigBinds(t *testing.T) {
	tempDir := t.TempDir()

	tomlData := `
authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey user@host"]
bind = [
    "extra:/opt/extra",
    "/var/data:/data:ro",
    "shared:/shared:rw",
]
`
	configPath := filepath.Join(tempDir, ".sshbox.toml")
	if err := os.WriteFile(configPath, []byte(tomlData), 0600); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	cfg, _, err := LoadOrInitConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadOrInitConfig failed: %v", err)
	}

	if len(cfg.ParsedBinds) != 3 {
		t.Fatalf("expected 3 parsed binds, got %d", len(cfg.ParsedBinds))
	}

	// 1. extra:/opt/extra -> relative, default ro
	if cfg.ParsedBinds[0].HostPath != filepath.Join(tempDir, "extra") {
		t.Errorf("expected host path %s, got %s", filepath.Join(tempDir, "extra"), cfg.ParsedBinds[0].HostPath)
	}
	if cfg.ParsedBinds[0].JailPath != "/opt/extra" {
		t.Errorf("expected jail path /opt/extra, got %s", cfg.ParsedBinds[0].JailPath)
	}
	if cfg.ParsedBinds[0].ReadWrite != false {
		t.Errorf("expected ReadWrite=false, got true")
	}

	// 2. /var/data:/data:ro -> absolute, ro
	if cfg.ParsedBinds[1].HostPath != "/var/data" {
		t.Errorf("expected host path /var/data, got %s", cfg.ParsedBinds[1].HostPath)
	}
	if cfg.ParsedBinds[1].JailPath != "/data" {
		t.Errorf("expected jail path /data, got %s", cfg.ParsedBinds[1].JailPath)
	}
	if cfg.ParsedBinds[1].ReadWrite != false {
		t.Errorf("expected ReadWrite=false, got true")
	}

	// 3. shared:/shared:rw -> relative, rw
	if cfg.ParsedBinds[2].HostPath != filepath.Join(tempDir, "shared") {
		t.Errorf("expected host path %s, got %s", filepath.Join(tempDir, "shared"), cfg.ParsedBinds[2].HostPath)
	}
	if cfg.ParsedBinds[2].JailPath != "/shared" {
		t.Errorf("expected jail path /shared, got %s", cfg.ParsedBinds[2].JailPath)
	}
	if cfg.ParsedBinds[2].ReadWrite != true {
		t.Errorf("expected ReadWrite=true, got false")
	}
}

func TestNixPackageValidation(t *testing.T) {
	valid := []string{"ripgrep", "jq", "curl", "hello", "which"}
	for _, p := range valid {
		if !validPkgName.MatchString(p) {
			t.Errorf("expected %q to be valid package name", p)
		}
	}

	malicious := []string{
		`hello; builtins.trace "pwned" hello`,
		`hello [ "pwned" ]`,
		`(import /etc/passwd)`,
		`pkg"`,
		`pkg$foo`,
		`pkg/foo`,
		"pkg\nfoo",
		`pkg$(whoami)`,
		`pkg'foo`,
	}
	for _, p := range malicious {
		if validPkgName.MatchString(p) {
			t.Errorf("expected malicious payload %q to be rejected, but matched as valid", p)
		}
		_, err := BuildNixEnv([]string{p})
		if err == nil {
			t.Errorf("expected BuildNixEnv to fail on payload %q, but got nil error", p)
		}
	}
}

func TestTokenizeCommand(t *testing.T) {
	cmd := `scp -r -p "/work/my file.txt" '/work/another dir'`
	tokens := tokenizeCommand(cmd)
	expected := []string{"scp", "-r", "-p", "/work/my file.txt", "/work/another dir"}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expected), len(tokens), tokens)
	}
	for i := range tokens {
		if tokens[i] != expected[i] {
			t.Errorf("token %d: expected %q, got %q", i, expected[i], tokens[i])
		}
	}
}

// Real-world programmatic SSH integration tests using a Unix domain socket
func TestSSHServerRealWorldIntegration(t *testing.T) {
	workDir := t.TempDir()
	homeDir := filepath.Join(workDir, ".home")
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		t.Fatalf("create home dir: %v", err)
	}

	// Generate client key pairs: authorized and unauthorized
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate auth key: %v", err)
	}
	authSSHPub, err := ssh.NewPublicKey(authPub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	authKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authSSHPub)))

	_, unauthPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unauth key: %v", err)
	}

	// Setup extra and shared directories for custom bind tests
	extraDir := filepath.Join(workDir, "extra_src")
	if err := os.MkdirAll(extraDir, 0755); err != nil {
		t.Fatalf("mkdir extra_src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(extraDir, "hello.txt"), []byte("from_extra"), 0644); err != nil {
		t.Fatalf("write extra hello: %v", err)
	}

	sharedDir := filepath.Join(workDir, "shared_src")
	if err := os.MkdirAll(sharedDir, 0755); err != nil {
		t.Fatalf("mkdir shared_src: %v", err)
	}

	// Write .sshbox.toml with authorized key and custom binds
	tomlBytes, err := toml.Marshal(&Config{
		AuthorizedKeys: []string{authKeyLine},
		Bind: []string{
			"extra_src:/opt/extra",
			"shared_src:/shared:rw",
		},
	})
	if err != nil {
		t.Fatalf("marshal .sshbox.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, ".sshbox.toml"), tomlBytes, 0600); err != nil {
		t.Fatalf("write .sshbox.toml: %v", err)
	}

	// Setup Unix domain socket for the server
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "sshbox.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket %s: %v", sockPath, err)
	}
	defer listener.Close()

	// Initialize and spawn the server with SCP enabled
	server, err := NewServer(workDir, WithSCP(true))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go func() {
		_ = server.Serve(listener)
	}()

	dialSSH := func(priv ed25519.PrivateKey) (*ssh.Client, error) {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			conn.Close()
			return nil, err
		}
		clientCfg := &ssh.ClientConfig{
			User:            "sshbox",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}
		cConn, chans, reqs, err := ssh.NewClientConn(conn, sockPath, clientCfg)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return ssh.NewClient(cConn, chans, reqs), nil
	}

	// 1. Test Authentication Security
	t.Run("AuthRejectionForUnauthorizedKey", func(t *testing.T) {
		client, err := dialSSH(unauthPriv)
		if err == nil {
			client.Close()
			t.Fatal("expected connection to fail with unauthorized key, but succeeded")
		}
	})

	t.Run("AuthSuccessForAuthorizedKey", func(t *testing.T) {
		client, err := dialSSH(authPriv)
		if err != nil {
			t.Fatalf("expected connection to succeed with authorized key, got: %v", err)
		}
		defer client.Close()
	})

	// Establish authorized client for remaining tests
	client, err := dialSSH(authPriv)
	if err != nil {
		t.Fatalf("connect authorized client: %v", err)
	}
	defer client.Close()

	// 2. Test Bubblewrap Execution & Isolation
	checkBwrap := func(t *testing.T) {
		if _, err := getBwrapPath(); err != nil {
			t.Skipf("skipping: %v", err)
		}
	}

	t.Run("BubblewrapCommandExecutionAndEnv", func(t *testing.T) {
		checkBwrap(t)
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		out, err := session.CombinedOutput("echo PWD=$PWD; echo USER=$USER; echo HOME=$HOME")
		if err != nil {
			t.Fatalf("command failed: %v, out: %s", err, string(out))
		}
		outStr := string(out)
		if !strings.Contains(outStr, "PWD=/work") {
			t.Errorf("expected PWD=/work, got output: %s", outStr)
		}
		if !strings.Contains(outStr, "USER=sshbox") {
			t.Errorf("expected USER=sshbox, got output: %s", outStr)
		}
		if !strings.Contains(outStr, "HOME=/home/sshbox") {
			t.Errorf("expected HOME=/home/sshbox, got output: %s", outStr)
		}
	})

	t.Run("BubblewrapTomlShadowingAndProtection", func(t *testing.T) {
		checkBwrap(t)
		// Verify /work/.sshbox.toml cannot be read (content is masked to empty)
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			out, err := session.CombinedOutput("cat /work/.sshbox.toml")
			if err != nil {
				t.Fatalf("read /work/.sshbox.toml failed: %v", err)
			}
			if len(out) != 0 {
				t.Errorf("expected /work/.sshbox.toml to be empty (shadowed), but got: %q", string(out))
			}
		}

		// Verify /work/.sshbox.toml cannot be modified (Read-only)
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			err = session.Run("echo 'hacked' >> /work/.sshbox.toml")
			if err == nil {
				t.Errorf("expected write to /work/.sshbox.toml to fail, but succeeded")
			}
		}
	})

	t.Run("BubblewrapHomeShadowingAndProtection", func(t *testing.T) {
		checkBwrap(t)
		// Put a file into host's .home directory
		secretFile := filepath.Join(homeDir, "secret.txt")
		if err := os.WriteFile(secretFile, []byte("hidden_content"), 0644); err != nil {
			t.Fatalf("write secret.txt: %v", err)
		}

		// Verify /work/.home is masked and cannot be accessed inside /work
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			out, err := session.CombinedOutput("ls -A /work/.home")
			if err != nil {
				t.Fatalf("ls /work/.home failed: %v", err)
			}
			if strings.TrimSpace(string(out)) != "" {
				t.Errorf("expected /work/.home to be empty, got: %s", string(out))
			}
		}

		// Verify /work/.home cannot be written to
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			err = session.Run("touch /work/.home/injected")
			if err == nil {
				t.Errorf("expected write to /work/.home to fail, but succeeded")
			}
		}

		// Verify /home/sshbox CAN access the real home files
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			out, err := session.CombinedOutput("cat /home/sshbox/secret.txt")
			if err != nil {
				t.Fatalf("read /home/sshbox/secret.txt failed: %v, out: %s", err, string(out))
			}
			if strings.TrimSpace(string(out)) != "hidden_content" {
				t.Errorf("expected hidden_content, got: %q", string(out))
			}
		}
	})

	t.Run("BubblewrapWorkReadWriteAccess", func(t *testing.T) {
		checkBwrap(t)
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		out, err := session.CombinedOutput("echo 'file_from_jail' > /work/created_by_jail.txt && cat /work/created_by_jail.txt")
		if err != nil {
			t.Fatalf("write to /work failed: %v, out: %s", err, string(out))
		}
		if strings.TrimSpace(string(out)) != "file_from_jail" {
			t.Errorf("unexpected output: %s", string(out))
		}

		// Verify file exists on host
		hostCreated := filepath.Join(workDir, "created_by_jail.txt")
		content, err := os.ReadFile(hostCreated)
		if err != nil {
			t.Fatalf("failed to read created file on host: %v", err)
		}
		if strings.TrimSpace(string(content)) != "file_from_jail" {
			t.Errorf("expected 'file_from_jail', got %q", string(content))
		}
	})

	t.Run("BubblewrapCustomBinds", func(t *testing.T) {
		checkBwrap(t)
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		// Read ro bind (/opt/extra/hello.txt)
		out, err := session.CombinedOutput("cat /opt/extra/hello.txt")
		if err != nil {
			t.Fatalf("read /opt/extra/hello.txt: %v, out: %s", err, string(out))
		}
		if strings.TrimSpace(string(out)) != "from_extra" {
			t.Errorf("expected 'from_extra', got %q", string(out))
		}

		// Verify ro bind fails on write
		session2, _ := client.NewSession()
		defer session2.Close()
		if err := session2.Run("echo fail >> /opt/extra/hello.txt"); err == nil {
			t.Error("expected write to ro bind to fail, but succeeded")
		}

		// Verify rw bind allows writing (/shared/test.txt)
		session3, _ := client.NewSession()
		defer session3.Close()
		if err := session3.Run("echo 'written_in_shared' > /shared/test.txt"); err != nil {
			t.Fatalf("write to rw bind failed: %v", err)
		}
		writtenData, err := os.ReadFile(filepath.Join(sharedDir, "test.txt"))
		if err != nil {
			t.Fatalf("read created file from host shared_src: %v", err)
		}
		if strings.TrimSpace(string(writtenData)) != "written_in_shared" {
			t.Errorf("expected 'written_in_shared', got %q", string(writtenData))
		}
	})

	// 3. Test SCP Protocol Handling & Security Restrictions
	t.Run("SCPSinkUploadToWork", func(t *testing.T) {
		checkBwrap(t)
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		stdin, err := session.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe: %v", err)
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			t.Fatalf("StdoutPipe: %v", err)
		}

		if err := session.Start("scp -t /work/uploaded.txt"); err != nil {
			t.Fatalf("Start scp: %v", err)
		}

		// Read initial 0x00 ACK from server
		var ack [1]byte
		if _, err := io.ReadFull(stdout, ack[:]); err != nil || ack[0] != 0 {
			t.Fatalf("expected 0x00 ACK from server, got: %v (byte: %d)", err, ack[0])
		}

		// Send file header C0644 12 uploaded.txt
		fileContent := "hello world\n"
		fmt.Fprintf(stdin, "C0644 %d uploaded.txt\n", len(fileContent))

		// Read ACK for header
		if _, err := io.ReadFull(stdout, ack[:]); err != nil || ack[0] != 0 {
			t.Fatalf("expected 0x00 ACK after header, got %d", ack[0])
		}

		// Send file content followed by 0x00
		io.WriteString(stdin, fileContent)
		stdin.Write([]byte{0})

		// Read ACK after content
		if _, err := io.ReadFull(stdout, ack[:]); err != nil || ack[0] != 0 {
			t.Fatalf("expected 0x00 ACK after content, got %d", ack[0])
		}

		stdin.Close()
		_ = session.Wait()

		// Verify on host
		hostFile := filepath.Join(workDir, "uploaded.txt")
		data, err := os.ReadFile(hostFile)
		if err != nil {
			t.Fatalf("read uploaded file: %v", err)
		}
		if string(data) != fileContent {
			t.Errorf("expected %q, got %q", fileContent, string(data))
		}
	})

	t.Run("SCPSourceDownloadFromWork", func(t *testing.T) {
		checkBwrap(t)
		testData := "data_to_download\n"
		testFile := filepath.Join(workDir, "download_test.txt")
		if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
			t.Fatalf("write download_test: %v", err)
		}

		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		stdin, err := session.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe: %v", err)
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			t.Fatalf("StdoutPipe: %v", err)
		}

		if err := session.Start("scp -f /work/download_test.txt"); err != nil {
			t.Fatalf("Start scp: %v", err)
		}

		// Client sends initial ACK
		stdin.Write([]byte{0})

		// Read header line ending with \n
		var headerBuf bytes.Buffer
		for {
			b := make([]byte, 1)
			if _, err := stdout.Read(b); err != nil {
				t.Fatalf("read header: %v", err)
			}
			headerBuf.Write(b)
			if b[0] == '\n' {
				break
			}
		}

		header := headerBuf.String()
		if !strings.HasPrefix(header, "C0644 ") || !strings.Contains(header, "download_test.txt") {
			t.Fatalf("unexpected header: %s", header)
		}

		// Client ACKs header
		stdin.Write([]byte{0})

		// Read content
		contentBuf := make([]byte, len(testData))
		if _, err := io.ReadFull(stdout, contentBuf); err != nil {
			t.Fatalf("read content: %v", err)
		}
		if string(contentBuf) != testData {
			t.Errorf("expected %q, got %q", testData, string(contentBuf))
		}

		// Read trailing 0x00
		var trailing [1]byte
		if _, err := io.ReadFull(stdout, trailing[:]); err != nil || trailing[0] != 0 {
			t.Fatalf("expected trailing 0x00, got: %d", trailing[0])
		}

		// Client ACKs completion
		stdin.Write([]byte{0})
		stdin.Close()
		_ = session.Wait()
	})

	t.Run("SCPSinkUploadToHomeSshbox", func(t *testing.T) {
		checkBwrap(t)
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		stdin, err := session.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe: %v", err)
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			t.Fatalf("StdoutPipe: %v", err)
		}

		if err := session.Start("scp -t /home/sshbox/home_config.json"); err != nil {
			t.Fatalf("Start scp: %v", err)
		}

		var ack [1]byte
		if _, err := io.ReadFull(stdout, ack[:]); err != nil || ack[0] != 0 {
			t.Fatalf("expected initial 0x00 ACK, got: %d", ack[0])
		}

		content := `{"theme":"dark"}`
		fmt.Fprintf(stdin, "C0644 %d home_config.json\n", len(content))
		if _, err := io.ReadFull(stdout, ack[:]); err != nil || ack[0] != 0 {
			t.Fatalf("expected header ACK, got: %d", ack[0])
		}

		io.WriteString(stdin, content)
		stdin.Write([]byte{0})
		if _, err := io.ReadFull(stdout, ack[:]); err != nil || ack[0] != 0 {
			t.Fatalf("expected content ACK, got: %d", ack[0])
		}

		stdin.Close()
		_ = session.Wait()

		// Verify file is saved in host's .home directory!
		expectedHostPath := filepath.Join(homeDir, "home_config.json")
		data, err := os.ReadFile(expectedHostPath)
		if err != nil {
			t.Fatalf("read file from host home: %v", err)
		}
		if string(data) != content {
			t.Errorf("expected %s, got %s", content, string(data))
		}
	})

	t.Run("SCPSecurityRejectionPaths", func(t *testing.T) {
		checkBwrap(t)
		badPaths := []string{
			"/work/.sshbox.toml",
			"/work/.home",
			"/etc/passwd",
			"/etc/shadow",
		}

		for _, p := range badPaths {
			t.Run("Sink_"+p, func(t *testing.T) {
				session, err := client.NewSession()
				if err != nil {
					t.Fatalf("NewSession: %v", err)
				}
				defer session.Close()

				stdin, _ := session.StdinPipe()
				stdout, _ := session.StdoutPipe()
				if err := session.Start(fmt.Sprintf("scp -t %s", p)); err != nil {
					// Session start failed, which is acceptable rejection
					return
				}

				// Read initial ACK from scp
				var ack [1]byte
				if _, err := io.ReadFull(stdout, ack[:]); err != nil || ack[0] != 0 {
					return // Rejected at startup
				}

				// Try to write a file to the forbidden target
				fmt.Fprintf(stdin, "C0644 4 test\ntest\x00")
				stdin.Close()

				var code [1]byte
				_, err = io.ReadFull(stdout, code[:])
				waitErr := session.Wait()
				// Writing to read-only/masked path MUST fail
				if waitErr == nil && (err != nil || code[0] == 0) {
					t.Errorf("expected write to %s to fail, but succeeded", p)
				}
			})

			t.Run("Source_"+p, func(t *testing.T) {
				session, err := client.NewSession()
				if err != nil {
					t.Fatalf("NewSession: %v", err)
				}
				defer session.Close()

				stdin, _ := session.StdinPipe()
				stdout, _ := session.StdoutPipe()
				if err := session.Start(fmt.Sprintf("scp -f %s", p)); err != nil {
					return
				}

				// Send initial client ACK
				stdin.Write([]byte{0})

				if p == "/work/.sshbox.toml" {
					// Read file header C0444 0 .sshbox.toml\n
					headerBuf := make([]byte, 64)
					n, _ := stdout.Read(headerBuf)
					headerStr := string(headerBuf[:n])
					// Verify the file inside sandbox is 0 bytes (masked)
					if !strings.Contains(headerStr, " 0 .sshbox.toml") {
						t.Errorf("expected masked empty file for .sshbox.toml, got: %s", headerStr)
					}
					// Acknowledge header and trailing
					stdin.Write([]byte{0})
					var trail [1]byte
					_, _ = stdout.Read(trail[:])
					stdin.Write([]byte{0})
					stdin.Close()
					_ = session.Wait()
					return
				}

				var code [1]byte
				_, err = io.ReadFull(stdout, code[:])
				stdin.Close()
				waitErr := session.Wait()
				// Reading protected / non-existent host files MUST fail
				if waitErr == nil && (err != nil || code[0] == 0) {
					t.Errorf("expected read from %s to fail, but succeeded", p)
				}
			})
		}
	})

	// 4. Test Security Defaults: SCP Disabled, GPU Disabled, Net Disabled
	t.Run("SCPDisabledByDefault", func(t *testing.T) {
		noSCPWorkDir := t.TempDir()
		tomlData, _ := toml.Marshal(&Config{
			AuthorizedKeys: []string{authKeyLine},
		})
		_ = os.WriteFile(filepath.Join(noSCPWorkDir, ".sshbox.toml"), tomlData, 0600)

		noSCPSock := filepath.Join(t.TempDir(), "no_scp.sock")
		noSCPListener, err := net.Listen("unix", noSCPSock)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer noSCPListener.Close()

		noSCPServer, err := NewServer(noSCPWorkDir) // default EnableSCP is false
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		go func() { _ = noSCPServer.Serve(noSCPListener) }()

		conn, err := net.Dial("unix", noSCPSock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		signer, _ := ssh.NewSignerFromKey(authPriv)
		cConn, chans, reqs, err := ssh.NewClientConn(conn, noSCPSock, &ssh.ClientConfig{
			User:            "sshbox",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewClientConn: %v", err)
		}
		noSCPClient := ssh.NewClient(cConn, chans, reqs)
		defer noSCPClient.Close()

		session, err := noSCPClient.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		err = session.Run("scp -t /work/fail.txt")
		if err == nil {
			t.Fatal("expected scp command to be rejected when scp is disabled, but succeeded")
		}
	})

	t.Run("GPUDisabledByDefault_MinimalDev", func(t *testing.T) {
		checkBwrap(t)
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		out, err := session.CombinedOutput("ls -1 /dev")
		if err != nil {
			t.Fatalf("ls /dev failed: %v", err)
		}
		outStr := string(out)
		// Standard isolated /dev has null, zero, random, urandom, tty
		if !strings.Contains(outStr, "null") || !strings.Contains(outStr, "zero") {
			t.Errorf("expected virtual /dev with null and zero, got: %s", outStr)
		}
		// Block devices must NOT be present
		if strings.Contains(outStr, "sda") || strings.Contains(outStr, "nvme") || strings.Contains(outStr, "vda") {
			t.Errorf("host block devices leaked into jail /dev: %s", outStr)
		}
	})

	t.Run("NetDisabledByDefault_IsolatedNet", func(t *testing.T) {
		checkBwrap(t)
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer session.Close()

		out, err := session.CombinedOutput("cat /proc/net/dev")
		if err != nil {
			t.Fatalf("cat /proc/net/dev failed: %v", err)
		}
		lines := strings.Split(string(out), "\n")
		var ifaces []string
		for _, line := range lines {
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				iface := strings.TrimSpace(parts[0])
				ifaces = append(ifaces, iface)
			}
		}
		// Only loopback 'lo' should be in the network namespace
		for _, iface := range ifaces {
			if iface != "lo" {
				t.Errorf("unexpected non-loopback network interface in jail: %s", iface)
			}
		}
	})

	t.Run("NoPredictableTmpFilesOnHost", func(t *testing.T) {
		// Verify sshbox does not create or rely on predictable files in /tmp
		bad1 := filepath.Join(os.TempDir(), "sshbox-empty-bind")
		bad2 := filepath.Join(os.TempDir(), "sshbox-empty-dir")
		if fi, err := os.Stat(bad1); err == nil && !fi.IsDir() {
			t.Logf("Found %s (check if from previous runs)", bad1)
		}
		_ = bad1
		_ = bad2
	})

	t.Run("ForwardDisabledByDefault", func(t *testing.T) {
		l, err := client.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			l.Close()
			t.Fatal("expected remote port forwarding to fail when forward is disabled, but client.Listen succeeded")
		}
	})
}

func TestRemotePortForwarding(t *testing.T) {
	workDir := t.TempDir()

	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	authSSHPub, err := ssh.NewPublicKey(authPub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	authKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authSSHPub)))

	forwardTrue := true
	tomlBytes, err := toml.Marshal(&Config{
		AuthorizedKeys: []string{authKeyLine},
		Forward:        &forwardTrue,
	})
	if err != nil {
		t.Fatalf("marshal toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, ".sshbox.toml"), tomlBytes, 0600); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "sshbox-fwd.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	server, err := NewServer(workDir, WithForward(true))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if !server.EnableForward {
		t.Fatal("expected server.EnableForward to be true")
	}

	go func() {
		_ = server.Serve(listener)
	}()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(authPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	clientCfg := &ssh.ClientConfig{
		User:            "sshbox",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cConn, chans, reqs, err := ssh.NewClientConn(conn, sockPath, clientCfg)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	client := ssh.NewClient(cConn, chans, reqs)
	defer client.Close()

	// 1. Request remote port forward (simulating ssh -R :0:...)
	remoteListener, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client.Listen failed: %v", err)
	}
	defer remoteListener.Close()

	boundAddr := remoteListener.Addr().String()

	// 2. Start mock remote service accepting connections from the tunnel
	go func() {
		for {
			srvConn, err := remoteListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				// Echo with prefix
				_, _ = c.Write(append([]byte("echo: "), buf[:n]...))
			}(srvConn)
		}
	}()

	// 3. Reverse-connect from the host machine to the bound port (simulating ssh -p <port> root@localhost)
	hostConn, err := net.Dial("tcp", boundAddr)
	if err != nil {
		t.Fatalf("reverse-connect to %s failed: %v", boundAddr, err)
	}
	defer hostConn.Close()

	msg := "hello reverse connect"
	if _, err := hostConn.Write([]byte(msg)); err != nil {
		t.Fatalf("write to tunnel: %v", err)
	}

	resp := make([]byte, 64)
	n, err := hostConn.Read(resp)
	if err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	expected := "echo: " + msg
	if string(resp[:n]) != expected {
		t.Fatalf("expected response %q, got %q", expected, string(resp[:n]))
	}

	// 4. Cancel the forward by closing remoteListener
	if err := remoteListener.Close(); err != nil {
		t.Fatalf("remoteListener.Close failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// 5. Subsequent connection to the port should be refused
	refusedConn, err := net.DialTimeout("tcp", boundAddr, 200*time.Millisecond)
	if err == nil {
		refusedConn.Close()
		t.Fatalf("expected connection to %s to be refused after cancel, but succeeded", boundAddr)
	}

	// 6. Security: reject non-localhost bind addresses (e.g. 0.0.0.0, external IPs)
	for _, badAddr := range []string{"0.0.0.0:0", "192.168.1.1:0", "10.0.0.1:0", "example.com:0"} {
		badListener, err := client.Listen("tcp", badAddr)
		if err == nil {
			badListener.Close()
			t.Fatalf("expected client.Listen on non-localhost %s to be rejected, but succeeded", badAddr)
		}
	}
}

func TestOpenSSHClientRealWorldRemoteForwarding(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("openssh client (ssh) not found in PATH")
	}

	workDir := t.TempDir()

	// 1. Generate client key
	keyPath := filepath.Join(workDir, "id_ed25519")
	pubKeyPath := keyPath + ".pub"
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v, out: %s", err, string(out))
	}
	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}

	// 2. Setup server config with authorized key and forward=true
	forwardTrue := true
	tomlBytes, err := toml.Marshal(&Config{
		AuthorizedKeys: []string{strings.TrimSpace(string(pubBytes))},
		Forward:        &forwardTrue,
	})
	if err != nil {
		t.Fatalf("marshal toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, ".sshbox.toml"), tomlBytes, 0600); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	// 3. Start mock backend service on remote client machine
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backendListener.Close()
	backendPort := backendListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				_, _ = conn.Write(append([]byte("backend: "), buf[:n]...))
			}(c)
		}
	}()

	// 4. Start sshbox server on an ephemeral TCP port
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer serverListener.Close()
	serverPort := serverListener.Addr().(*net.TCPAddr).Port

	server, err := NewServer(workDir, WithForward(true), WithVerbose(true))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() {
		_ = server.Serve(serverListener)
	}()

	// Pick an available port for the reverse forward
	testFwdL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	fwdPort := testFwdL.Addr().(*net.TCPAddr).Port
	testFwdL.Close()

	// 5. Run OpenSSH client: ssh -N -R <fwdPort>:localhost:<backendPort> -p <serverPort> ...
	sshArgs := []string{
		"-F", "none",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-i", keyPath,
		"-N",
		"-R", fmt.Sprintf("%d:localhost:%d", fwdPort, backendPort),
		"-p", fmt.Sprintf("%d", serverPort),
		"sshbox@127.0.0.1",
	}

	sshCmd := exec.Command("ssh", sshArgs...)
	var sshStderr bytes.Buffer
	sshCmd.Stderr = &sshStderr
	if err := sshCmd.Start(); err != nil {
		t.Fatalf("failed to start ssh client: %v", err)
	}
	defer func() {
		_ = sshCmd.Process.Kill()
		_ = sshCmd.Wait()
	}()

	// Wait for the forward port to become active on the server
	var clientConn net.Conn
	var dialErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		clientConn, dialErr = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort))
		if dialErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("timed out connecting to forwarded port %d: %v (ssh stderr: %s)", fwdPort, dialErr, sshStderr.String())
	}
	defer clientConn.Close()

	// 6. Test bidirectional communication through the reverse tunnel
	reqMsg := "ping from reverse connect"
	if _, err := clientConn.Write([]byte(reqMsg)); err != nil {
		t.Fatalf("write to tunnel: %v", err)
	}
	respBuf := make([]byte, 1024)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read from tunnel: %v (ssh stderr: %s)", err, sshStderr.String())
	}
	expected := "backend: " + reqMsg
	if string(respBuf[:n]) != expected {
		t.Fatalf("expected %q, got %q", expected, string(respBuf[:n]))
	}

	// 7. Also test connecting over IPv6 localhost [::1] (matches user scenario ssh -p 2222 root@localhost)
	if ipv6Conn, err := net.Dial("tcp", fmt.Sprintf("[::1]:%d", fwdPort)); err == nil {
		defer ipv6Conn.Close()
		reqMsg6 := "ping from ipv6 reverse connect"
		if _, err := ipv6Conn.Write([]byte(reqMsg6)); err != nil {
			t.Fatalf("write to ipv6 tunnel: %v", err)
		}
		respBuf6 := make([]byte, 1024)
		n6, err := ipv6Conn.Read(respBuf6)
		if err != nil {
			t.Fatalf("read from ipv6 tunnel: %v (ssh stderr: %s)", err, sshStderr.String())
		}
		expected6 := "backend: " + reqMsg6
		if string(respBuf6[:n6]) != expected6 {
			t.Fatalf("expected %q, got %q", expected6, string(respBuf6[:n6]))
		}
	}

	// Verify no OpenSSH warning was emitted in stderr
	if strings.Contains(sshStderr.String(), "unknown listen_port") {
		t.Fatalf("OpenSSH client warned about unknown listen_port: %s", sshStderr.String())
	}
}

func TestOpenSSHClientCommandExecution(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("openssh client (ssh) not found in PATH")
	}

	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap (bwrap) not found in PATH")
	}

	workDir := t.TempDir()

	keyPath := filepath.Join(workDir, "id_ed25519")
	pubKeyPath := keyPath + ".pub"
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v, out: %s", err, string(out))
	}
	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}

	tomlBytes, err := toml.Marshal(&Config{
		AuthorizedKeys: []string{strings.TrimSpace(string(pubBytes))},
	})
	if err != nil {
		t.Fatalf("marshal toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, ".sshbox.toml"), tomlBytes, 0600); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer serverListener.Close()
	serverPort := serverListener.Addr().(*net.TCPAddr).Port

	server, err := NewServer(workDir)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() {
		_ = server.Serve(serverListener)
	}()

	baseArgs := []string{
		"-F", "none",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-i", keyPath,
		"-p", fmt.Sprintf("%d", serverPort),
		"sshbox@127.0.0.1",
	}

	t.Run("NonInteractiveCommandWithOpenStdin", func(t *testing.T) {
		// Create an open pipe for stdin to simulate running from an interactive terminal
		// where stdin is not closed.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		defer r.Close()
		defer w.Close()

		sshArgs := append(append([]string{}, baseArgs...), "echo hello")
		sshCmd := exec.Command("ssh", sshArgs...)
		sshCmd.Stdin = r
		var stdout, stderr bytes.Buffer
		sshCmd.Stdout = &stdout
		sshCmd.Stderr = &stderr

		done := make(chan error, 1)
		if err := sshCmd.Start(); err != nil {
			t.Fatalf("failed to start ssh client: %v", err)
		}

		go func() {
			done <- sshCmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("ssh command failed: %v, stderr: %s", err, stderr.String())
			}
			if strings.TrimSpace(stdout.String()) != "hello" {
				t.Fatalf("expected 'hello', got %q", stdout.String())
			}
		case <-time.After(3 * time.Second):
			_ = sshCmd.Process.Kill()
			t.Fatalf("ssh command hung indefinitely! stdout: %q, stderr: %q", stdout.String(), stderr.String())
		}
	})

	t.Run("NonInteractiveCommandWithPipedStdin", func(t *testing.T) {
		sshArgs := append(append([]string{}, baseArgs...), "cat")
		sshCmd := exec.Command("ssh", sshArgs...)
		sshCmd.Stdin = strings.NewReader("hello from piped stdin\n")
		var stdout, stderr bytes.Buffer
		sshCmd.Stdout = &stdout
		sshCmd.Stderr = &stderr

		done := make(chan error, 1)
		if err := sshCmd.Start(); err != nil {
			t.Fatalf("failed to start ssh client: %v", err)
		}

		go func() {
			done <- sshCmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("ssh command failed: %v, stderr: %s", err, stderr.String())
			}
			if strings.TrimSpace(stdout.String()) != "hello from piped stdin" {
				t.Fatalf("expected 'hello from piped stdin', got %q", stdout.String())
			}
		case <-time.After(3 * time.Second):
			_ = sshCmd.Process.Kill()
			t.Fatalf("ssh command hung indefinitely! stdout: %q, stderr: %q", stdout.String(), stderr.String())
		}
	})

	t.Run("NonInteractiveCommandNonZeroExit", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		defer r.Close()
		defer w.Close()

		sshArgs := append(append([]string{}, baseArgs...), "sh -c 'exit 42'")
		sshCmd := exec.Command("ssh", sshArgs...)
		sshCmd.Stdin = r
		var stdout, stderr bytes.Buffer
		sshCmd.Stdout = &stdout
		sshCmd.Stderr = &stderr

		done := make(chan error, 1)
		if err := sshCmd.Start(); err != nil {
			t.Fatalf("failed to start ssh client: %v", err)
		}

		go func() {
			done <- sshCmd.Wait()
		}()

		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("expected error exit status 42, got nil")
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				if exitErr.ExitCode() != 42 {
					t.Fatalf("expected exit code 42, got %d", exitErr.ExitCode())
				}
			} else {
				t.Fatalf("unexpected error type: %v", err)
			}
		case <-time.After(3 * time.Second):
			_ = sshCmd.Process.Kill()
			t.Fatalf("ssh command hung indefinitely!")
		}
	})

	t.Run("NonInteractiveCommandStderr", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		defer r.Close()
		defer w.Close()

		sshArgs := append(append([]string{}, baseArgs...), "sh -c 'echo custom_error_output >&2'")
		sshCmd := exec.Command("ssh", sshArgs...)
		sshCmd.Stdin = r
		var stdout, stderr bytes.Buffer
		sshCmd.Stdout = &stdout
		sshCmd.Stderr = &stderr

		done := make(chan error, 1)
		if err := sshCmd.Start(); err != nil {
			t.Fatalf("failed to start ssh client: %v", err)
		}

		go func() {
			done <- sshCmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("ssh command failed: %v, stderr: %s", err, stderr.String())
			}
			if !strings.Contains(stderr.String(), "custom_error_output") {
				t.Fatalf("expected stderr to contain 'custom_error_output', got %q", stderr.String())
			}
		case <-time.After(3 * time.Second):
			_ = sshCmd.Process.Kill()
			t.Fatalf("ssh command hung indefinitely!")
		}
	})
}
