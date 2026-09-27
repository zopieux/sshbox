package sshbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/crypto/ssh"
)

func TestConfigLoadAndGenerate(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Initial load should create .bashbox.toml with host key
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

	configPath := filepath.Join(tempDir, ".bashbox.toml")
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

func TestResolveAndValidatePath(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		reqPath   string
		shouldErr bool
	}{
		{"work root", "/work", false},
		{"work subfile", "/work/foo.txt", false},
		{"relative file", "foo.txt", false},
		{"home root", "/home/bashbox", false},
		{"home subfile", "/home/bashbox/test.txt", false},
		{"etc passwd", "/etc/passwd", true},
		{"root dir", "/", false}, // defaults to /work
		{"directory traversal 1", "/work/../etc/passwd", true},
		{"directory traversal 2", "/home/bashbox/../../etc/passwd", true},
		{"bashbox toml in work", "/work/.bashbox.toml", true},
		{"bashbox toml subpath", "/work/.bashbox.toml/sub", true},
		{"home via work", "/work/.home", true},
		{"home subfile via work", "/work/.home/secret", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveAndValidatePath(tempDir, tc.reqPath)
			if tc.shouldErr && err == nil {
				t.Fatalf("expected error for path %q, got nil", tc.reqPath)
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("unexpected error for path %q: %v", tc.reqPath, err)
			}
		})
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

	// Write .bashbox.toml with the authorized public key using toml marshaller
	tomlBytes, err := toml.Marshal(&Config{
		AuthorizedKeys: []string{authKeyLine},
	})
	if err != nil {
		t.Fatalf("marshal .bashbox.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, ".bashbox.toml"), tomlBytes, 0600); err != nil {
		t.Fatalf("write .bashbox.toml: %v", err)
	}

	// Setup Unix domain socket for the server
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "sshbox.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket %s: %v", sockPath, err)
	}
	defer listener.Close()

	// Initialize and spawn the server
	server, err := NewServer(workDir)
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
			User:            "bashbox",
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
		if !strings.Contains(outStr, "USER=bashbox") {
			t.Errorf("expected USER=bashbox, got output: %s", outStr)
		}
		if !strings.Contains(outStr, "HOME=/home/bashbox") {
			t.Errorf("expected HOME=/home/bashbox, got output: %s", outStr)
		}
	})

	t.Run("BubblewrapTomlShadowingAndProtection", func(t *testing.T) {
		checkBwrap(t)
		// Verify /work/.bashbox.toml cannot be read (content is masked to empty)
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			out, err := session.CombinedOutput("cat /work/.bashbox.toml")
			if err != nil {
				t.Fatalf("read /work/.bashbox.toml failed: %v", err)
			}
			if len(out) != 0 {
				t.Errorf("expected /work/.bashbox.toml to be empty (shadowed), but got: %q", string(out))
			}
		}

		// Verify /work/.bashbox.toml cannot be modified (Read-only)
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			err = session.Run("echo 'hacked' >> /work/.bashbox.toml")
			if err == nil {
				t.Errorf("expected write to /work/.bashbox.toml to fail, but succeeded")
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

		// Verify /home/bashbox CAN access the real home files
		{
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer session.Close()

			out, err := session.CombinedOutput("cat /home/bashbox/secret.txt")
			if err != nil {
				t.Fatalf("read /home/bashbox/secret.txt failed: %v, out: %s", err, string(out))
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

	// 3. Test SCP Protocol Handling & Security Restrictions
	t.Run("SCPSinkUploadToWork", func(t *testing.T) {
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

	t.Run("SCPSinkUploadToHomeBashbox", func(t *testing.T) {
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

		if err := session.Start("scp -t /home/bashbox/home_config.json"); err != nil {
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
		badPaths := []string{
			"/work/.bashbox.toml",
			"/work/.home",
			"/etc/passwd",
			"/work/../outside.txt",
			"/home/bashbox/../../etc/shadow",
		}

		for _, p := range badPaths {
			t.Run("Sink_"+p, func(t *testing.T) {
				session, err := client.NewSession()
				if err != nil {
					t.Fatalf("NewSession: %v", err)
				}
				defer session.Close()

				stdout, _ := session.StdoutPipe()
				_ = session.Start(fmt.Sprintf("scp -t %s", p))

				var code [1]byte
				_, err = io.ReadFull(stdout, code[:])
				// Server should return error indicator (0x01 or 0x02) instead of 0x00 ACK
				if err == nil && code[0] == 0 {
					t.Errorf("expected error code for forbidden path %s, but got 0x00 (success)", p)
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
				_ = session.Start(fmt.Sprintf("scp -f %s", p))

				// Send initial client ACK
				stdin.Write([]byte{0})

				var code [1]byte
				_, err = io.ReadFull(stdout, code[:])
				if err == nil && code[0] == 0 {
					t.Errorf("expected error code for forbidden path %s, but got 0x00", p)
				}
			})
		}
	})
}
