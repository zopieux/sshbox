package sshbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/crypto/ssh"
)

type BindMount struct {
	HostPath  string
	JailPath  string
	ReadWrite bool
}

type Config struct {
	Port           *int     `toml:"port,omitempty"`
	AuthorizedKeys []string `toml:"authorized_keys"`
	AuthorizedKey  string   `toml:"authorized_key,omitempty"`
	HostKey        string   `toml:"host_key"`
	Bind           []string `toml:"bind,omitempty"`
	Packages       []string `toml:"packages,omitempty"`
	SCP            *bool    `toml:"scp,omitempty"`
	GPU            *bool    `toml:"gpu,omitempty"`
	Net            *bool    `toml:"net,omitempty"`
	Forward        *bool    `toml:"forward,omitempty"`
	OpenPort       string   `toml:"open_port,omitempty"`

	ParsedBinds      []BindMount     `toml:"-"`
	PackageBinPath   string          `toml:"-"`
	parsedPublicKeys []ssh.PublicKey `toml:"-"`
}

// OpenPortMode defines how the jail's port should be exposed externally.
type OpenPortMode string

const (
	OpenPortNone     OpenPortMode = "none"
	OpenPortFirewall OpenPortMode = "firewall"
	OpenPortNatPMP   OpenPortMode = "natpmp"
	OpenPortBoth     OpenPortMode = "both"
)

func (c *Config) GetPort() int {
	if c != nil && c.Port != nil && *c.Port > 0 {
		return *c.Port
	}
	return 2222
}

func (c *Config) GetSCP() bool {
	return c != nil && c.SCP != nil && *c.SCP
}

func (c *Config) GetGPU() bool {
	return c != nil && c.GPU != nil && *c.GPU
}

func (c *Config) GetNet() bool {
	return c != nil && c.Net != nil && *c.Net
}

func (c *Config) GetForward() bool {
	return c != nil && c.Forward != nil && *c.Forward
}

func (c *Config) GetOpenPortMode() OpenPortMode {
	if c == nil {
		return OpenPortNone
	}
	switch strings.ToLower(strings.TrimSpace(c.OpenPort)) {
	case "firewall":
		return OpenPortFirewall
	case "natpmp":
		return OpenPortNatPMP
	case "both":
		return OpenPortBoth
	default:
		return OpenPortNone
	}
}

func (c *Config) ShouldOpenFirewall() bool {
	m := c.GetOpenPortMode()
	return m == OpenPortFirewall || m == OpenPortBoth
}

func (c *Config) ShouldOpenNatPMP() bool {
	m := c.GetOpenPortMode()
	return m == OpenPortNatPMP || m == OpenPortBoth
}

func LoadOrInitConfig(dir string) (*Config, ssh.Signer, error) {
	configPath := filepath.Join(dir, ".sshbox.toml")

	var cfg Config
	var data []byte
	exists := true

	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			exists = false
		} else {
			return nil, nil, fmt.Errorf("read config file %s: %w", configPath, err)
		}
	}

	if exists {
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return nil, nil, fmt.Errorf("parse config file %s: %w", configPath, err)
		}
	}

	var signer ssh.Signer
	needSave := !exists

	if strings.TrimSpace(cfg.HostKey) == "" {
		hostKeyPEM, newSigner, err := generateEd25519HostKey()
		if err != nil {
			return nil, nil, fmt.Errorf("generate host key: %w", err)
		}
		cfg.HostKey = hostKeyPEM
		signer = newSigner
		needSave = true
	} else {
		parsedSigner, err := ssh.ParsePrivateKey([]byte(cfg.HostKey))
		if err != nil {
			return nil, nil, fmt.Errorf("parse host key from config: %w", err)
		}
		signer = parsedSigner
	}

	if needSave {
		if cfg.Port == nil {
			defaultPort := 2222
			cfg.Port = &defaultPort
		}
		if err := saveConfig(configPath, &cfg); err != nil {
			return nil, nil, fmt.Errorf("save config %s: %w", configPath, err)
		}
		log.Printf("Updated config with host key at %s", configPath)
	}

	// Parse authorized keys
	var allKeyLines []string
	for _, k := range cfg.AuthorizedKeys {
		lines := strings.Split(k, "\n")
		allKeyLines = append(allKeyLines, lines...)
	}
	if cfg.AuthorizedKey != "" {
		lines := strings.Split(cfg.AuthorizedKey, "\n")
		allKeyLines = append(allKeyLines, lines...)
	}

	for _, line := range allKeyLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			log.Printf("Warning: failed to parse authorized key %q: %v", line, err)
			continue
		}
		cfg.parsedPublicKeys = append(cfg.parsedPublicKeys, pubKey)
	}

	if len(cfg.parsedPublicKeys) == 0 {
		log.Printf("Warning: No authorized public keys found in %s! Add client pubkeys to 'authorized_keys'.", configPath)
	} else {
		log.Printf("Loaded %d authorized public key(s) from %s", len(cfg.parsedPublicKeys), configPath)
	}

	// Parse bind mounts
	for _, spec := range cfg.Bind {
		bm, err := parseBindString(dir, spec)
		if err != nil {
			log.Printf("Warning: failed to parse bind %q: %v", spec, err)
			continue
		}
		if bm != nil {
			cfg.ParsedBinds = append(cfg.ParsedBinds, *bm)
		}
	}

	if len(cfg.ParsedBinds) > 0 {
		log.Printf("Loaded %d bind mount(s) from %s", len(cfg.ParsedBinds), configPath)
	}

	return &cfg, signer, nil
}

func parseBindString(dir, spec string) (*BindMount, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("invalid bind spec %q: must be host:jail[:rw]", spec)
	}

	hostPath := strings.TrimSpace(parts[0])
	jailPath := strings.TrimSpace(parts[1])
	if hostPath == "" || jailPath == "" {
		return nil, fmt.Errorf("invalid bind spec %q: host and jail paths cannot be empty", spec)
	}

	if !filepath.IsAbs(hostPath) {
		hostPath = filepath.Clean(filepath.Join(dir, hostPath))
	} else {
		hostPath = filepath.Clean(hostPath)
	}

	jailPath = path.Clean(jailPath)
	if !strings.HasPrefix(jailPath, "/") {
		jailPath = "/" + jailPath
	}

	rw := false
	if len(parts) == 3 {
		mode := strings.ToLower(strings.TrimSpace(parts[2]))
		switch mode {
		case "rw":
			rw = true
		case "ro":
			rw = false
		default:
			return nil, fmt.Errorf("invalid bind mode %q in %q: must be 'ro' or 'rw'", parts[2], spec)
		}
	}

	return &BindMount{
		HostPath:  hostPath,
		JailPath:  jailPath,
		ReadWrite: rw,
	}, nil
}

func (c *Config) Authenticate(key ssh.PublicKey) bool {
	target := key.Marshal()
	for _, pub := range c.parsedPublicKeys {
		if subtle.ConstantTimeCompare(pub.Marshal(), target) == 1 {
			return true
		}
	}
	return false
}

func generateEd25519HostKey() (string, ssh.Signer, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generate ed25519: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(privKey, "sshbox-host-key")
	if err != nil {
		return "", nil, fmt.Errorf("marshal private key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(block)
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return "", nil, fmt.Errorf("parse generated private key: %w", err)
	}

	return string(pemBytes), signer, nil
}

func saveConfig(path string, cfg *Config) error {
	var sb strings.Builder
	sb.WriteString("# sshbox configuration (.sshbox.toml)\n\n")
	if cfg.Port != nil {
		sb.WriteString(fmt.Sprintf("port = %d\n\n", *cfg.Port))
	}
	if cfg.SCP != nil {
		sb.WriteString(fmt.Sprintf("scp = %t\n\n", *cfg.SCP))
	}
	if cfg.GPU != nil {
		sb.WriteString(fmt.Sprintf("gpu = %t\n\n", *cfg.GPU))
	}
	if cfg.Net != nil {
		sb.WriteString(fmt.Sprintf("net = %t\n\n", *cfg.Net))
	}
	if cfg.Forward != nil {
		sb.WriteString(fmt.Sprintf("forward = %t\n\n", *cfg.Forward))
	}
	if mode := cfg.GetOpenPortMode(); mode != OpenPortNone {
		sb.WriteString(fmt.Sprintf("open_port = %q\n\n", mode))
	}

	sb.WriteString("# Accepted client public keys for SSH authentication\n")
	if len(cfg.AuthorizedKeys) == 0 {
		sb.WriteString("authorized_keys = [\n    # \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host\"\n]\n\n")
	} else {
		encoded, err := toml.Marshal(map[string][]string{"authorized_keys": cfg.AuthorizedKeys})
		if err == nil {
			sb.WriteString(string(encoded))
			sb.WriteString("\n")
		}
	}

	if len(cfg.Bind) > 0 {
		encoded, err := toml.Marshal(map[string][]string{"bind": cfg.Bind})
		if err == nil {
			sb.WriteString(string(encoded))
			sb.WriteString("\n")
		}
	}

	if len(cfg.Packages) > 0 {
		encoded, err := toml.Marshal(map[string][]string{"packages": cfg.Packages})
		if err == nil {
			sb.WriteString(string(encoded))
			sb.WriteString("\n")
		}
	}

	sb.WriteString("# Server host private key (OpenSSH format)\n")
	sb.WriteString("host_key = \"\"\"\n")
	sb.WriteString(strings.TrimSpace(cfg.HostKey))
	sb.WriteString("\n\"\"\"\n")

	return os.WriteFile(path, []byte(sb.String()), 0600)
}
