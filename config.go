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
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	AuthorizedKeys []string `toml:"authorized_keys"`
	AuthorizedKey  string   `toml:"authorized_key,omitempty"`
	HostKey        string   `toml:"host_key"`

	parsedPublicKeys []ssh.PublicKey `toml:"-"`
}

func LoadOrInitConfig(dir string) (*Config, ssh.Signer, error) {
	configPath := filepath.Join(dir, ".bashbox.toml")

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

	return &cfg, signer, nil
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
	sb.WriteString("# sshbox configuration (.bashbox.toml)\n\n")
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

	sb.WriteString("# Server host private key (OpenSSH format)\n")
	sb.WriteString("host_key = \"\"\"\n")
	sb.WriteString(strings.TrimSpace(cfg.HostKey))
	sb.WriteString("\n\"\"\"\n")

	return os.WriteFile(path, []byte(sb.String()), 0600)
}
