package sshbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPortForwarderModes(t *testing.T) {
	origExecutor := commandExecutor
	defer func() { commandExecutor = origExecutor }()

	tests := []struct {
		name         string
		mode         OpenPortMode
		expectNAT    bool
		expectFW     bool
		expectNATCls bool
		expectFWCls  bool
	}{
		{
			name:         "FirewallOnly",
			mode:         OpenPortFirewall,
			expectNAT:    false,
			expectFW:     true,
			expectNATCls: false,
			expectFWCls:  true,
		},
		{
			name:         "NatPMPOnly",
			mode:         OpenPortNatPMP,
			expectNAT:    true,
			expectFW:     false,
			expectNATCls: true,
			expectFWCls:  false,
		},
		{
			name:         "Both",
			mode:         OpenPortBoth,
			expectNAT:    true,
			expectFW:     true,
			expectNATCls: true,
			expectFWCls:  true,
		},
		{
			name:         "None",
			mode:         OpenPortNone,
			expectNAT:    false,
			expectFW:     false,
			expectNATCls: false,
			expectFWCls:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var executedCommands [][]string

			commandExecutor = func(name string, args ...string) *exec.Cmd {
				mu.Lock()
				full := append([]string{name}, args...)
				executedCommands = append(executedCommands, full)
				mu.Unlock()

				if name == "ip" {
					return exec.Command("echo", "default via 10.0.0.1 dev eth0")
				}
				for _, a := range args {
					if a == "-C" {
						return exec.Command("false")
					}
				}
				return exec.Command("true")
			}

			mon := NewPlainMonitor(false)
			pf := NewPortForwarder(2222, tc.mode, mon)
			pf.Lifetime = 1 * time.Hour

			pf.Open()

			mu.Lock()
			openCmds := make([][]string, len(executedCommands))
			copy(openCmds, executedCommands)
			executedCommands = nil
			mu.Unlock()

			hasNAT := false
			hasFW := false
			for _, cmd := range openCmds {
				cmdStr := strings.Join(cmd, " ")
				if strings.Contains(cmdStr, "natpmpc -g 10.0.0.1 -a 2222 2222 tcp 3600") {
					hasNAT = true
				}
				if strings.Contains(cmdStr, "iptables -w -A sshbox -p tcp --dport 2222 -j ACCEPT") {
					hasFW = true
				}
			}

			if hasNAT != tc.expectNAT {
				t.Errorf("open NAT mismatch: expected %v, got %v (cmds: %v)", tc.expectNAT, hasNAT, openCmds)
			}
			if hasFW != tc.expectFW {
				t.Errorf("open FW mismatch: expected %v, got %v (cmds: %v)", tc.expectFW, hasFW, openCmds)
			}

			pf.Close()

			mu.Lock()
			closeCmds := make([][]string, len(executedCommands))
			copy(closeCmds, executedCommands)
			mu.Unlock()

			hasNATCls := false
			hasFWCls := false
			for _, cmd := range closeCmds {
				cmdStr := strings.Join(cmd, " ")
				if strings.Contains(cmdStr, "natpmpc -g 10.0.0.1 -a 2222 2222 tcp 0") {
					hasNATCls = true
				}
				if strings.Contains(cmdStr, "iptables -w -D sshbox -p tcp --dport 2222 -j ACCEPT") {
					hasFWCls = true
				}
			}

			if hasNATCls != tc.expectNATCls {
				t.Errorf("close NAT mismatch: expected %v, got %v (cmds: %v)", tc.expectNATCls, hasNATCls, closeCmds)
			}
			if hasFWCls != tc.expectFWCls {
				t.Errorf("close FW mismatch: expected %v, got %v (cmds: %v)", tc.expectFWCls, hasFWCls, closeCmds)
			}
		})
	}
}

func TestConfigOpenPortModes(t *testing.T) {
	tempDir := t.TempDir()

	modes := []struct {
		rawVal       string
		expectedMode OpenPortMode
		expFW        bool
		expNAT       bool
	}{
		{"firewall", OpenPortFirewall, true, false},
		{"natpmp", OpenPortNatPMP, false, true},
		{"both", OpenPortBoth, true, true},
		{"none", OpenPortNone, false, false},
		{"", OpenPortNone, false, false},
		{"INVALID", OpenPortNone, false, false},
	}

	for _, tc := range modes {
		t.Run("Mode_"+tc.rawVal, func(t *testing.T) {
			dir := filepath.Join(tempDir, "jail_"+tc.rawVal)
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}

			cfg, _, err := LoadOrInitConfig(dir)
			if err != nil {
				t.Fatal(err)
			}
			cfg.OpenPort = tc.rawVal

			if cfg.GetOpenPortMode() != tc.expectedMode {
				t.Errorf("expected GetOpenPortMode() == %q, got %q", tc.expectedMode, cfg.GetOpenPortMode())
			}
			if cfg.ShouldOpenFirewall() != tc.expFW {
				t.Errorf("expected ShouldOpenFirewall() == %v, got %v", tc.expFW, cfg.ShouldOpenFirewall())
			}
			if cfg.ShouldOpenNatPMP() != tc.expNAT {
				t.Errorf("expected ShouldOpenNatPMP() == %v, got %v", tc.expNAT, cfg.ShouldOpenNatPMP())
			}

			if err := saveConfig(filepath.Join(dir, ".sshbox.toml"), cfg); err != nil {
				t.Fatal(err)
			}

			// Reload and verify persistence
			reloaded, _, err := LoadOrInitConfig(dir)
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.GetOpenPortMode() != tc.expectedMode {
				t.Errorf("reloaded expected GetOpenPortMode() == %q, got %q", tc.expectedMode, reloaded.GetOpenPortMode())
			}

			srv, err := NewServer(dir)
			if err != nil {
				t.Fatal(err)
			}
			if srv.OpenPortMode != tc.expectedMode {
				t.Errorf("srv.OpenPortMode mismatch: expected %q, got %q", tc.expectedMode, srv.OpenPortMode)
			}
		})
	}
}
