package sshbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortConfigAndConflict(t *testing.T) {
	tempDir := t.TempDir()

	dirA := filepath.Join(tempDir, "jailA")
	dirB := filepath.Join(tempDir, "jailB")
	dirC := filepath.Join(tempDir, "jailC")
	if err := os.MkdirAll(dirA, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dirB, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dirC, 0755); err != nil {
		t.Fatal(err)
	}

	// 1. Both dirA and dirB default to 2222 -> Conflict!
	cfgA, _, err := LoadOrInitConfig(dirA)
	if err != nil {
		t.Fatalf("LoadOrInitConfig dirA: %v", err)
	}
	if cfgA.GetPort() != 2222 {
		t.Fatalf("expected default port 2222, got %d", cfgA.GetPort())
	}

	cfgB, _, err := LoadOrInitConfig(dirB)
	if err != nil {
		t.Fatalf("LoadOrInitConfig dirB: %v", err)
	}
	if cfgB.GetPort() != 2222 {
		t.Fatalf("expected default port 2222, got %d", cfgB.GetPort())
	}

	conflicts, err := CheckPortConflicts([]string{dirA, dirB})
	if err != nil {
		t.Fatalf("CheckPortConflicts: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Port != 2222 {
		t.Errorf("expected conflict on port 2222, got %d", conflicts[0].Port)
	}
	if len(conflicts[0].Dirs) != 2 {
		t.Errorf("expected 2 conflicting dirs, got %d", len(conflicts[0].Dirs))
	}
	conflictMsg := conflicts[0].Error()
	if !strings.Contains(conflictMsg, "2222") || !strings.Contains(conflictMsg, dirA) || !strings.Contains(conflictMsg, dirB) {
		t.Errorf("expected message to mention port and abspaths, got: %s", conflictMsg)
	}

	// 2. Change dirB to port 2223 and dirC to 2224 -> No conflict!
	port2223 := 2223
	cfgB.Port = &port2223
	if err := saveConfig(filepath.Join(dirB, ".sshbox.toml"), cfgB); err != nil {
		t.Fatalf("saveConfig dirB: %v", err)
	}

	port2224 := 2224
	cfgC, _, err := LoadOrInitConfig(dirC)
	if err != nil {
		t.Fatalf("LoadOrInitConfig dirC: %v", err)
	}
	cfgC.Port = &port2224
	if err := saveConfig(filepath.Join(dirC, ".sshbox.toml"), cfgC); err != nil {
		t.Fatalf("saveConfig dirC: %v", err)
	}

	conflicts, err = CheckPortConflicts([]string{dirA, dirB, dirC})
	if err != nil {
		t.Fatalf("CheckPortConflicts: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d", len(conflicts))
	}

	// 3. Manager initialization with multiple independent jails
	mon := NewPlainMonitor(false)
	mgr, err := NewManager([]string{dirA, dirB, dirC}, mon)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if len(mgr.Servers) != 3 {
		t.Fatalf("expected 3 servers in manager, got %d", len(mgr.Servers))
	}

	// Verify each server has its own isolated context
	if mgr.Servers[0].WorkDir != dirA || mgr.Servers[0].Port != 2222 {
		t.Errorf("server 0 mismatch: %s:%d", mgr.Servers[0].WorkDir, mgr.Servers[0].Port)
	}
	if mgr.Servers[1].WorkDir != dirB || mgr.Servers[1].Port != 2223 {
		t.Errorf("server 1 mismatch: %s:%d", mgr.Servers[1].WorkDir, mgr.Servers[1].Port)
	}
	if mgr.Servers[2].WorkDir != dirC || mgr.Servers[2].Port != 2224 {
		t.Errorf("server 2 mismatch: %s:%d", mgr.Servers[2].WorkDir, mgr.Servers[2].Port)
	}

	// Verify isolated host key signers
	pubKeyA := string(mgr.Servers[0].Config.HostKey)
	pubKeyB := string(mgr.Servers[1].Config.HostKey)
	if pubKeyA == pubKeyB {
		t.Error("jailA and jailB should have independent host keys, but got identical keys")
	}

	jails := mgr.Jails()
	if len(jails) != 3 {
		t.Fatalf("expected 3 jails, got %d", len(jails))
	}
}

func TestManagerPerJailConfigIsolation(t *testing.T) {
	tempDir := t.TempDir()

	dirA := filepath.Join(tempDir, "jailA")
	dirB := filepath.Join(tempDir, "jailB")
	if err := os.MkdirAll(dirA, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dirB, 0755); err != nil {
		t.Fatal(err)
	}

	trueVal := true
	falseVal := false
	portA := 2230
	portB := 2231

	// Jail A: scp=true, gpu=false, net=true, forward=false
	cfgA, _, err := LoadOrInitConfig(dirA)
	if err != nil {
		t.Fatal(err)
	}
	cfgA.Port = &portA
	cfgA.SCP = &trueVal
	cfgA.GPU = &falseVal
	cfgA.Net = &trueVal
	cfgA.Forward = &falseVal
	if err := saveConfig(filepath.Join(dirA, ".sshbox.toml"), cfgA); err != nil {
		t.Fatal(err)
	}

	// Jail B: scp=false, gpu=true, net=false, forward=true
	cfgB, _, err := LoadOrInitConfig(dirB)
	if err != nil {
		t.Fatal(err)
	}
	cfgB.Port = &portB
	cfgB.SCP = &falseVal
	cfgB.GPU = &trueVal
	cfgB.Net = &falseVal
	cfgB.Forward = &trueVal
	if err := saveConfig(filepath.Join(dirB, ".sshbox.toml"), cfgB); err != nil {
		t.Fatal(err)
	}

	mon := NewPlainMonitor(false)
	mgr, err := NewManager([]string{dirA, dirB}, mon)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Verify Jail A has its own exact settings
	sA := mgr.Servers[0]
	if !sA.EnableSCP || sA.EnableGPU || !sA.EnableNet || sA.EnableForward {
		t.Errorf("Jail A configs conflated: scp=%v, gpu=%v, net=%v, forward=%v",
			sA.EnableSCP, sA.EnableGPU, sA.EnableNet, sA.EnableForward)
	}

	// Verify Jail B has its own exact settings
	sB := mgr.Servers[1]
	if sB.EnableSCP || !sB.EnableGPU || sB.EnableNet || !sB.EnableForward {
		t.Errorf("Jail B configs conflated: scp=%v, gpu=%v, net=%v, forward=%v",
			sB.EnableSCP, sB.EnableGPU, sB.EnableNet, sB.EnableForward)
	}
}
