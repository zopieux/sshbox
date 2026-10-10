package sshbox

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// commandExecutor allows overriding exec.Command in tests
	commandExecutor = exec.Command
)

// PortForwarder coordinates automatic port exposure via firewall, NAT-PMP, or both.
type PortForwarder struct {
	Port     int
	Mode     OpenPortMode
	Gateway  string
	Lifetime time.Duration
	Monitor  Monitor

	mu        sync.Mutex
	openedNAT bool
	openedFW  bool
}

// NewPortForwarder initializes a PortForwarder for the given port and mode.
func NewPortForwarder(port int, mode OpenPortMode, mon Monitor) *PortForwarder {
	lifetime := 24 * time.Hour
	if envLife := os.Getenv("PORT_LIFETIME"); envLife != "" {
		if d, err := time.ParseDuration(envLife); err == nil && d > 0 {
			lifetime = d
		} else if val, err := strconv.Atoi(envLife); err == nil && val > 0 {
			lifetime = time.Duration(val) * time.Second
		}
	}
	return &PortForwarder{
		Port:     port,
		Mode:     mode,
		Lifetime: lifetime,
		Monitor:  mon,
	}
}

// Open attempts to open the port according to Mode (firewall, natpmp, both).
func (pf *PortForwarder) Open() {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.Mode == OpenPortNatPMP || pf.Mode == OpenPortBoth {
		pf.openNAT()
	}
	if pf.Mode == OpenPortFirewall || pf.Mode == OpenPortBoth {
		pf.openFirewall()
	}
}

// Close removes the natpmpc mapping and cleans up the firewall rule in the dedicated chain.
func (pf *PortForwarder) Close() {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.openedNAT {
		pf.closeNAT()
	}
	if pf.openedFW {
		pf.closeFirewall()
	}
}

func (pf *PortForwarder) getGateway() string {
	if pf.Gateway != "" {
		return pf.Gateway
	}
	gw := detectDefaultGateway()
	if gw == "" {
		gw = "192.168.1.1"
	}
	pf.Gateway = gw
	return gw
}

func detectDefaultGateway() string {
	cmd := commandExecutor("ip", "route", "show", "default")
	out, err := cmd.Output()
	if err == nil {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
		if len(fields) >= 3 {
			return fields[2]
		}
	}
	return "192.168.1.1"
}

func (pf *PortForwarder) openNAT() {
	gw := pf.getGateway()
	lifetimeSecs := int(pf.Lifetime.Seconds())
	if lifetimeSecs <= 0 {
		lifetimeSecs = 86400
	}
	lifetimeStr := strconv.Itoa(lifetimeSecs)
	portStr := strconv.Itoa(pf.Port)

	cmd := commandExecutor("natpmpc", "-g", gw, "-a", portStr, portStr, "tcp", lifetimeStr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if pf.Monitor != nil {
			pf.Monitor.Log("Warning: failed to open port %d via NAT-PMP (gateway: %s): %v (%s)",
				pf.Port, gw, err, strings.TrimSpace(string(out)))
		}
		return
	}
	pf.openedNAT = true
	if pf.Monitor != nil {
		pf.Monitor.Log("NAT-PMP: opened port %d (TCP) via %s", pf.Port, gw)
	}
}

func (pf *PortForwarder) closeNAT() {
	gw := pf.getGateway()
	portStr := strconv.Itoa(pf.Port)

	cmd := commandExecutor("natpmpc", "-g", gw, "-a", portStr, portStr, "tcp", "0")
	_ = cmd.Run()
	pf.openedNAT = false
	if pf.Monitor != nil {
		pf.Monitor.Log("NAT-PMP: closed port %d (TCP) via %s", pf.Port, gw)
	}
}

func runCmd(name string, args ...string) error {
	cmd := commandExecutor(name, args...)
	return cmd.Run()
}

func ensureFirewallChain() {
	// 1. IPv4: Ensure dedicated 'sshbox' chain exists
	_ = runCmd("sudo", "iptables", "-w", "-N", "sshbox")

	// Hook into 'nixos-fw' if present, otherwise 'INPUT'
	if err := runCmd("sudo", "iptables", "-w", "-C", "nixos-fw", "-j", "sshbox"); err != nil {
		if err2 := runCmd("sudo", "iptables", "-w", "-I", "nixos-fw", "1", "-j", "sshbox"); err2 != nil {
			if err3 := runCmd("sudo", "iptables", "-w", "-C", "INPUT", "-j", "sshbox"); err3 != nil {
				_ = runCmd("sudo", "iptables", "-w", "-I", "INPUT", "1", "-j", "sshbox")
			}
		}
	}

	// 2. IPv6: Ensure dedicated 'sshbox' chain exists
	_ = runCmd("sudo", "ip6tables", "-w", "-N", "sshbox")

	// Hook into 'nixos-fw' if present, otherwise 'INPUT'
	if err := runCmd("sudo", "ip6tables", "-w", "-C", "nixos-fw", "-j", "sshbox"); err != nil {
		if err2 := runCmd("sudo", "ip6tables", "-w", "-I", "nixos-fw", "1", "-j", "sshbox"); err2 != nil {
			if err3 := runCmd("sudo", "ip6tables", "-w", "-C", "INPUT", "-j", "sshbox"); err3 != nil {
				_ = runCmd("sudo", "ip6tables", "-w", "-I", "INPUT", "1", "-j", "sshbox")
			}
		}
	}
}

func (pf *PortForwarder) openFirewall() {
	ensureFirewallChain()
	portStr := strconv.Itoa(pf.Port)

	v4OK := false
	if err := runCmd("sudo", "iptables", "-w", "-C", "sshbox", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"); err != nil {
		if err2 := runCmd("sudo", "iptables", "-w", "-A", "sshbox", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"); err2 == nil {
			v4OK = true
		}
	} else {
		v4OK = true
	}

	v6OK := false
	if err := runCmd("sudo", "ip6tables", "-w", "-C", "sshbox", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"); err != nil {
		if err2 := runCmd("sudo", "ip6tables", "-w", "-A", "sshbox", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"); err2 == nil {
			v6OK = true
		}
	} else {
		v6OK = true
	}

	if v4OK || v6OK {
		pf.openedFW = true
		if pf.Monitor != nil {
			pf.Monitor.Log("Firewall: opened port %d (TCP) in dedicated chain sshbox", pf.Port)
		}
	} else if pf.Monitor != nil {
		pf.Monitor.Log("Warning: failed to add firewall rules for port %d in chain sshbox", pf.Port)
	}
}

func (pf *PortForwarder) closeFirewall() {
	portStr := strconv.Itoa(pf.Port)
	_ = runCmd("sudo", "iptables", "-w", "-D", "sshbox", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT")
	_ = runCmd("sudo", "ip6tables", "-w", "-D", "sshbox", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT")
	pf.openedFW = false
	if pf.Monitor != nil {
		pf.Monitor.Log("Firewall: closed port %d (TCP) in dedicated chain sshbox", pf.Port)
	}
}
