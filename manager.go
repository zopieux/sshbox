package sshbox

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// PortConflictError records a port that is used by multiple jails.
type PortConflictError struct {
	Port int
	Dirs []string
}

func (e *PortConflictError) Error() string {
	return fmt.Sprintf("port %d is used by multiple jails: %s", e.Port, strings.Join(e.Dirs, ", "))
}

// Manager coordinates multiple independent jails centrally.
type Manager struct {
	Servers   []*Server
	Listeners []net.Listener
	mu        sync.Mutex
	closed    bool
}

// CheckPortConflicts inspects the .sshbox.toml config of each directory and identifies duplicate ports.
func CheckPortConflicts(dirs []string) ([]*PortConflictError, error) {
	portToDirs := make(map[int][]string)
	seenDirs := make(map[string]bool)

	for _, d := range dirs {
		absDir, err := filepath.Abs(d)
		if err != nil {
			return nil, fmt.Errorf("resolve path %s: %w", d, err)
		}
		if seenDirs[absDir] {
			continue
		}
		seenDirs[absDir] = true

		cfg, _, err := LoadOrInitConfig(absDir)
		if err != nil {
			return nil, fmt.Errorf("load config for %s: %w", absDir, err)
		}

		port := cfg.GetPort()
		portToDirs[port] = append(portToDirs[port], absDir)
	}

	var conflicts []*PortConflictError
	for port, absDirs := range portToDirs {
		if len(absDirs) > 1 {
			sort.Strings(absDirs)
			conflicts = append(conflicts, &PortConflictError{
				Port: port,
				Dirs: absDirs,
			})
		}
	}

	sort.Slice(conflicts, func(i, j int) bool {
		return conflicts[i].Port < conflicts[j].Port
	})

	return conflicts, nil
}

// NewManager initializes independent servers for each directory, rejecting any port conflicts.
func NewManager(dirs []string, mon Monitor, opts ...ServerOption) (*Manager, error) {
	conflicts, err := CheckPortConflicts(dirs)
	if err != nil {
		return nil, err
	}
	if len(conflicts) > 0 {
		var msgs []string
		for _, c := range conflicts {
			msgs = append(msgs, c.Error())
		}
		return nil, errors.New(strings.Join(msgs, "; "))
	}

	seenDirs := make(map[string]bool)
	var servers []*Server

	for _, d := range dirs {
		absDir, err := filepath.Abs(d)
		if err != nil {
			return nil, err
		}
		if seenDirs[absDir] {
			continue
		}
		seenDirs[absDir] = true

		srvOpts := []ServerOption{WithMonitor(mon)}
		for _, opt := range opts {
			temp := &Server{}
			opt(temp)
			if temp.Verbose {
				srvOpts = append(srvOpts, WithVerbose(true))
			}
		}
		srv, err := NewServer(absDir, srvOpts...)
		if err != nil {
			return nil, fmt.Errorf("initialize jail server for %s: %w", absDir, err)
		}
		servers = append(servers, srv)
	}

	return &Manager{Servers: servers}, nil
}

// Jails returns the list of JailInfo managed by this Manager.
func (m *Manager) Jails() []JailInfo {
	var list []JailInfo
	for _, s := range m.Servers {
		list = append(list, JailInfo{
			WorkDir: s.WorkDir,
			Port:    s.Port,
		})
	}
	return list
}

// Serve starts listening on all jail ports and serves SSH connections independently.
func (m *Manager) Serve(host string) error {
	var listeners []net.Listener
	for _, s := range m.Servers {
		addr := fmt.Sprintf("%s:%d", host, s.Port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			for _, prev := range listeners {
				_ = prev.Close()
			}
			return fmt.Errorf("listen on %s (%s): %w", addr, s.WorkDir, err)
		}
		listeners = append(listeners, l)
		s.Monitor.Log("sshbox jail listening on %s (sandbox root: %s)", addr, s.WorkDir)
	}

	m.mu.Lock()
	m.Listeners = listeners
	m.mu.Unlock()

	errCh := make(chan error, len(m.Servers))
	for i, s := range m.Servers {
		l := listeners[i]
		srv := s
		go func() {
			errCh <- srv.Serve(l)
		}()
	}

	return <-errCh
}

// Close shuts down all listening sockets across all jails.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for _, l := range m.Listeners {
		_ = l.Close()
	}
	for _, s := range m.Servers {
		s.ClosePortForward()
	}
}
