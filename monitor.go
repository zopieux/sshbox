package sshbox

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Monitor provides an interface for logging server and session activity.
type Monitor interface {
	Log(format string, args ...any)
	NewSession(remoteAddr string) SessionHandle
	Close()
}

// SessionHandle represents an active connection session.
type SessionHandle interface {
	SetUser(user string)
	SetType(typ string)
	SetJail(workDir string, port int)
	Log(format string, args ...any)
	Close()
}

// LogEntry stores a single timestamped log line.
type LogEntry struct {
	Time    time.Time
	Message string
}

// PlainMonitor outputs all logs directly to standard Go log.Printf (used when --no-ui is set or stdout is not a TTY).
type PlainMonitor struct {
	verbose bool
}

// NewPlainMonitor returns a Monitor that outputs to standard logger.
func NewPlainMonitor(verbose bool) *PlainMonitor {
	return &PlainMonitor{verbose: verbose}
}

func (p *PlainMonitor) Log(format string, args ...any) {
	log.Printf(format, args...)
}

func (p *PlainMonitor) NewSession(remoteAddr string) SessionHandle {
	return &plainSessionHandle{
		remoteAddr: remoteAddr,
		verbose:    p.verbose,
	}
}

func (p *PlainMonitor) Close() {}

type plainSessionHandle struct {
	remoteAddr string
	user       string
	typ        string
	workDir    string
	port       int
	verbose    bool
	mu         sync.Mutex
}

func (s *plainSessionHandle) SetUser(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.user = user
}

func (s *plainSessionHandle) SetType(typ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.typ = typ
}

func (s *plainSessionHandle) SetJail(workDir string, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workDir = workDir
	s.port = port
}

func (s *plainSessionHandle) Log(format string, args ...any) {
	s.mu.Lock()
	user := s.user
	if user == "" {
		user = "?"
	}
	addr := s.remoteAddr
	s.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s@%s] %s", user, addr, msg)
}

func (s *plainSessionHandle) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
}
