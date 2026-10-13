package sshbox

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	PaneSessions = 0
	PaneLogs     = 1
)

// JailInfo represents an active jail's root directory and port.
type JailInfo struct {
	WorkDir string
	Port    int
}

// SessionInfo holds the monitoring state and logs for a session.
type SessionInfo struct {
	ID           int
	RemoteAddr   string
	User         string
	Type         string
	JailDir      string
	JailPort     int
	Active       bool
	StartTime    time.Time
	EndTime      time.Time
	Logs         []LogEntry
	ScrollOffset int // 0 = at bottom; >0 = scrolled up by N lines
	AutoScroll   bool
	process      *os.Process
	closeFunc    func()
	mu           sync.RWMutex
}

// TUI manages the terminal user interface for monitoring sessions.
type TUI struct {
	workDir        string
	listenAddr     string
	jails          []JailInfo
	sessions       []*SessionInfo
	serverSession  *SessionInfo
	selectedIndex  int
	activePane     int
	mu             sync.RWMutex
	renderCh       chan struct{}
	quitCh         chan struct{}
	stopCh         chan struct{}
	oldTermState   *term.State
	closed         bool
	nextID         int
	onQuitCallback func()
}

// SetJails sets the list of managed jails for display in the TUI.
func (t *TUI) SetJails(jails []JailInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.jails = jails
	t.triggerRender()
}

// NewTUI initializes a new TUI monitor.
func NewTUI(workDir, listenAddr string) *TUI {
	if abs, err := filepath.Abs(workDir); err == nil {
		workDir = abs
	}
	t := &TUI{
		workDir:    workDir,
		listenAddr: listenAddr,
		renderCh:   make(chan struct{}, 1),
		quitCh:     make(chan struct{}),
		stopCh:     make(chan struct{}),
		nextID:     1,
		activePane: PaneSessions,
	}

	t.serverSession = &SessionInfo{
		ID:         0,
		RemoteAddr: "local",
		User:       "server",
		Type:       "daemon",
		Active:     true,
		StartTime:  time.Now(),
		AutoScroll: true,
	}
	t.sessions = append(t.sessions, t.serverSession)

	return t
}

// SetOnQuit sets a callback to invoke when the user presses 'q' or Ctrl+C in the TUI.
func (t *TUI) SetOnQuit(fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onQuitCallback = fn
}

// Start enters raw mode and launches the TUI rendering and input loops.
func (t *TUI) Start() error {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return fmt.Errorf("stdin is not a terminal")
	}

	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("enter raw mode: %w", err)
	}
	t.oldTermState = oldState

	// Enter alternate screen buffer & hide cursor
	_, _ = os.Stdout.WriteString("\x1b[?1049h\x1b[?25l")

	go t.renderLoop()
	go t.inputLoop()

	t.triggerRender()
	return nil
}

// QuitChan returns a channel that is closed when the user requests exit via the TUI.
func (t *TUI) QuitChan() <-chan struct{} {
	return t.quitCh
}

// Close restores the terminal.
func (t *TUI) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()

	close(t.stopCh)

	// Leave alternate screen buffer & show cursor
	_, _ = os.Stdout.WriteString("\x1b[?1049l\x1b[?25h")

	if t.oldTermState != nil {
		_ = term.Restore(int(os.Stdin.Fd()), t.oldTermState)
	}
}

func (t *TUI) getLogAreaHeight() int {
	_, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || height < 10 {
		height = 24
	}
	bodyHeight := height - 3
	logAreaHeight := bodyHeight - 4 // minus 2 detail lines, 1 separator line, 1 bottom line
	if logAreaHeight < 1 {
		logAreaHeight = 1
	}
	return logAreaHeight
}

func (t *TUI) logToSession(s *SessionInfo, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	s.mu.Lock()
	s.Logs = append(s.Logs, LogEntry{
		Time:    time.Now(),
		Message: msg,
	})
	logAreaHeight := t.getLogAreaHeight()
	maxOffset := len(s.Logs) - logAreaHeight
	if maxOffset <= 0 {
		s.ScrollOffset = 0
		s.AutoScroll = true
	} else if !s.AutoScroll && s.ScrollOffset > 0 {
		s.ScrollOffset++
		if s.ScrollOffset > maxOffset {
			s.ScrollOffset = maxOffset
		}
	}
	s.mu.Unlock()
	t.triggerRender()
}

// Log adds a server-level log entry to the [Server] session.
func (t *TUI) Log(format string, args ...any) {
	t.logToSession(t.serverSession, format, args...)
}

// NewSession creates and registers a new remote accepted connection session.
func (t *TUI) NewSession(remoteAddr string) SessionHandle {
	t.mu.Lock()
	id := t.nextID
	t.nextID++

	s := &SessionInfo{
		ID:         id,
		RemoteAddr: remoteAddr,
		User:       "connecting...",
		Type:       "accepted",
		Active:     true,
		StartTime:  time.Now(),
		AutoScroll: true,
	}
	s.Logs = append(s.Logs, LogEntry{
		Time:    time.Now(),
		Message: fmt.Sprintf("Accepted connection from %s", remoteAddr),
	})

	t.sessions = append(t.sessions, s)
	// Auto-select the newly arrived session if on server session or default
	if len(t.sessions) == 2 {
		t.selectedIndex = 1
	}
	t.mu.Unlock()

	t.triggerRender()
	return &tuiSessionHandle{t: t, info: s}
}

type tuiSessionHandle struct {
	t    *TUI
	info *SessionInfo
}

func (h *tuiSessionHandle) SetUser(user string) {
	h.info.mu.Lock()
	h.info.User = user
	h.info.mu.Unlock()
	h.t.triggerRender()
}

func (h *tuiSessionHandle) SetType(typ string) {
	h.info.mu.Lock()
	h.info.Type = typ
	h.info.mu.Unlock()
	h.t.triggerRender()
}

func (h *tuiSessionHandle) SetJail(workDir string, port int) {
	h.info.mu.Lock()
	h.info.JailDir = workDir
	h.info.JailPort = port
	h.info.mu.Unlock()
	h.t.triggerRender()
}

func (h *tuiSessionHandle) SetProcess(proc *os.Process) {
	h.info.mu.Lock()
	h.info.process = proc
	h.info.mu.Unlock()
}

func (h *tuiSessionHandle) SetCloseFunc(fn func()) {
	h.info.mu.Lock()
	h.info.closeFunc = fn
	h.info.mu.Unlock()
}

func (h *tuiSessionHandle) Log(format string, args ...any) {
	h.t.logToSession(h.info, format, args...)
}

func (h *tuiSessionHandle) Close() {
	h.info.mu.Lock()
	h.info.Active = false
	h.info.process = nil
	h.info.closeFunc = nil
	h.info.EndTime = time.Now()
	dur := h.info.EndTime.Sub(h.info.StartTime).Truncate(time.Second)
	h.info.Logs = append(h.info.Logs, LogEntry{
		Time:    time.Now(),
		Message: fmt.Sprintf("Session closed (duration: %s)", dur),
	})
	logAreaHeight := h.t.getLogAreaHeight()
	maxOffset := len(h.info.Logs) - logAreaHeight
	if maxOffset <= 0 {
		h.info.ScrollOffset = 0
		h.info.AutoScroll = true
	} else if !h.info.AutoScroll && h.info.ScrollOffset > 0 {
		h.info.ScrollOffset++
		if h.info.ScrollOffset > maxOffset {
			h.info.ScrollOffset = maxOffset
		}
	}
	h.info.mu.Unlock()
	h.t.triggerRender()
}

func (t *TUI) triggerRender() {
	select {
	case t.renderCh <- struct{}{}:
	default:
	}
}

func (t *TUI) renderLoop() {
	sigWinch := make(chan os.Signal, 1)
	signal.Notify(sigWinch, syscall.SIGWINCH)
	defer signal.Stop(sigWinch)

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-sigWinch:
			t.render()
		case <-t.renderCh:
			t.render()
		case <-ticker.C:
			// Periodic refresh for duration counters
			t.render()
		}
	}
}

func (t *TUI) inputLoop() {
	buf := make([]byte, 32)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}

		select {
		case <-t.stopCh:
			return
		default:
		}

		t.handleInput(buf[:n])
	}
}

func (t *TUI) handleInput(b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Quit keys: Ctrl+C (3) or 'q' / 'Q'
	if len(b) == 1 {
		switch b[0] {
		case 3, 'q', 'Q':
			select {
			case <-t.quitCh:
			default:
				close(t.quitCh)
			}
			if t.onQuitCallback != nil {
				go t.onQuitCallback()
			}
			return

		case '\t': // Tab: toggle pane focus
			if t.activePane == PaneSessions {
				t.activePane = PaneLogs
			} else {
				t.activePane = PaneSessions
			}
			t.triggerRender()
			return

		case '\r', '\n': // Enter: focus logs pane
			t.activePane = PaneLogs
			t.triggerRender()
			return


		case 'j':
			if t.activePane == PaneSessions {
				t.navigateSession(1)
			} else {
				t.scrollCurrentSession(1)
			}
			t.triggerRender()
			return

		case 'k':
			if t.activePane == PaneSessions {
				t.navigateSession(-1)
			} else {
				t.scrollCurrentSession(-1)
			}
			t.triggerRender()
			return

		case 'x', 'X':
			t.killSelectedSessionLocked()
			t.triggerRender()
			return

		case 'g': // Home
			t.scrollCurrentSessionToTop()
			t.triggerRender()
			return

		case 'G': // End
			t.scrollCurrentSessionToBottom()
			t.triggerRender()
			return

		case 'c', 'C', 'd', 'D': // Clean dead sessions
			t.cleanDeadSessionsLocked()
			t.triggerRender()
			return
		}
	}

	// Escape sequences
	seq := string(b)
	switch {
	case seq == "\x1b[Z": // Shift-Tab
		if t.activePane == PaneSessions {
			t.activePane = PaneLogs
		} else {
			t.activePane = PaneSessions
		}
		t.triggerRender()

	case seq == "\x1b[A": // Up arrow
		if t.activePane == PaneSessions {
			t.navigateSession(-1)
		} else {
			t.scrollCurrentSession(-1)
		}
		t.triggerRender()

	case seq == "\x1b[B": // Down arrow
		if t.activePane == PaneSessions {
			t.navigateSession(1)
		} else {
			t.scrollCurrentSession(1)
		}
		t.triggerRender()

	case seq == "\x1b[5~": // Page Up
		t.scrollCurrentSessionPage(-1)
		t.triggerRender()

	case seq == "\x1b[6~": // Page Down
		t.scrollCurrentSessionPage(1)
		t.triggerRender()

	case seq == "\x1b[H" || seq == "\x1b[1~" || seq == "\x1b[7~": // Home
		t.scrollCurrentSessionToTop()
		t.triggerRender()

	case seq == "\x1b[F" || seq == "\x1b[4~" || seq == "\x1b[8~": // End
		t.scrollCurrentSessionToBottom()
		t.triggerRender()
	}
}

// KillSelectedSession immediately kills (-9) the jailed (bwrap) process that is selected highlighted,
// or closes the session in case of a forward. On the server pane this does nothing.
func (t *TUI) KillSelectedSession() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.killSelectedSessionLocked()
	t.triggerRender()
}

func (t *TUI) killSelectedSessionLocked() {
	if t.selectedIndex < 0 || t.selectedIndex >= len(t.sessions) {
		return
	}
	s := t.sessions[t.selectedIndex]
	if s.ID == 0 {
		// on the server pane this does nothing
		return
	}
	if !s.Active {
		return
	}

	s.mu.Lock()
	proc := s.process
	closeFn := s.closeFunc
	sessType := s.Type
	s.process = nil
	s.mu.Unlock()

	if proc != nil {
		t.logToSession(s, "Killed (-9) jailed process (PID %d)", proc.Pid)
		_ = proc.Signal(syscall.SIGKILL)
	} else if strings.HasPrefix(sessType, "fwd") || closeFn != nil {
		t.logToSession(s, "Forward session closed by operator")
		if closeFn != nil {
			go closeFn()
		}
	}
}

// CleanDeadSessions removes all terminated sessions from the TUI.
// If the user was focused in the logs pane of a dead session, it navigates
// to the always-there main server in the left pane.
func (t *TUI) CleanDeadSessions() {
	t.mu.Lock()
	t.cleanDeadSessionsLocked()
	t.mu.Unlock()
	t.triggerRender()
}

func (t *TUI) cleanDeadSessionsLocked() {
	if len(t.sessions) == 0 {
		return
	}

	var currentSelected *SessionInfo
	if t.selectedIndex >= 0 && t.selectedIndex < len(t.sessions) {
		currentSelected = t.sessions[t.selectedIndex]
	}

	wasLogsPaneOfDead := false
	if currentSelected != nil && t.activePane == PaneLogs && !currentSelected.Active && currentSelected.ID != 0 {
		wasLogsPaneOfDead = true
	}

	var newSessions []*SessionInfo
	for _, s := range t.sessions {
		if s.ID == 0 || s.Active {
			newSessions = append(newSessions, s)
		}
	}
	t.sessions = newSessions

	if wasLogsPaneOfDead {
		t.selectedIndex = 0
		t.activePane = PaneSessions
	} else if currentSelected != nil {
		found := false
		for i, s := range t.sessions {
			if s == currentSelected {
				t.selectedIndex = i
				found = true
				break
			}
		}
		if !found {
			if t.selectedIndex >= len(t.sessions) {
				t.selectedIndex = len(t.sessions) - 1
			}
			if t.selectedIndex < 0 {
				t.selectedIndex = 0
			}
		}
	}
}

func (t *TUI) navigateSession(delta int) {
	if len(t.sessions) == 0 {
		return
	}
	t.selectedIndex += delta
	if t.selectedIndex < 0 {
		t.selectedIndex = 0
	}
	if t.selectedIndex >= len(t.sessions) {
		t.selectedIndex = len(t.sessions) - 1
	}
}

func (t *TUI) scrollCurrentSession(delta int) {
	if t.selectedIndex < 0 || t.selectedIndex >= len(t.sessions) {
		return
	}
	s := t.sessions[t.selectedIndex]
	s.mu.Lock()
	defer s.mu.Unlock()

	logAreaHeight := t.getLogAreaHeight()
	maxOffset := len(s.Logs) - logAreaHeight
	if maxOffset <= 0 {
		// All lines fit within the viewport: scrolling does nothing!
		s.ScrollOffset = 0
		s.AutoScroll = true
		return
	}

	if delta < 0 {
		// delta < 0: scroll up towards older logs
		s.ScrollOffset -= delta // increase offset
		if s.ScrollOffset > maxOffset {
			s.ScrollOffset = maxOffset
		}
		s.AutoScroll = false
	} else if delta > 0 {
		// delta > 0: scroll down towards recent logs
		s.ScrollOffset -= delta
		if s.ScrollOffset <= 0 {
			s.ScrollOffset = 0
			s.AutoScroll = true
		}
	}
}

func (t *TUI) scrollCurrentSessionPage(dir int) {
	pageSize := t.getLogAreaHeight()
	if pageSize > 2 {
		pageSize -= 2
	}
	t.scrollCurrentSession(dir * pageSize)
}

func (t *TUI) scrollCurrentSessionToTop() {
	if t.selectedIndex < 0 || t.selectedIndex >= len(t.sessions) {
		return
	}
	s := t.sessions[t.selectedIndex]
	s.mu.Lock()
	defer s.mu.Unlock()

	logAreaHeight := t.getLogAreaHeight()
	maxOffset := len(s.Logs) - logAreaHeight
	if maxOffset <= 0 {
		s.ScrollOffset = 0
		s.AutoScroll = true
		return
	}
	s.ScrollOffset = maxOffset
	s.AutoScroll = false
}

func (t *TUI) scrollCurrentSessionToBottom() {
	if t.selectedIndex < 0 || t.selectedIndex >= len(t.sessions) {
		return
	}
	s := t.sessions[t.selectedIndex]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ScrollOffset = 0
	s.AutoScroll = true
}

func visibleWidth(s string) int {
	w := 0
	inEsc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '~' {
				inEsc = false
			}
			continue
		}
		// ASCII fast path
		if c < 128 {
			w++
		} else {
			r, size := utf8.DecodeRuneInString(s[i:])
			i += size - 1
			_ = r
			w++
		}
	}
	return w
}

func padOrTruncate(s string, targetWidth int) string {
	curr := visibleWidth(s)
	if curr == targetWidth {
		return s
	}
	if curr < targetWidth {
		return s + strings.Repeat(" ", targetWidth-curr)
	}
	// Truncate to targetWidth
	var b strings.Builder
	w := 0
	inEsc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\x1b' {
			inEsc = true
			b.WriteByte(c)
			continue
		}
		if inEsc {
			b.WriteByte(c)
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '~' {
				inEsc = false
			}
			continue
		}
		if w >= targetWidth {
			break
		}
		if c < 128 {
			b.WriteByte(c)
			w++
		} else {
			_, size := utf8.DecodeRuneInString(s[i:])
			b.WriteString(s[i : i+size])
			i += size - 1
			w++
		}
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

func (t *TUI) render() {
	t.mu.RLock()
	defer t.mu.RUnlock()

	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 50 || height < 10 {
		width = 80
		height = 24
	}

	avail := width - 3 // 3 columns for left border, mid divider, right border
	leftInnerW := avail / 3
	if leftInnerW < 22 {
		leftInnerW = 22
	}
	if leftInnerW > avail-25 {
		leftInnerW = avail - 25
	}
	rightInnerW := avail - leftInnerW

	var buf bytes.Buffer
	buf.WriteString("\x1b[H") // Move to top-left (no clear to avoid flicker)

	// ANSI Colors & Styles
	cReset := "\x1b[0m"
	cDim := "\x1b[90m"
	cBold := "\x1b[1m"
	cCyan := "\x1b[36m"
	cGreen := "\x1b[32m"
	cYellow := "\x1b[33m"
	cWhite := "\x1b[37m"
	cRev := "\x1b[7m"

	// 1. Top Bar: Server summary
	activeCount := 0
	for _, s := range t.sessions {
		if s.ID != 0 && s.Active {
			activeCount++
		}
	}

	var topBarLeft string
	if len(t.jails) > 1 {
		var portStrs []string
		for _, j := range t.jails {
			portStrs = append(portStrs, fmt.Sprintf("%d", j.Port))
		}
		topBarLeft = fmt.Sprintf(" %s%ssshbox%s │ Jails: %d │ Ports: %s%s%s",
			cBold, cCyan, cReset,
			len(t.jails),
			cWhite, strings.Join(portStrs, ", "), cReset,
		)
	} else {
		topBarLeft = fmt.Sprintf(" %s%ssshbox%s │ Listen: %s%s%s │ Root: %s",
			cBold, cCyan, cReset,
			cWhite, t.listenAddr, cReset,
			t.workDir,
		)
	}

	topBarRight := fmt.Sprintf("Active: %s%d%s ",
		cGreen, activeCount, cReset,
	)
	topSpaces := width - visibleWidth(topBarLeft) - visibleWidth(topBarRight)
	if topSpaces < 1 {
		topSpaces = 1
	}
	topLine := topBarLeft + strings.Repeat(" ", topSpaces) + topBarRight
	buf.WriteString(cRev)
	buf.WriteString(padOrTruncate(topLine, width))
	buf.WriteString(cReset)
	buf.WriteString("\r\n")

	// 2. Panes Headers
	leftFocused := (t.activePane == PaneSessions)
	rightFocused := (t.activePane == PaneLogs)

	leftBorderColor := cDim
	if leftFocused {
		leftBorderColor = cBold + cCyan
	}
	rightBorderColor := cDim
	if rightFocused {
		rightBorderColor = cBold + cCyan
	}
	midBorderColor := cDim
	if leftFocused || rightFocused {
		midBorderColor = cCyan
	}

	leftTitleText := fmt.Sprintf(" SESSIONS (%d) ", activeCount)
	if leftFocused {
		leftTitleText = fmt.Sprintf(" [SESSIONS (%d)] ", activeCount)
	}
	leftHeaderBar := "─" + cBold + cWhite + leftTitleText + leftBorderColor
	leftFill := leftInnerW - 1 - visibleWidth(leftTitleText)
	if leftFill > 0 {
		leftHeaderBar += strings.Repeat("─", leftFill)
	}

	rightTitleText := " SESSION LOGS "
	if rightFocused {
		rightTitleText = " [SESSION LOGS] "
	}
	rightHeaderBar := "─" + cBold + cWhite + rightTitleText + rightBorderColor
	rightFill := rightInnerW - 1 - visibleWidth(rightTitleText)
	if rightFill > 0 {
		rightHeaderBar += strings.Repeat("─", rightFill)
	}

	// Full top border of the grid:
	// ┌ (1) + leftHeaderBar (leftInnerW) + ┬ (1) + rightHeaderBar (rightInnerW) + ┐ (1)
	buf.WriteString(leftBorderColor)
	buf.WriteString("┌")
	buf.WriteString(leftHeaderBar)
	buf.WriteString(midBorderColor)
	buf.WriteString("┬")
	buf.WriteString(rightBorderColor)
	buf.WriteString(rightHeaderBar)
	buf.WriteString("┐")
	buf.WriteString(cReset)
	buf.WriteString("\r\n")

	// Main body height (excluding top bar, header line, bottom border line, status bar)
	bodyHeight := height - 3
	if bodyHeight < 4 {
		bodyHeight = 4
	}

	// Prepare current selected session
	var currentSession *SessionInfo
	if t.selectedIndex >= 0 && t.selectedIndex < len(t.sessions) {
		currentSession = t.sessions[t.selectedIndex]
	}

	// Right pane details header (rows 0, 1)
	rightDetailsLines := make([]string, 2)
	if currentSession != nil {
		currentSession.mu.RLock()
		duration := time.Since(currentSession.StartTime).Truncate(time.Second)
		var statusStr string
		if currentSession.Active {
			statusStr = fmt.Sprintf("%s● ACTIVE%s (running: %s)", cBold+cGreen, cReset, duration)
		} else {
			if !currentSession.EndTime.IsZero() {
				duration = currentSession.EndTime.Sub(currentSession.StartTime).Truncate(time.Second)
			}
			statusStr = fmt.Sprintf("%s○ CLOSED%s (duration: %s)", cDim, cReset, duration)
		}

		if currentSession.ID == 0 {
			rightDetailsLines[0] = fmt.Sprintf(" %sSession: [Server Host]%s │ Status: %s", cBold, cReset, statusStr)
			if len(t.jails) > 1 {
				var jailStrs []string
				for _, j := range t.jails {
					jailStrs = append(jailStrs, fmt.Sprintf("%s(:%d)", filepath.Base(j.WorkDir), j.Port))
				}
				rightDetailsLines[1] = fmt.Sprintf(" Jails (%d): %s", len(t.jails), strings.Join(jailStrs, ", "))
			} else {
				rightDetailsLines[1] = fmt.Sprintf(" Sandbox Root: %s", t.workDir)
			}
		} else {
			user := currentSession.User
			if user == "" {
				user = "(auth...)"
			}
			rightDetailsLines[0] = fmt.Sprintf(" %s#%d %s@%s%s │ Status: %s │ Type: %s%s%s",
				cBold, currentSession.ID, user, currentSession.RemoteAddr, cReset,
				statusStr, cCyan, currentSession.Type, cReset)
			root := currentSession.JailDir
			if root == "" {
				root = t.workDir
			}
			portStr := ""
			if currentSession.JailPort > 0 {
				portStr = fmt.Sprintf(" │ Port: %d", currentSession.JailPort)
			}
			rightDetailsLines[1] = fmt.Sprintf(" Started: %s%s │ Sandbox Root: %s │ Logs: %d lines",
				currentSession.StartTime.Format("15:04:05"), portStr, root, len(currentSession.Logs))
		}
		currentSession.mu.RUnlock()
	} else {
		rightDetailsLines[0] = " No session selected"
		rightDetailsLines[1] = ""
	}

	logAreaHeight := bodyHeight - 4 // minus 2 detail lines, 1 separator line, 1 bottom line
	if logAreaHeight < 1 {
		logAreaHeight = 1
	}

	// Prepare logs lines for right pane
	var logLinesToDisplay []string
	autoScrollStatus := ""
	if currentSession != nil {
		currentSession.mu.RLock()
		totalLogs := len(currentSession.Logs)
		offset := currentSession.ScrollOffset

		if currentSession.AutoScroll || offset == 0 {
			autoScrollStatus = fmt.Sprintf("%s[● Auto-scroll: ON]%s", cGreen, cReset)
			start := totalLogs - logAreaHeight
			if start < 0 {
				start = 0
			}
			for i := start; i < totalLogs; i++ {
				entry := currentSession.Logs[i]
				line := fmt.Sprintf("%s[%s]%s %s",
					cDim, entry.Time.Format("15:04:05"), cReset, entry.Message)
				logLinesToDisplay = append(logLinesToDisplay, line)
			}
		} else {
			autoScrollStatus = fmt.Sprintf("%s[▲ Scrolled +%d | Auto-scroll: PAUSED]%s", cYellow, offset, cReset)
			end := totalLogs - offset
			if end < 0 {
				end = 0
			}
			start := end - logAreaHeight
			if start < 0 {
				start = 0
			}
			for i := start; i < end; i++ {
				entry := currentSession.Logs[i]
				line := fmt.Sprintf("%s[%s]%s %s",
					cDim, entry.Time.Format("15:04:05"), cReset, entry.Message)
				logLinesToDisplay = append(logLinesToDisplay, line)
			}
		}
		currentSession.mu.RUnlock()
	}

	// Render rows
	for row := 0; row < bodyHeight-1; row++ {
		// --- Left Pane Content ---
		leftContent := ""
		if row < len(t.sessions) {
			sess := t.sessions[row]
			sess.mu.RLock()
			statusDot := fmt.Sprintf("%s●%s", cGreen, cReset)
			if !sess.Active {
				statusDot = fmt.Sprintf("%s○%s", cDim, cReset)
			}

			user := sess.User
			if user == "" {
				user = "?"
			}

			var itemText string
			if sess.ID == 0 {
				itemText = fmt.Sprintf("%s [Server]", statusDot)
			} else if sess.JailPort > 0 && len(t.jails) > 1 {
				itemText = fmt.Sprintf("%s #%d %s [%s] :%d", statusDot, sess.ID, user, sess.Type, sess.JailPort)
			} else {
				itemText = fmt.Sprintf("%s #%d %s [%s]", statusDot, sess.ID, user, sess.Type)
			}
			sess.mu.RUnlock()

			if row == t.selectedIndex {
				if leftFocused {
					leftContent = fmt.Sprintf("%s▶ %s%s", cBold+cCyan, itemText, cReset)
				} else {
					leftContent = fmt.Sprintf("▶ %s", itemText)
				}
			} else {
				leftContent = fmt.Sprintf("  %s", itemText)
			}
		}
		leftPadded := padOrTruncate(leftContent, leftInnerW)

		// --- Right Pane Content and Separator ---
		var midChar, rightBorderChar, rightPadded string
		if row < 2 {
			midChar = "│"
			rightBorderChar = "│"
			rightPadded = padOrTruncate(rightDetailsLines[row], rightInnerW)
		} else if row == 2 {
			midChar = "├"
			rightBorderChar = "┤"
			rightPadded = rightBorderColor + strings.Repeat("─", rightInnerW) + cReset
		} else {
			midChar = "│"
			rightBorderChar = "│"
			logIndex := row - 3
			content := ""
			if logIndex < len(logLinesToDisplay) {
				content = " " + logLinesToDisplay[logIndex]
			}
			rightPadded = padOrTruncate(content, rightInnerW)
		}

		buf.WriteString(leftBorderColor)
		buf.WriteString("│")
		buf.WriteString(cReset)
		buf.WriteString(leftPadded)
		buf.WriteString(midBorderColor)
		buf.WriteString(midChar)
		buf.WriteString(cReset)
		buf.WriteString(rightPadded)
		buf.WriteString(rightBorderColor)
		buf.WriteString(rightBorderChar)
		buf.WriteString(cReset)
		buf.WriteString("\r\n")
	}

	// Bottom border of panes:
	// └ (1) + leftBottomBar (leftInnerW) + ┴ (1) + rightBottomBar (rightInnerW) + ┘ (1)
	leftBottomBar := strings.Repeat("─", leftInnerW)
	rightBottomBar := ""
	if autoScrollStatus != "" {
		badge := " " + autoScrollStatus + " "
		badgeW := visibleWidth(badge)
		fill := rightInnerW - badgeW - 1
		if fill >= 0 {
			rightBottomBar = strings.Repeat("─", fill) + badge + rightBorderColor + "─"
		} else {
			rightBottomBar = strings.Repeat("─", rightInnerW)
		}
	} else {
		rightBottomBar = strings.Repeat("─", rightInnerW)
	}

	buf.WriteString(leftBorderColor)
	buf.WriteString("└")
	buf.WriteString(leftBottomBar)
	buf.WriteString(midBorderColor)
	buf.WriteString("┴")
	buf.WriteString(rightBorderColor)
	buf.WriteString(rightBottomBar)
	buf.WriteString("┘")
	buf.WriteString(cReset)
	buf.WriteString("\r\n")

	// 3. Status Bar (Keybindings & Hints)
	statusText := fmt.Sprintf(" %s[Tab]%s Switch Pane  %s[↑/↓]%s %s  %s[x]%s Kill  %s[PgUp/PgDn]%s Scroll Logs  %s[c]%s Clean  %s[q]%s Quit",
		cBold, cReset,
		cBold, cReset,
		func() string {
			if leftFocused {
				return "Select Session"
			}
			return "Scroll Line"
		}(),
		cBold, cReset,
		cBold, cReset,
		cBold, cReset,
		cBold, cReset,
	)
	buf.WriteString(cRev)
	buf.WriteString(padOrTruncate(statusText, width))
	buf.WriteString(cReset)

	_, _ = os.Stdout.Write(buf.Bytes())
}
