package sshbox

import (
	"strings"
	"testing"
	"time"
)

func TestPlainMonitor(t *testing.T) {
	mon := NewPlainMonitor(true)
	mon.Log("Server log test: %s", "hello")

	sess := mon.NewSession("127.0.0.1:12345")
	sess.SetUser("alice")
	sess.SetType("shell")
	sess.Log("Session log test: %d", 42)
	sess.Close()
	mon.Close()
}

func TestTUIMonitorSessionsAndAutoscroll(t *testing.T) {
	tui := NewTUI("/tmp/work", "0.0.0.0:2222")

	// 1. Initial state should have 1 session ([Server])
	if len(tui.sessions) != 1 {
		t.Fatalf("expected 1 initial session, got %d", len(tui.sessions))
	}
	serverSess := tui.sessions[0]
	if serverSess.ID != 0 || serverSess.User != "server" {
		t.Fatalf("unexpected server session: %+v", serverSess)
	}

	// Log to server session
	tui.Log("Server starting on port %d", 2222)
	if len(serverSess.Logs) != 1 {
		t.Fatalf("expected 1 server log, got %d", len(serverSess.Logs))
	}

	// 2. Add remote accepted connection
	sessHandle := tui.NewSession("192.168.1.100:54321")
	if len(tui.sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(tui.sessions))
	}

	sess := tui.sessions[1]
	if sess.ID != 1 {
		t.Errorf("expected session ID 1, got %d", sess.ID)
	}
	if !sess.Active {
		t.Errorf("expected active session")
	}
	if !sess.AutoScroll {
		t.Errorf("expected AutoScroll to be true initially")
	}
	if sess.ScrollOffset != 0 {
		t.Errorf("expected ScrollOffset to be 0 initially")
	}

	// 3. Update session metadata and add logs
	sessHandle.SetUser("bob")
	sessHandle.SetType("shell")
	if sess.User != "bob" {
		t.Errorf("expected user bob, got %s", sess.User)
	}
	if sess.Type != "shell" {
		t.Errorf("expected type shell, got %s", sess.Type)
	}

	for i := 0; i < 50; i++ {
		sessHandle.Log("Log entry line %d", i)
	}

	// Autoscroll should remain ON and offset 0
	if !sess.AutoScroll || sess.ScrollOffset != 0 {
		t.Errorf("expected AutoScroll=true, offset=0, got auto=%v, offset=%d", sess.AutoScroll, sess.ScrollOffset)
	}

	// 4. Test scrolling up (simulating Page Up or Up arrow)
	tui.scrollCurrentSession(-5)
	if sess.AutoScroll {
		t.Errorf("expected AutoScroll=false after scrolling up")
	}
	if sess.ScrollOffset != 5 {
		t.Errorf("expected ScrollOffset=5, got %d", sess.ScrollOffset)
	}

	// Adding a log while scrolled up should increment offset so visible view does not jump
	prevOffset := sess.ScrollOffset
	sessHandle.Log("Background incoming log")
	if sess.ScrollOffset != prevOffset+1 {
		t.Errorf("expected ScrollOffset=%d after incoming log, got %d", prevOffset+1, sess.ScrollOffset)
	}

	// 5. Test scrolling down (simulating Page Down or Down arrow) back to end
	tui.scrollCurrentSession(sess.ScrollOffset)
	if !sess.AutoScroll {
		t.Errorf("expected AutoScroll=true after scrolling back to end")
	}
	if sess.ScrollOffset != 0 {
		t.Errorf("expected ScrollOffset=0, got %d", sess.ScrollOffset)
	}

	// 6. Test Jump to Top / Jump to Bottom
	tui.scrollCurrentSessionToTop()
	if sess.AutoScroll {
		t.Errorf("expected AutoScroll=false at top")
	}
	if sess.ScrollOffset == 0 {
		t.Errorf("expected positive ScrollOffset at top")
	}

	tui.scrollCurrentSessionToBottom()
	if !sess.AutoScroll || sess.ScrollOffset != 0 {
		t.Errorf("expected AutoScroll=true, offset=0 after jump to bottom")
	}

	// 7. Test closing session
	sessHandle.Close()
	if sess.Active {
		t.Errorf("expected session to be inactive after Close()")
	}

	// 8. Test pane toggling
	if tui.activePane != PaneSessions {
		tui.activePane = PaneSessions
	}
	tui.handleInput([]byte{'\t'}) // Tab key
	if tui.activePane != PaneLogs {
		t.Errorf("expected PaneLogs after Tab, got %d", tui.activePane)
	}
	tui.handleInput([]byte{'\t'}) // Tab key again
	if tui.activePane != PaneSessions {
		t.Errorf("expected PaneSessions after second Tab, got %d", tui.activePane)
	}

	// 9. Test session navigation
	sessHandle2 := tui.NewSession("192.168.1.101:54322")
	_ = sessHandle2
	tui.selectedIndex = 0
	tui.handleInput([]byte{'j'}) // Next
	if tui.selectedIndex != 1 {
		t.Errorf("expected selectedIndex=1 after 'j', got %d", tui.selectedIndex)
	}
	tui.handleInput([]byte{'k'}) // Prev
	if tui.selectedIndex != 0 {
		t.Errorf("expected selectedIndex=0 after 'k', got %d", tui.selectedIndex)
	}
}

func TestPadOrTruncate(t *testing.T) {
	cases := []struct {
		input  string
		width  int
		expect int
	}{
		{"hello", 10, 10},
		{"hello world this is long", 8, 8},
		{"\x1b[32mgreen\x1b[0m", 10, 10},
		{"\x1b[1;36mcolored and very long text\x1b[0m", 12, 12},
	}

	for _, c := range cases {
		out := padOrTruncate(c.input, c.width)
		w := visibleWidth(out)
		if w != c.expect {
			t.Errorf("padOrTruncate(%q, %d) has visible width %d, expected %d", c.input, c.width, w, c.expect)
		}
	}

	// Check truncation content
	short := padOrTruncate("abcdefghij", 5)
	if !strings.HasPrefix(short, "abcde") {
		t.Errorf("expected prefix abcde, got %q", short)
	}
}

func TestTUIQuitHandling(t *testing.T) {
	tui := NewTUI("/tmp", "localhost:2222")

	quitCalled := false
	tui.SetOnQuit(func() {
		quitCalled = true
	})

	tui.handleInput([]byte{'q'})

	select {
	case <-tui.QuitChan():
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Fatal("QuitChan not closed on 'q'")
	}

	time.Sleep(20 * time.Millisecond)
	if !quitCalled {
		t.Error("expected onQuitCallback to be invoked")
	}
}

func TestClientSessionCountAndHeader(t *testing.T) {
	tui := NewTUI("/test", "127.0.0.1:2222")

	// Initially, 0 remote client sessions (only Server)
	clientCount := 0
	for _, s := range tui.sessions {
		if s.ID != 0 {
			clientCount++
		}
	}
	if clientCount != 0 {
		t.Fatalf("expected 0 client sessions initially, got %d", clientCount)
	}

	// Add a client session
	sess := tui.NewSession("1.2.3.4:5678")
	clientCount = 0
	for _, s := range tui.sessions {
		if s.ID != 0 {
			clientCount++
		}
	}
	if clientCount != 1 {
		t.Fatalf("expected 1 client session after adding connection, got %d", clientCount)
	}

	sess.Close()
}

func TestScrollingDoesNothingWhenAllLinesFit(t *testing.T) {
	tui := NewTUI("/tmp", "127.0.0.1:2222")
	sessHandle := tui.NewSession("127.0.0.1:1111")
	sess := tui.sessions[1]

	// Only 2 log lines (far less than log area height)
	sessHandle.Log("Line 1")
	sessHandle.Log("Line 2")

	// Attempt to scroll up
	tui.scrollCurrentSession(-1)
	if sess.ScrollOffset != 0 || !sess.AutoScroll {
		t.Fatalf("expected ScrollOffset=0 and AutoScroll=true when all lines fit, got offset=%d, autoScroll=%v", sess.ScrollOffset, sess.AutoScroll)
	}

	tui.scrollCurrentSession(-10)
	if sess.ScrollOffset != 0 || !sess.AutoScroll {
		t.Fatalf("expected ScrollOffset=0 after scrolling -10 when all lines fit, got offset=%d", sess.ScrollOffset)
	}

	tui.scrollCurrentSessionToTop()
	if sess.ScrollOffset != 0 || !sess.AutoScroll {
		t.Fatalf("expected ScrollOffset=0 after scrollCurrentSessionToTop when all lines fit, got offset=%d", sess.ScrollOffset)
	}
}


