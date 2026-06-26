package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/khalid-src/corv-client/internal/profile"
)

// TestViewNeverExceedsTerminalWidth guards the home screen against lines wider
// than the terminal, which wrap and make the layout look broken. It renders at a
// range of sizes, with and without saved connections.
func TestViewNeverExceedsTerminalWidth(t *testing.T) {
	profiles := []profile.Profile{
		{Name: "web-01", Target: "ubuntu@10.0.0.4", Port: 22},
		{Name: "db", Target: "ubuntu@10.0.0.9", Port: 2222, ProxyJump: "ops@bastion"},
		{Name: "edge", Target: "admin@host.example.com", IdentityFile: "k"},
	}
	sizes := []struct{ w, h int }{
		{16, 8}, {20, 10}, {24, 8}, {40, 12}, {60, 20}, {80, 24}, {100, 30}, {120, 40}, {200, 50},
	}
	for _, empty := range []bool{false, true} {
		for _, s := range sizes {
			m := model{screen: screenList}
			if !empty {
				m.profiles = profiles
			}
			m.table = newConnectionTable()
			m.width, m.height = s.w, s.h
			m.layout()

			view := m.View()
			for n, line := range strings.Split(view, "\n") {
				if got := lipgloss.Width(line); got > s.w {
					t.Errorf("empty=%v size=%dx%d: line %d width %d > terminal %d\n%q",
						empty, s.w, s.h, n, got, s.w, line)
				}
			}
		}
	}
}

// TestFooterKeepsAllControlsWhenNarrow ensures the footer wraps rather than
// dropping controls: every key hint stays visible even on a narrow terminal.
func TestFooterKeepsAllControlsWhenNarrow(t *testing.T) {
	wants := []string{"Navigate", "Connect", "Add", "Edit", "Delete", "Import", "Logs", "Info", "Quit"}
	for _, w := range []int{24, 30, 40, 60, 100} {
		m := model{screen: screenList}
		m.table = newConnectionTable()
		m.width, m.height = w, 24
		m.layout()
		footer := m.chipsFooter(w)
		for _, label := range wants {
			if !strings.Contains(footer, label) {
				t.Errorf("width %d: footer dropped %q\n%s", w, label, footer)
			}
		}
		for n, line := range strings.Split(footer, "\n") {
			if got := lipgloss.Width(line); got > w {
				t.Errorf("width %d: footer line %d width %d > %d", w, n, got, w)
			}
		}
	}
}

// TestFrameBordersAlign checks the home panel's bordered box has a matching left
// and right edge on every row (a misaligned right border is the classic symptom
// of byte-vs-display-width math).
func TestFrameBordersAlign(t *testing.T) {
	m := model{
		screen:   screenList,
		profiles: []profile.Profile{{Name: "srv", Target: "ubuntu@10.0.0.4"}},
	}
	m.table = newConnectionTable()
	m.width, m.height = 90, 28
	m.layout()

	box := m.frame(m.width, m.height-2)
	for n, line := range strings.Split(box, "\n") {
		if w := lipgloss.Width(line); w != m.width {
			t.Fatalf("frame row %d width %d, want %d: %q", n, w, m.width, line)
		}
	}
}
