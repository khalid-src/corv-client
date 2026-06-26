package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/khalid-src/corv-client/internal/audit"
)

type logsModel struct {
	vp      viewport.Model
	ready   bool
	servers []string // selectable filters; "" means all servers
	idx     int      // index into servers
}

func (l *logsModel) setSize(w, h int) {
	if w <= 0 || h <= 0 {
		return
	}
	if !l.ready {
		l.vp = viewport.New(w, max(3, h-1))
		l.ready = true
	} else {
		l.vp.Width = w
		l.vp.Height = max(3, h-1)
	}
}

// startLogs opens the audit view filtered to a server. It builds the server
// selector from the current connections plus an "all servers" entry, and
// starts on the requested server (or "all" when name is empty).
func (m *model) startLogs(name string) tea.Cmd {
	servers := []string{""} // "" = all servers
	for _, p := range m.profiles {
		servers = append(servers, p.Name)
	}
	m.logs.servers = servers
	m.logs.idx = 0
	for i, s := range servers {
		if s == name {
			m.logs.idx = i
			break
		}
	}

	m.logs.setSize(m.width, m.bodyHeight())
	m.refreshLogs()
	m.screen = screenLogs
	m.clearStatus()
	return nil
}

// refreshLogs re-renders the viewport for the currently selected server.
func (m *model) refreshLogs() {
	filter := m.logs.servers[m.logs.idx]
	m.logs.vp.SetContent(m.renderLog(filter))
	m.logs.vp.GotoTop()
}

func (m model) updateLogs(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch strings.ToLower(key.String()) {
		case "esc", "q", "l":
			m.screen = screenList
			return m, nil
		case "left", "shift+tab", "h":
			m.logs.idx = (m.logs.idx - 1 + len(m.logs.servers)) % len(m.logs.servers)
			m.refreshLogs()
			return m, nil
		case "right", "tab":
			m.logs.idx = (m.logs.idx + 1) % len(m.logs.servers)
			m.refreshLogs()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.logs.vp, cmd = m.logs.vp.Update(msg)
	return m, cmd
}

func (m model) viewLogs() string {
	scope := "all servers"
	if s := m.logs.servers[m.logs.idx]; s != "" {
		scope = s
	}
	title := titleStyle.Render("Audit Log") +
		subtleStyle.Render("  ◂ ") + focusLabel.Render(scope) + subtleStyle.Render(" ▸")
	note := dimStyle.Render("Command history covers Corv-run commands. Interactive shells are logged as sessions.")
	body := title + "\n" + note + "\n\n" + m.logs.vp.View()
	hints := joinHints(
		hint("←/→", "switch server"),
		hint("↑/↓ pgup/pgdn", "scroll"),
		hint("esc", "back"),
	)
	return m.chrome(body, hints)
}

// renderLog formats recent audit entries for one server (or all) into an
// aligned, newest-first listing.
func (m model) renderLog(filter string) string {
	if m.log == nil {
		return dimStyle.Render("  no audit log configured")
	}
	entries, err := m.log.Read(filter, 500)
	if err != nil {
		return badStyle.Render("  " + err.Error())
	}
	if len(entries) == 0 {
		if filter == "" {
			return dimStyle.Render("  no Corv-run commands recorded yet\n\n") +
				dimStyle.Render("  Commands run as `corv <name> -- <cmd>` appear here. Interactive shells appear after they exit.")
		}
		return dimStyle.Render("  no Corv-run commands recorded for "+filter+"\n\n") +
			dimStyle.Render("  Use ←/→ to switch to all servers. Interactive shell commands typed inside SSH are not inspected.")
	}

	tsStyle := lipgloss.NewStyle().Foreground(colSubtle)
	showServer := filter == "" // only show the server column in the merged view

	var b strings.Builder
	for i := len(entries) - 1; i >= 0; i-- { // newest first
		e := entries[i]
		ts := e.StartedAt.Local().Format("2006-01-02 15:04:05")
		code := auditStatus(e.ExitCode, e.Error)
		dur := ""
		if e.DurationMS > 0 {
			dur = dimStyle.Render(" " + formatDuration(e.DurationMS))
		}
		head := tsStyle.Render(ts) + "  "
		if showServer {
			head += titleStyle.Render(pad(e.Profile, 16)) + " "
		}
		head += code + dur
		b.WriteString(head + "\n")
		b.WriteString(dimStyle.Render("    $ ") + audit.OneLine(e.Command) + "\n\n")
	}
	return b.String()
}

func auditStatus(exitCode int, err string) string {
	if exitCode == 75 {
		return subtleStyle.Render("running")
	}
	if exitCode != 0 || err != "" {
		return badStyle.Render("exit " + itoa(exitCode))
	}
	return goodStyle.Render("ok")
}

func formatDuration(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d < time.Second {
		return itoa(int(ms)) + "ms"
	}
	return d.Round(time.Millisecond).String()
}
