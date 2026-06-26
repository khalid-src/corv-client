package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

func (m model) updateDelete(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "y", "Y", "enter":
		name := m.deleteName
		updated, err := m.deleteSelected(name)
		if err != nil {
			m.err = err.Error()
			m.screen = screenList
			return m, nil
		}
		m = updated
		m.message = "removed " + name
		m.screen = screenList
		return m, nil
	case "n", "N", "esc":
		m.screen = screenList
		return m, nil
	}
	return m, nil
}

func (m model) viewDelete() string {
	body := titleStyle.Render("Delete connection") + "\n\n" +
		"  Remove " + focusLabel.Render(m.deleteName) + " and its stored secret?\n\n" +
		dimStyle.Render("  This cannot be undone.")
	panel := panelStyle.Render(body)
	hints := joinHints(hint("y", "delete"), hint("n/esc", "cancel"))
	return m.chrome(panel, hints)
}
