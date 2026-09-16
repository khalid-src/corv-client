package tui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/khalid-src/corv-client/internal/importstate"
	"github.com/khalid-src/corv-client/internal/profile"
)

type importModel struct {
	input textinput.Model
}

func (im *importModel) setWidth(w int) { im.input.Width = w }

func (m *model) startImport() tea.Cmd {
	ti := textinput.New()
	ti.CharLimit = 512
	ti.Prompt = ""
	ti.SetValue(defaultSSHConfigPath())
	ti.Width = min(60, max(20, m.width-6))
	m.importInput = importModel{input: ti}
	m.screen = screenImport
	m.clearStatus()
	return m.importInput.input.Focus()
}

func (m model) updateImport(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "esc":
		m.screen = screenList
		m.clearStatus()
		return m, nil
	case "enter":
		n, err := m.doImport(strings.TrimSpace(m.importInput.input.Value()))
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.reload()
		m.screen = screenList
		m.message = "imported " + itoa(n) + " connection(s)"
		return m, nil
	}
	var cmd tea.Cmd
	m.importInput.input, cmd = m.importInput.input.Update(msg)
	return m, cmd
}

// doImport reads connections from path, stores any secrets in the vault, and
// merges new profiles into the registry (existing names are left untouched).
func (m model) doImport(path string) (int, error) {
	path = profile.TrimPath(path)
	if path == "" {
		return 0, errStr("enter a file path to import")
	}
	imported, err := profile.Import(path)
	if err != nil {
		return 0, err
	}
	result, err := importstate.Apply(m.store, m.secrets, imported)
	if err != nil {
		return result.Added, err
	}
	return result.Added, nil
}

func (m model) viewImport() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Import Connections") + "\n\n")
	b.WriteString(subtleStyle.Render("Path to an SSH config or a .csv file:") + "\n\n")
	b.WriteString("  " + m.importInput.input.View() + "\n\n")
	b.WriteString(dimStyle.Render("• SSH config: hosts from ~/.ssh/config (and its Includes)") + "\n")
	b.WriteString(dimStyle.Render("• CSV columns: name,host,user,port,identity_file,password,proxy_jump") + "\n")
	b.WriteString(dimStyle.Render("Existing connections are kept; only new ones are added."))

	panel := panelStyle.Render(b.String())
	hints := joinHints(hint("enter", "import"), hint("esc", "cancel"))
	return m.chrome(panel, hints)
}

func defaultSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "config")
}
