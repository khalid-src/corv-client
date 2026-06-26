package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
)

// form field indices.
const (
	fName = iota
	fUser
	fHost
	fPort
	fKey
	fJump
	fPassword
	fPassphrase
	fieldCount
)

var fieldLabels = [fieldCount]string{
	fName:       "Name",
	fUser:       "User",
	fHost:       "Host",
	fPort:       "Port",
	fKey:        "Key file",
	fJump:       "Jump host",
	fPassword:   "Password",
	fPassphrase: "Key passphrase",
}

// fieldPlaceholders hint what each field expects when it is empty. The key
// field in particular wants a path to a private key file.
var fieldPlaceholders = [fieldCount]string{
	fName: "my-server",
	fUser: "login user",
	fHost: "1.2.3.4 or host.example.com",
	fPort: "22",
	fKey:  `path to private key file  (empty = password/agent)`,
	fJump: "user@bastion (optional)",
}

type formModel struct {
	inputs   []textinput.Model
	focus    int
	editName string // empty for a new connection
}

func newForm(p profile.Profile, editName string) formModel {
	inputs := make([]textinput.Model, fieldCount)
	user, host := splitTarget(p.Target)
	values := [fieldCount]string{
		fName: p.Name,
		fUser: user,
		fHost: host,
		fPort: func() string {
			if p.Port != 0 {
				return strconv.Itoa(p.Port)
			}
			return ""
		}(),
		fKey:  p.IdentityFile,
		fJump: p.ProxyJump,
	}
	for i := range inputs {
		ti := textinput.New()
		ti.SetValue(values[i])
		ti.CharLimit = 256
		ti.Prompt = ""
		if i == fPassword || i == fPassphrase {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
			if editName != "" {
				ti.Placeholder = "(leave empty to keep)"
			}
		} else if fieldPlaceholders[i] != "" {
			ti.Placeholder = fieldPlaceholders[i]
		}
		inputs[i] = ti
	}
	return formModel{inputs: inputs, editName: editName}
}

func (f *formModel) setWidth(w int) {
	for i := range f.inputs {
		f.inputs[i].Width = w
	}
}

func (f *formModel) focusField(i int) tea.Cmd {
	for j := range f.inputs {
		f.inputs[j].Blur()
	}
	f.focus = i
	return f.inputs[i].Focus()
}

func (m *model) startAdd() tea.Cmd {
	m.form = newForm(profile.Profile{}, "")
	m.form.setWidth(min(50, max(20, m.width-6)))
	m.screen = screenForm
	m.clearStatus()
	return m.form.focusField(0)
}

func (m *model) startEdit(p profile.Profile) tea.Cmd {
	m.form = newForm(p, p.Name)
	m.form.setWidth(min(50, max(20, m.width-6)))
	m.screen = screenForm
	m.clearStatus()
	return m.form.focusField(0)
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "esc":
		m.screen = screenList
		m.clearStatus()
		return m, nil
	case "tab", "down":
		return m, m.form.focusField((m.form.focus + 1) % fieldCount)
	case "shift+tab", "up":
		return m, m.form.focusField((m.form.focus - 1 + fieldCount) % fieldCount)
	case "enter":
		if err := m.saveForm(); err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.reload()
		m.screen = screenList
		m.message = "saved connection"
		return m, nil
	}

	var cmd tea.Cmd
	m.form.inputs[m.form.focus], cmd = m.form.inputs[m.form.focus].Update(msg)
	return m, cmd
}

func (m model) viewForm() string {
	title := "Add Connection"
	if m.form.editName != "" {
		title = "Edit Connection"
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render(title) + "\n\n")
	for i := range m.form.inputs {
		label := fieldLabels[i]
		ls := labelStyle
		marker := "  "
		if i == m.form.focus {
			ls = focusLabel
			marker = "▸ "
		}
		b.WriteString(marker + ls.Render(pad(label, 16)) + " " + m.form.inputs[i].View() + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("Password is stored encrypted in the local vault."))

	panel := panelStyle.Render(b.String())
	hints := joinHints(
		hint("↑/↓ tab", "move"),
		hint("enter", "save"),
		hint("esc", "cancel"),
	)
	return m.chrome(panel, hints)
}

func (m *model) saveForm() error {
	get := func(i int) string { return strings.TrimSpace(m.form.inputs[i].Value()) }
	name := get(fName)
	user := get(fUser)
	host := get(fHost)
	portText := get(fPort)
	identity := get(fKey)
	jump := get(fJump)
	password := m.form.inputs[fPassword].Value()
	passphrase := m.form.inputs[fPassphrase].Value()

	if name == "" {
		return errStr("name is required")
	}
	if host == "" {
		return errStr("host is required")
	}
	port := 0
	if portText != "" {
		p, err := strconv.Atoi(portText)
		if err != nil || p <= 0 || p > 65535 {
			return errStr("invalid port")
		}
		port = p
	}

	target := host
	if user != "" {
		target = user + "@" + host
	}
	p := profile.Profile{Name: name, Target: target, Port: port, IdentityFile: identity, ProxyJump: jump}
	if err := validateProfile(p); err != nil {
		return err
	}

	reg, err := m.store.Load()
	if err != nil {
		return err
	}

	var existing profile.Profile
	var hadExisting bool
	if m.form.editName != "" {
		existing, hadExisting = reg.Get(m.form.editName)
		if m.form.editName != name { // rename: drop old key + secret
			reg.Remove(m.form.editName)
			if existing.SecretRef != "" {
				_ = m.secrets.Delete(existing.SecretRef)
				existing.SecretRef = ""
			}
		}
	}

	if hadExisting && existing.SecretRef != "" {
		p.SecretRef = existing.SecretRef
	}
	if password != "" || passphrase != "" {
		p.SecretRef = "profile:" + name
		if err := m.secrets.Set(p.SecretRef, vault.Secret{Password: password, Passphrase: passphrase}); err != nil {
			return err
		}
	}
	if err := reg.Set(p); err != nil {
		return err
	}
	return m.store.Save(reg)
}

func validateProfile(p profile.Profile) error {
	reg := profile.Registry{}
	return reg.Set(p)
}

func splitTarget(target string) (user, host string) {
	if at := strings.LastIndex(target, "@"); at > 0 {
		return target[:at], target[at+1:]
	}
	return "", target
}

func pad(s string, w int) string {
	return lipgloss.NewStyle().Width(w).Render(s)
}

type errStr string

func (e errStr) Error() string { return string(e) }
