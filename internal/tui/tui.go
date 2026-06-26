// Package tui is the interactive UI for Corv. It lists
// connections, adds/edits/imports them, shows the audit log, and returns the
// chosen connection name to the caller. It never opens SSH sessions itself.
package tui

import (
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/vault"
	"github.com/khalid-src/corv-client/internal/version"
)

type screen int

const (
	screenList screen = iota
	screenForm
	screenDelete
	screenImport
	screenLogs
	screenInfo
)

// raven is the home-screen mascot glyph: a raven head facing left.
var raven = []string{
	"  ╭───╮",
	" <  • │",
	"      │",
	"  ╰───╯",
}

// Run launches the interactive UI and blocks until the user quits or
// chooses a connection. Returns the chosen connection name (empty if the user
// quit without selecting).
func Run(store *profile.Store, secrets *vault.Store, log *audit.Log, stdin io.Reader, stdout io.Writer, notice string) (string, error) {
	m, err := newModel(store, secrets, log)
	if err != nil {
		return "", err
	}
	m.notice = notice
	// Seed the real terminal size up front. Bubble Tea normally delivers it via
	// WindowSizeMsg, but over some terminals and SSH PTYs that first message is
	// delayed or never arrives, leaving the model at its 80x24 fallback and the
	// UI stuck in a small box. Querying the size directly makes the first paint
	// fill the screen; WindowSizeMsg still keeps it current on resize.
	if w, h := terminalSize(stdout); w > 0 {
		m.width, m.height = w, h
		m.layout()
	}
	prog := tea.NewProgram(m,
		tea.WithInput(stdin),
		tea.WithOutput(stdout),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	final, err := prog.Run()
	if err != nil {
		return "", err
	}
	if fm, ok := final.(model); ok {
		return fm.connectName, nil
	}
	return "", nil
}

// terminalSize reports the current terminal size from the output stream (or the
// process's stdout as a fallback), or 0,0 when it cannot be determined.
func terminalSize(out io.Writer) (int, int) {
	if f, ok := out.(*os.File); ok {
		if w, h, err := term.GetSize(int(f.Fd())); err == nil && w > 0 {
			return w, h
		}
	}
	if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w, h
	}
	return 0, 0
}

type model struct {
	store   *profile.Store
	secrets *vault.Store
	log     *audit.Log

	width, height int
	listWidth     int
	screen        screen

	profiles []profile.Profile
	table    table.Model

	form        formModel
	importInput importModel
	logs        logsModel
	deleteName  string

	message string
	err     string
	notice  string

	connectName string
}

func newModel(store *profile.Store, secrets *vault.Store, log *audit.Log) (model, error) {
	reg, err := store.Load()
	if err != nil {
		return model{}, err
	}
	m := model{
		store:    store,
		secrets:  secrets,
		log:      log,
		profiles: reg.List(),
	}
	m.table = newConnectionTable()
	m.rebuildTable()
	return m, nil
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	switch m.screen {
	case screenList:
		return m.updateList(msg)
	case screenForm:
		return m.updateForm(msg)
	case screenDelete:
		return m.updateDelete(msg)
	case screenImport:
		return m.updateImport(msg)
	case screenLogs:
		return m.updateLogs(msg)
	case screenInfo:
		return m.updateInfo(msg)
	}
	return m, nil
}

// minTermWidth/minTermHeight are the smallest size the UI renders at; below
// this it shows a compact notice rather than a broken, overflowing layout.
const (
	minTermWidth  = 24
	minTermHeight = 8
)

func (m model) View() string {
	if m.width > 0 && m.height > 0 && (m.width < minTermWidth || m.height < minTermHeight) {
		return lipgloss.NewStyle().
			Width(m.width).Height(m.height).MaxWidth(m.width).MaxHeight(m.height).
			Align(lipgloss.Center, lipgloss.Center).
			Render(subtleStyle.Render("terminal too small"))
	}
	switch m.screen {
	case screenForm:
		return m.viewForm()
	case screenDelete:
		return m.viewDelete()
	case screenImport:
		return m.viewImport()
	case screenLogs:
		return m.viewLogs()
	case screenInfo:
		return m.viewInfo()
	default:
		return m.viewList()
	}
}

// layout sizes per-screen widgets to the current terminal dimensions.
func (m *model) layout() {
	bodyH := m.bodyHeight()
	// The home screen is a single frame: the table sits inside the frame
	// border (2 cols) and is centered, with slack for margins. The bubbles
	// table's header rule renders ~4 cols wider than its body.
	m.listWidth = max(20, m.width-9)
	m.table.SetWidth(m.listWidth)
	m.rebuildTable() // also sizes the table height to its content

	m.logs.setSize(m.width, bodyH)
	m.importInput.setWidth(min(60, max(20, m.width-6)))
	m.form.setWidth(min(50, max(20, m.width-6)))
}

// bodyHeight is the usable height between the title bar and the footer.
func (m model) bodyHeight() int {
	if m.height <= 0 {
		return 20
	}
	// title bar (1) + spacer (1) + status (1) + footer (1)
	h := m.height - 4
	if h < 3 {
		h = 3
	}
	return h
}

// ---- list screen -------------------------------------------------------

func newConnectionTable() table.Model {
	t := table.New(table.WithFocused(true))
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colDim).
		BorderBottom(true).
		Bold(true).
		Foreground(colSubtle)
	s.Selected = s.Selected.
		Foreground(colOnAccent).
		Background(colAccent).
		Bold(true)
	t.SetStyles(s)
	return t
}

// rebuildTable refreshes columns and rows from the current profile list,
// preserving the cursor position.
func (m *model) rebuildTable() {
	w := m.listWidth
	if w <= 0 {
		w = 78
	}
	nameW, portW, authW, jumpW := 18, 6, 9, 16
	addrW := w - nameW - portW - authW - jumpW - 6
	if addrW < 14 {
		addrW = 14
	}
	m.table.SetColumns([]table.Column{
		{Title: "NAME", Width: nameW},
		{Title: "ADDRESS", Width: addrW},
		{Title: "PORT", Width: portW},
		{Title: "AUTH", Width: authW},
		{Title: "JUMP", Width: jumpW},
	})

	rows := make([]table.Row, 0, len(m.profiles))
	for _, p := range m.profiles {
		port := "22"
		if p.Port != 0 {
			port = itoa(p.Port)
		}
		jump := p.ProxyJump
		if jump == "" {
			jump = "-"
		}
		rows = append(rows, table.Row{p.Name, p.Target, port, authLabel(p), jump})
	}
	m.table.SetRows(rows)

	// Size the table to its content so the centered frame doesn't pad it out
	// with a tail of empty rows; cap it at the space the frame can show. The
	// view height counts the header and its rule, so add 2 for them.
	avail := m.bodyHeight() - headerRows
	if avail < 3 {
		avail = 3
	}
	m.table.SetHeight(min(avail, len(rows)+2))

	// Keep the cursor in range. Note an empty list leaves the cursor at -1, so
	// the first added row would not render until a key press unless we reset it.
	if len(rows) > 0 {
		cur := m.table.Cursor()
		if cur < 0 {
			cur = 0
		} else if cur >= len(rows) {
			cur = len(rows) - 1
		}
		m.table.SetCursor(cur)
	}
}

func (m model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}

	switch strings.ToLower(key.String()) {
	case "q", "esc":
		return m, tea.Quit
	case "enter", "c":
		if p, ok := m.selected(); ok {
			m.connectName = p.Name
			return m, tea.Quit
		}
	case "a":
		return m, m.startAdd()
	case "e":
		if p, ok := m.selected(); ok {
			return m, m.startEdit(p)
		}
	case "d":
		if p, ok := m.selected(); ok {
			m.deleteName = p.Name
			m.screen = screenDelete
			m.clearStatus()
		}
	case "i":
		return m, m.startImport()
	case "l":
		return m, m.startLogs("")
	case "?":
		m.screen = screenInfo
		m.clearStatus()
	case "r":
		m.reload()
		m.message = "refreshed"
	default:
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}
	return m, nil
}

// headerRows is the number of rows the home-screen header occupies above the
// table. Keep this in sync with homeHeader plus the spacer added in frame.
const headerRows = 7

func (m model) viewList() string {
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}

	footer := m.chipsFooter(w)
	// A status row (connect failures, errors) above the footer - the home screen
	// previously omitted it, so failures returned here silently. Rendered as the
	// plain status string (no width wrapper, which would overflow the terminal).
	status := m.statusLine()
	contentH := h - lipgloss.Height(footer) - lipgloss.Height(status)
	if contentH < headerRows+3 {
		contentH = headerRows + 3
	}
	return lipgloss.JoinVertical(lipgloss.Left, m.frame(w, contentH), status, footer)
}

// frame is the single home-screen panel: the raven/wordmark header above the
// connection table (or an empty-state invitation), centered in both axes so
// the content sits in the middle of the terminal rather than the top corner.
func (m model) frame(w, h int) string {
	inW := w - 2
	rows := h - 2
	top := boxTop(w, "[ Corv ]", "[ "+itoa(len(m.profiles))+" saved ]")

	header := homeHeader()

	// Body: the connection list, or an empty-state hint.
	var body []string
	if len(m.profiles) == 0 {
		body = []string{
			subtleStyle.Render("No connections yet."),
			dimStyle.Render("Press ") + kbd.Render("[a]") +
				dimStyle.Render(" to add a new profile or ") +
				kbd.Render("[i]") + dimStyle.Render(" to import."),
		}
	} else {
		body = strings.Split(m.table.View(), "\n")
	}

	// Each block is centered horizontally as a unit (one shared left pad keeps
	// the table columns aligned); the whole stack is then centered vertically.
	content := centerBlock(inW, header)
	content = append(content, padLine(inW, ""))
	content = append(content, centerBlock(inW, body)...)

	inner := blankLines(rows, inW)
	offset := (rows - len(content)) / 2
	if offset < 0 {
		offset = 0
	}
	for i, line := range content {
		put(inner, rows, offset+i, line)
	}
	return assemble(top, inner, w)
}

func homeHeader() []string {
	gap := "    "
	return []string{
		"",
		accentBold.Render(raven[0]),
		accentBold.Render(raven[1]) + gap + accentBold.Render("CORV"),
		accentBold.Render(raven[2]) + gap + subtleStyle.Render("The SSH client for AI agents and humans"),
		accentBold.Render(raven[3]),
		"",
	}
}

// centerBlock left-pads every line by the same amount so the block is centered
// horizontally within w while internal alignment (e.g. table columns) is kept.
func centerBlock(w int, lines []string) []string {
	bw := 0
	for _, l := range lines {
		if x := lipgloss.Width(l); x > bw {
			bw = x
		}
	}
	prefix := strings.Repeat(" ", max(0, (w-bw)/2))
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = padLine(w, prefix+l)
	}
	return out
}

// chipsFooter is the bottom key-hint strip. Chips wrap onto as many lines as the
// width needs so every control stays visible at any terminal size, rather than
// being dropped when space runs short.
func (m model) chipsFooter(w int) string {
	avail := max(1, w-2) // the outer style pads one column each side
	lines := wrapItems(footerChipList(), avail)

	ver := dimStyle.Render(version.Version)
	verW := lipgloss.Width(ver)
	if n := len(lines); n > 0 && lipgloss.Width(lines[n-1])+1+verW <= avail {
		// Right-align the version on the last chip line when it fits.
		pad := avail - lipgloss.Width(lines[n-1]) - verW
		lines[n-1] += strings.Repeat(" ", pad) + ver
	} else if verW <= avail {
		lines = append(lines, lipgloss.NewStyle().Width(avail).Align(lipgloss.Right).Render(ver))
	}

	return lipgloss.NewStyle().Width(w).MaxWidth(w).Padding(0, 1).Render(strings.Join(lines, "\n"))
}

// wrapItems greedily packs space-separated items into lines no wider than avail,
// so the full set is always shown even on a narrow terminal.
func wrapItems(items []string, avail int) []string {
	var lines []string
	cur := ""
	for _, it := range items {
		switch {
		case cur == "":
			cur = it
		case lipgloss.Width(cur)+1+lipgloss.Width(it) <= avail:
			cur += " " + it
		default:
			lines = append(lines, cur)
			cur = it
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func footerChipList() []string {
	return []string{
		chip("↑↓", "Navigate"),
		chip("ENTER", "Connect"),
		chip("a", "Add"),
		chip("e", "Edit"),
		chip("d", "Delete"),
		chip("i", "Import"),
		chip("l", "Logs"),
		chip("?", "Info"),
		chip("q", "Quit"),
	}
}

// ---- box-drawing helpers (manual legend borders) -----------------------

// boxTop composes a rounded top border with one or more bracketed legend
// segments embedded in it: ╭─[ A ]──[ B ]────...────╮ (lipgloss has no native
// border legend, so the line is assembled by hand).
func boxTop(w int, segs ...string) string {
	inW := w - 2
	used := 1 // the single dash after the corner
	legend := ""
	for i, s := range segs {
		if i > 0 {
			legend += bs("──")
			used += 2
		}
		legend += legendStyle.Render(s)
		used += lipgloss.Width(s)
	}
	fill := inW - used
	if fill < 0 {
		fill = 0
	}
	return bs("╭") + bs("─") + legend + bs(strings.Repeat("─", fill)) + bs("╮")
}

func boxBottom(w int) string {
	return bs("╰") + bs(strings.Repeat("─", w-2)) + bs("╯")
}

// assemble wraps inner lines (each already exactly w-2 wide) with side borders
// and joins them between the prebuilt top and bottom borders.
func assemble(top string, inner []string, w int) string {
	var b strings.Builder
	b.WriteString(top + "\n")
	for _, line := range inner {
		b.WriteString(bs("│") + line + bs("│") + "\n")
	}
	b.WriteString(boxBottom(w))
	return b.String()
}

func chip(key, label string) string {
	return chipKey.Render("["+key+"]") + " " + chipDesc.Render(label)
}

// blankLines returns n empty lines, each padded to width w.
func blankLines(n, w int) []string {
	out := make([]string, n)
	empty := padLine(w, "")
	for i := range out {
		out[i] = empty
	}
	return out
}

// put writes line at index i when it falls within the frame's inner rows.
func put(inner []string, rows, i int, line string) {
	if i >= 0 && i < rows {
		inner[i] = line
	}
}

func (m model) updateInfo(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch strings.ToLower(key.String()) {
		case "esc", "q", "?":
			m.screen = screenList
		}
	}
	return m, nil
}

func (m model) viewInfo() string {
	disclaimer := "Software is provided as-is. Use responsibly."
	w := min(84, max(40, m.width-10))
	body := titleStyle.Render("Corv") + "\n\n" +
		subtleStyle.Render("The SSH client for AI agents and humans") + "\n\n" +
		"Version: " + focusLabel.Render(version.Version) + "\n" +
		"License: " + focusLabel.Render("Apache-2.0") + "\n\n" +
		dimStyle.Render("Stored credentials stay local. Audit and run logs may contain command text or remote output.") + "\n" +
		"\n" + focusLabel.Render("Disclaimer") + "\n" +
		subtleStyle.Width(w).Render(disclaimer)
	panel := panelStyle.Render(body)
	hints := joinHints(hint("esc", "back"), hint("q", "quit"))
	return m.chrome(panel, hints)
}

func padLine(w int, s string) string {
	return lipgloss.NewStyle().Width(w).MaxWidth(w).Inline(true).Render(s)
}

func bs(s string) string { return borderStyle.Render(s) }

func (m model) selected() (profile.Profile, bool) {
	i := m.table.Cursor()
	if i < 0 || i >= len(m.profiles) {
		return profile.Profile{}, false
	}
	return m.profiles[i], true
}

// ---- shared helpers ----------------------------------------------------

func (m *model) reload() {
	reg, err := m.store.Load()
	if err != nil {
		m.err = err.Error()
		return
	}
	m.profiles = reg.List()
	m.rebuildTable()
}

func (m *model) clearStatus() {
	m.message = ""
	m.err = ""
	m.notice = ""
}

func (m model) deleteSelected(name string) (model, error) {
	reg, err := m.store.Load()
	if err != nil {
		return m, err
	}
	p, _ := reg.Get(name)
	reg.Remove(name)
	if err := m.store.Save(reg); err != nil {
		return m, err
	}
	if p.SecretRef != "" {
		_ = m.secrets.Delete(p.SecretRef)
	}
	m.reload()
	return m, nil
}

// authLabel summarises how a profile authenticates without revealing secrets.
func authLabel(p profile.Profile) string {
	switch {
	case p.IdentityFile != "":
		return "key"
	case p.SecretRef != "":
		return "password"
	default:
		return "agent"
	}
}

func joinHints(hints ...string) string {
	out := ""
	sep := dimStyle.Render("  •  ")
	for i, h := range hints {
		if i > 0 {
			out += sep
		}
		out += h
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
