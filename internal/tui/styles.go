package tui

import "github.com/charmbracelet/lipgloss"

var (
	colAccent   = lipgloss.Color("99")  // violet (Corv brand)
	colOnAccent = lipgloss.Color("231") // near-white
	colSubtle   = lipgloss.Color("245")
	colDim      = lipgloss.Color("240")
	colGood     = lipgloss.Color("42")
	colBad      = lipgloss.Color("203")
	colLegend   = lipgloss.Color("147") // lavender, for box title legends
	colBorder   = lipgloss.Color("60")  // muted slate-violet box borders
)

var (
	appBar = lipgloss.NewStyle().
		Bold(true).
		Foreground(colOnAccent).
		Background(colAccent).
		Padding(0, 1)

	appBarDim = lipgloss.NewStyle().
			Foreground(colOnAccent).
			Background(colAccent)

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(colAccent)

	subtleStyle = lipgloss.NewStyle().Foreground(colSubtle)
	dimStyle    = lipgloss.NewStyle().Foreground(colDim)
	goodStyle   = lipgloss.NewStyle().Foreground(colGood)
	badStyle    = lipgloss.NewStyle().Foreground(colBad)

	labelStyle = lipgloss.NewStyle().Foreground(colSubtle)
	focusLabel = lipgloss.NewStyle().Foreground(colAccent).Bold(true)

	hintKey  = lipgloss.NewStyle().Foreground(colOnAccent).Bold(true)
	hintDesc = lipgloss.NewStyle().Foreground(colSubtle)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colDim).
			Padding(1, 2)

	// home-screen frame styles
	borderStyle = lipgloss.NewStyle().Foreground(colBorder)
	legendStyle = lipgloss.NewStyle().Foreground(colLegend).Bold(true)
	accentBold  = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	kbd         = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	chipKey     = lipgloss.NewStyle().Background(colAccent).Foreground(colOnAccent).Bold(true)
	chipDesc    = lipgloss.NewStyle().Foreground(colSubtle)
)

// chrome wraps a screen body with the title bar and a footer hint line,
// padding to the full terminal height so layout never jumps between screens.
func (m model) chrome(body, hints string) string {
	bar := m.titleBar()
	footer := m.footer(hints)

	status := m.statusLine()
	header := lipgloss.JoinVertical(lipgloss.Left, bar, "")
	bottom := lipgloss.JoinVertical(lipgloss.Left, status, footer)

	if m.height > 0 {
		bodyHeight := m.height - lipgloss.Height(header) - lipgloss.Height(bottom)
		if bodyHeight < 1 {
			bodyHeight = 1
		}
		body = lipgloss.NewStyle().Height(bodyHeight).MaxHeight(bodyHeight).Render(body)
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, body, bottom)
}

func (m model) titleBar() string {
	left := appBar.Render("Corv")
	right := appBarDim.Render(" The SSH client for AI agents and humans ")
	gap := ""
	if m.width > 0 {
		used := lipgloss.Width(left) + lipgloss.Width(right)
		if pad := m.width - used; pad > 0 {
			gap = appBarDim.Render(spaces(pad))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, left, gap, right)
}

func (m model) statusLine() string {
	switch {
	case m.err != "":
		return badStyle.Render("✗ " + m.err)
	case m.notice != "":
		// Connection/return notices in the brand violet so they read as Corv.
		return accentBold.Render("● " + m.notice)
	case m.message != "":
		return goodStyle.Render("✓ " + m.message)
	default:
		return " "
	}
}

func (m model) footer(hints string) string {
	return hintDesc.Render(hints)
}

func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

func hint(key, desc string) string {
	return hintKey.Render(key) + " " + hintDesc.Render(desc)
}
