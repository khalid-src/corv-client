package output

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Clean de-noises raw terminal bytes - resolving carriage returns and
// backspaces and stripping ANSI - and returns the full result without
// bounding. Used to render a stored run log faithfully.
func Clean(raw []byte) string {
	f := New(Options{Unbounded: true})
	_, _ = f.Write(raw)
	return f.String()
}

// Bound trims already-clean text to a head and a tail with a marker for the
// omitted middle (the "middle-out" view). When MaxBytes is set it bounds by a
// byte budget, keeping whole lines, so output that fits is returned in full and
// only genuinely large output is trimmed; otherwise it bounds by the head and
// tail line counts. Zero-value options use defaults.
func Bound(text string, opt Options) string {
	if opt.Unbounded {
		return text
	}
	o := opt.withDefaults()
	trimmed := strings.TrimRight(text, "\n")
	if trimmed == "" {
		return ""
	}
	if o.MaxBytes > 0 {
		return boundBytes(text, trimmed, o.MaxBytes)
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) <= o.HeadLines+o.TailLines {
		return text
	}
	hidden := len(lines) - o.HeadLines - o.TailLines
	var b strings.Builder
	for _, l := range lines[:o.HeadLines] {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "... %d line(s) hidden (full output: see run log) ...\n", hidden)
	for _, l := range lines[len(lines)-o.TailLines:] {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// boundBytes returns full when it fits in max bytes; otherwise it keeps whole
// lines from the head and the tail up to roughly half the budget each, with a
// marker for the omitted middle.
func boundBytes(full, trimmed string, max int) string {
	if len(trimmed) <= max {
		return full
	}
	lines := strings.Split(trimmed, "\n")
	half := max / 2

	headEnd, used := 0, 0
	for headEnd < len(lines) {
		cost := len(lines[headEnd]) + 1
		if used+cost > half && headEnd > 0 {
			break
		}
		used += cost
		headEnd++
	}

	tailStart, used := len(lines), 0
	for tailStart-1 >= headEnd {
		cost := len(lines[tailStart-1]) + 1
		if used+cost > half && tailStart < len(lines) {
			break
		}
		used += cost
		tailStart--
	}

	if hidden := tailStart - headEnd; hidden > 0 {
		var b strings.Builder
		for _, l := range lines[:headEnd] {
			b.WriteString(l)
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "... %d line(s) hidden (full output: see run log) ...\n", hidden)
		for _, l := range lines[tailStart:] {
			b.WriteString(l)
			b.WriteByte('\n')
		}
		return b.String()
	}

	// Too few line breaks to trim on boundaries (e.g. one long minified line):
	// cut on rune boundaries so the budget is still respected.
	return cutHead(trimmed, half) + "\n... output trimmed (full output: see run log) ...\n" + cutTail(trimmed, half)
}

// cutHead returns s truncated to at most n bytes, ending on a rune boundary.
func cutHead(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cutTail returns the last up-to-n bytes of s, starting on a rune boundary.
func cutTail(s string, n int) string {
	if n >= len(s) {
		return s
	}
	start := len(s) - n
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[start:]
}

// signalRE matches lines that likely carry something the agent should see -
// errors, warnings, failures - even when the command exited zero.
var signalRE = regexp.MustCompile(`(?i)\b(error|err|warn|warning|fatal|fail|failed|failure|exception|traceback|panic|denied|refused|unreachable|timed out|timeout|unable|cannot|can't|deprecat|critical|conflict)\b`)

// falsePositiveRE drops reassuring lines like "0 errors" or "no warnings".
var falsePositiveRE = regexp.MustCompile(`(?i)\b(no|0|zero|without|none)\b[^.]{0,20}\b(error|warning|failure|issue|conflict)s?\b`)

// Signals extracts notable lines (errors, warnings, failures) from clean
// text, deduped and capped at max. These are surfaced regardless of exit
// code so a warning on a successful command is never hidden.
func Signals(text string, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || !signalRE.MatchString(t) || falsePositiveRE.MatchString(t) {
			continue
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		if len(t) > 200 {
			t = t[:200] + "..."
		}
		out = append(out, t)
		if len(out) >= max {
			break
		}
	}
	return out
}
