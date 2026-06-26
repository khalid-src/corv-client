// Package output is the output broker. Raw terminal output is
// hostile to an LLM: progress bars redraw the same line thousands of times
// with carriage returns, colour escapes add tokens with no meaning, and a
// noisy command can bury the one line that matters under megabytes of
// scrollback.
//
// Filter turns that stream into something an agent can actually read:
//
//   - carriage returns and backspaces are resolved so a progress bar
//     collapses to its final frame instead of thousands of lines;
//   - ANSI control sequences (colour, cursor moves) are stripped, while
//     "erase line" is honoured so redraws clean up after themselves;
//   - the result is bounded to a head and a tail with a marker for the
//     lines hidden in between, so the start (what ran) and the end (the
//     result or error) always survive.
//
// Filter is an io.Writer, so it doubles as a memory bound: a runaway
// command cannot blow up the process because only the head and tail are
// retained.
package output

import (
	"fmt"
	"strings"
)

// Defaults for how much output to keep. Tuned for agent context budgets:
// enough head to see what started, enough tail to see how it ended.
const (
	defaultHeadLines    = 40
	defaultTailLines    = 120
	defaultMaxLineBytes = 64 * 1024
	// unboundedMaxLineBytes caps a single line when rendering a complete saved
	// log (Unbounded mode). The input is an already-bounded byte slice read
	// from disk, so there is no streaming-memory risk; this only guards a
	// pathological allocation and sits well above the largest saved log, so a
	// long single-line log is returned in full rather than clipped at 64 KiB.
	unboundedMaxLineBytes = 8 * 1024 * 1024
)

// Options controls how much of the stream is retained.
type Options struct {
	HeadLines    int  // lines kept from the start (default 40)
	TailLines    int  // lines kept from the end (default 120)
	MaxLineBytes int  // cap on a single line's length (default 64 KiB)
	MaxBytes     int  // when >0, Bound keeps whole lines up to this byte budget
	Unbounded    bool // keep every line (de-noise only, no head/tail bounding)
}

func (o Options) withDefaults() Options {
	if o.HeadLines <= 0 {
		o.HeadLines = defaultHeadLines
	}
	if o.TailLines <= 0 {
		o.TailLines = defaultTailLines
	}
	if o.MaxLineBytes <= 0 {
		if o.Unbounded {
			o.MaxLineBytes = unboundedMaxLineBytes
		} else {
			o.MaxLineBytes = defaultMaxLineBytes
		}
	}
	return o
}

// Filter resolves terminal control characters and bounds the result. It is
// not safe for concurrent use; give each stream (stdout, stderr) its own.
type Filter struct {
	opt Options

	// line is the current logical line being assembled; col is the cursor
	// position within it (carriage return moves it back to 0).
	line []byte
	col  int

	// esc accumulates an in-progress ANSI escape sequence.
	inEsc bool
	esc   []byte

	// head keeps the first HeadLines finalized lines; tail is a ring of the
	// most recent TailLines. n is the total number of finalized lines.
	head     []string
	tail     []string
	tailNext int
	tailLen  int
	n        int

	// signals are notable lines (errors/warnings) seen anywhere in the full
	// stream - surfaced even when bounded out, so a warning on a successful
	// command is never hidden. Capped and deduped to stay memory-safe.
	signals     []string
	signalsSeen map[string]bool
}

// maxSignals caps how many highlight lines a single stream retains.
const maxSignals = 8

// New returns a Filter using opt, falling back to defaults for zero fields.
func New(opt Options) *Filter {
	opt = opt.withDefaults()
	f := &Filter{opt: opt}
	if !opt.Unbounded {
		f.head = make([]string, 0, opt.HeadLines)
		f.tail = make([]string, opt.TailLines)
	}
	return f
}

// Write feeds raw bytes into the filter. It never returns an error and
// always reports len(p) consumed, so it is safe as a command's stdout/stderr.
func (f *Filter) Write(p []byte) (int, error) {
	for _, b := range p {
		f.feed(b)
	}
	return len(p), nil
}

func (f *Filter) feed(b byte) {
	if f.inEsc {
		f.feedEsc(b)
		return
	}

	switch b {
	case 0x1b: // ESC: start of an ANSI sequence
		f.inEsc = true
		f.esc = f.esc[:0]
	case '\n':
		f.finishLine()
	case '\r':
		f.col = 0
	case '\b':
		if f.col > 0 {
			f.col--
		}
	case '\t':
		f.put('\t')
	case 0x07: // bell: drop
	default:
		if b < 0x20 {
			// Other C0 control characters carry no text; drop them.
			return
		}
		f.put(b)
	}
}

// feedEsc consumes an ANSI escape sequence. Only CSI sequences are parsed;
// of those only "erase line" (final byte K) has an effect. Everything else
// (colour, cursor movement) is discarded so the captured text stays plain.
func (f *Filter) feedEsc(b byte) {
	if len(f.esc) == 0 {
		// First byte after ESC selects the sequence type.
		if b == '[' {
			f.esc = append(f.esc, b)
			return
		}
		// Non-CSI escape (e.g. ESC followed by a single byte): drop both.
		f.inEsc = false
		return
	}

	// Inside a CSI sequence: parameter/intermediate bytes are 0x20-0x3f,
	// the final byte is 0x40-0x7e.
	if b >= 0x40 && b <= 0x7e {
		f.applyCSI(b)
		f.inEsc = false
		return
	}
	f.esc = append(f.esc, b)
	if len(f.esc) > 32 {
		// Malformed/overlong sequence: abandon it rather than grow forever.
		f.inEsc = false
	}
}

func (f *Filter) applyCSI(final byte) {
	if final != 'K' {
		return // colour, cursor moves, etc. are dropped
	}
	// Erase-in-line. Parameter is between '[' and the final byte.
	param := string(f.esc[1:])
	switch param {
	case "", "0": // cursor to end of line
		if f.col < len(f.line) {
			f.line = f.line[:f.col]
		}
	case "1": // start of line to cursor
		for i := 0; i < f.col && i < len(f.line); i++ {
			f.line[i] = ' '
		}
	case "2": // whole line
		f.line = f.line[:0]
		f.col = 0
	}
}

// put writes a printable byte at the cursor, overwriting or extending the
// current line, and advances the cursor.
func (f *Filter) put(b byte) {
	if f.col < len(f.line) {
		f.line[f.col] = b
	} else {
		if len(f.line) >= f.opt.MaxLineBytes {
			// Line is already at the cap; advance the cursor but stop
			// growing so a newline-free stream cannot exhaust memory.
			f.col++
			return
		}
		f.line = append(f.line, b)
	}
	f.col++
}

// finishLine emits the current logical line and resets the buffer.
func (f *Filter) finishLine() {
	line := strings.TrimRight(string(f.line), " ")
	f.emit(line)
	f.line = f.line[:0]
	f.col = 0
}

func (f *Filter) emit(line string) {
	f.n++
	f.scanSignal(line)
	if f.opt.Unbounded {
		f.head = append(f.head, line)
		return
	}
	if len(f.head) < f.opt.HeadLines {
		f.head = append(f.head, line)
		return
	}
	f.tail[f.tailNext] = line
	f.tailNext = (f.tailNext + 1) % f.opt.TailLines
	if f.tailLen < f.opt.TailLines {
		f.tailLen++
	}
}

// scanSignal records a notable line (error/warning) up to the cap.
func (f *Filter) scanSignal(line string) {
	if len(f.signals) >= maxSignals {
		return
	}
	t := strings.TrimSpace(line)
	if t == "" || !signalRE.MatchString(t) || falsePositiveRE.MatchString(t) {
		return
	}
	if f.signalsSeen == nil {
		f.signalsSeen = map[string]bool{}
	}
	if f.signalsSeen[t] {
		return
	}
	f.signalsSeen[t] = true
	if len(t) > 200 {
		t = t[:200] + "..."
	}
	f.signals = append(f.signals, t)
}

// Signals returns the notable lines (errors/warnings) seen in the stream.
func (f *Filter) Signals() []string {
	f.flushPartial()
	return f.signals
}

// flushPartial finalizes a trailing line that had no closing newline. It is
// idempotent so String may be called more than once.
func (f *Filter) flushPartial() {
	if len(f.line) > 0 {
		f.finishLine()
	}
}

// Hidden reports the number of lines dropped between the head and tail.
func (f *Filter) Hidden() int {
	f.flushPartial()
	hidden := f.n - len(f.head) - f.tailLen
	if hidden < 0 {
		return 0
	}
	return hidden
}

// Lines reports the total number of logical lines seen.
func (f *Filter) Lines() int {
	f.flushPartial()
	return f.n
}

// String returns the cleaned, bounded output. When lines were dropped a
// single marker line records how many, so the omission is always visible.
func (f *Filter) String() string {
	f.flushPartial()

	if f.opt.Unbounded {
		var b strings.Builder
		for _, l := range f.head {
			b.WriteString(l)
			b.WriteByte('\n')
		}
		return b.String()
	}

	hidden := f.n - len(f.head) - f.tailLen
	if hidden < 0 {
		hidden = 0
	}

	var b strings.Builder
	for _, l := range f.head {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	if hidden > 0 {
		fmt.Fprintf(&b, "... %d line(s) hidden ...\n", hidden)
	}
	for i := 0; i < f.tailLen; i++ {
		idx := (f.tailNext - f.tailLen + i + f.opt.TailLines) % f.opt.TailLines
		b.WriteString(f.tail[idx])
		b.WriteByte('\n')
	}
	return b.String()
}
