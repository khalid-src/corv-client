package output

import (
	"fmt"
	"strings"
	"testing"
)

// write is a helper that feeds s through a fresh filter and returns the
// cleaned result.
func clean(opt Options, chunks ...string) string {
	f := New(opt)
	for _, c := range chunks {
		_, _ = f.Write([]byte(c))
	}
	return f.String()
}

func TestPlainPassthrough(t *testing.T) {
	got := clean(Options{}, "hello\nworld\n")
	if got != "hello\nworld\n" {
		t.Fatalf("got %q", got)
	}
}

func TestCarriageReturnCollapsesProgress(t *testing.T) {
	// A download progress bar rewriting one line many times must collapse
	// to its final frame.
	var sb strings.Builder
	for i := 0; i <= 100; i += 10 {
		fmt.Fprintf(&sb, "\rdownloading [%3d%%]", i)
	}
	sb.WriteString("\ndone\n")

	got := clean(Options{}, sb.String())
	if got != "downloading [100%]\ndone\n" {
		t.Fatalf("got %q", got)
	}
}

func TestCarriageReturnPartialOverwrite(t *testing.T) {
	// CR moves the cursor to column 0 without clearing; leftover tail stays.
	got := clean(Options{}, "abcdef\rXYZ\n")
	if got != "XYZdef\n" {
		t.Fatalf("got %q", got)
	}
}

func TestEraseLineClearsLeftover(t *testing.T) {
	// CR followed by erase-to-end is the clean progress-bar idiom.
	got := clean(Options{}, "abcdef\r\x1b[Kxy\n")
	if got != "xy\n" {
		t.Fatalf("got %q", got)
	}
}

func TestEraseWholeLine(t *testing.T) {
	got := clean(Options{}, "noise\x1b[2Kfresh\n")
	if got != "fresh\n" {
		t.Fatalf("got %q", got)
	}
}

func TestStripsColourKeepsText(t *testing.T) {
	got := clean(Options{}, "\x1b[31merror\x1b[0m: boom\n")
	if got != "error: boom\n" {
		t.Fatalf("got %q", got)
	}
}

func TestBackspace(t *testing.T) {
	// Backspace moves the cursor left without deleting; the next byte
	// overwrites, matching real terminal behaviour.
	got := clean(Options{}, "abc\b\bX\n")
	if got != "aXc\n" {
		t.Fatalf("got %q", got)
	}
}

func TestBoundingHidesMiddleKeepsHeadAndTail(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 1000; i++ {
		fmt.Fprintf(&sb, "line%d\n", i)
	}
	got := clean(Options{HeadLines: 2, TailLines: 2}, sb.String())
	want := "line1\nline2\n... 996 line(s) hidden ...\nline999\nline1000\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNoMarkerWhenWithinBudget(t *testing.T) {
	// total lines == head+tail must print everything in order, no marker.
	got := clean(Options{HeadLines: 2, TailLines: 2}, "a\nb\nc\nd\n")
	if got != "a\nb\nc\nd\n" {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(got, "hidden") {
		t.Fatalf("unexpected marker: %q", got)
	}
}

func TestChunkBoundariesDoNotMatter(t *testing.T) {
	// The same bytes split across writes (mid escape, mid line) must yield
	// the same result as one write.
	full := "abcdef\r\x1b[Kxy\nsecond\n"
	one := clean(Options{}, full)
	var many []string
	for i := 0; i < len(full); i++ {
		many = append(many, full[i:i+1])
	}
	split := clean(Options{}, many...)
	if one != split {
		t.Fatalf("byte-split differs: %q vs %q", one, split)
	}
}

func TestTrailingPartialLineFlushed(t *testing.T) {
	got := clean(Options{}, "no newline here")
	if got != "no newline here\n" {
		t.Fatalf("got %q", got)
	}
}

func TestStringIsIdempotent(t *testing.T) {
	f := New(Options{})
	_, _ = f.Write([]byte("partial"))
	first := f.String()
	second := f.String()
	if first != second {
		t.Fatalf("String not idempotent: %q vs %q", first, second)
	}
	if f.Lines() != 1 {
		t.Fatalf("expected 1 line, got %d", f.Lines())
	}
}

func TestLongLineCapped(t *testing.T) {
	f := New(Options{MaxLineBytes: 8})
	_, _ = f.Write([]byte(strings.Repeat("x", 1000)))
	if got := len(strings.TrimRight(f.String(), "\n")); got != 8 {
		t.Fatalf("expected capped line length 8, got %d", got)
	}
}

func TestHiddenAndLinesCounts(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 10; i++ {
		sb.WriteString("x\n")
	}
	f := New(Options{HeadLines: 2, TailLines: 3})
	_, _ = f.Write([]byte(sb.String()))
	if f.Lines() != 10 {
		t.Fatalf("lines = %d", f.Lines())
	}
	if f.Hidden() != 5 {
		t.Fatalf("hidden = %d", f.Hidden())
	}
}
