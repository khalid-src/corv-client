package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanFullNoBounding(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("line\n")
	}
	got := Clean([]byte(sb.String()))
	if n := strings.Count(got, "\n"); n != 1000 {
		t.Fatalf("Clean dropped lines: got %d, want 1000", n)
	}
	if strings.Contains(got, "hidden") {
		t.Fatal("Clean must not bound")
	}
}

// TestCleanLargeSingleLine guards the saved-log retrieval path (corv output):
// a long newline-free log must be returned in full, not clipped at the 64 KiB
// per-line cap used for live streaming.
func TestCleanLargeSingleLine(t *testing.T) {
	const size = 2 * 1024 * 1024
	raw := strings.Repeat("x", size)
	got := strings.TrimRight(Clean([]byte(raw)), "\n")
	if len(got) != size {
		t.Fatalf("Clean clipped single line: got %d bytes, want %d", len(got), size)
	}
}

// TestCleanLargeMultiLine confirms a multi-line log near the saved-log cap
// round-trips through Clean without dropping content.
func TestCleanLargeMultiLine(t *testing.T) {
	var sb strings.Builder
	const lines = 50000
	for i := 0; i < lines; i++ {
		sb.WriteString("the quick brown fox jumps over the lazy dog\n")
	}
	got := Clean([]byte(sb.String()))
	if n := strings.Count(got, "\n"); n != lines {
		t.Fatalf("Clean dropped lines: got %d, want %d", n, lines)
	}
}

func TestBoundUnboundedReturnsEveryLine(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("line\n")
	}
	text := sb.String()
	got := Bound(text, Options{Unbounded: true})
	if got != text {
		t.Fatalf("Unbounded Bound trimmed output: got %d lines, want 1000",
			strings.Count(got, "\n"))
	}
	if strings.Contains(got, "hidden") {
		t.Fatal("Unbounded Bound must not add a marker")
	}
}

func TestBoundBytesReturnsFullWhenWithinBudget(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString("line of output\n")
	}
	text := sb.String()
	got := Bound(text, Options{MaxBytes: 64 * 1024})
	if got != text {
		t.Fatalf("Bound trimmed output within budget: got %d bytes, want %d", len(got), len(text))
	}
	if strings.Contains(got, "hidden") {
		t.Fatal("Bound must not add a marker within budget")
	}
}

func TestBoundBytesTrimsLargeOutputKeepingHeadAndTail(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("HEAD-MARKER\n")
	for i := 0; i < 5000; i++ {
		sb.WriteString("filler line that adds bulk to the output\n")
	}
	sb.WriteString("TAIL-MARKER\n")
	got := Bound(sb.String(), Options{MaxBytes: 4 * 1024})
	if !strings.Contains(got, "HEAD-MARKER") || !strings.Contains(got, "TAIL-MARKER") {
		t.Fatalf("Bound dropped head or tail: %q", got[:min(80, len(got))])
	}
	if !strings.Contains(got, "line(s) hidden") {
		t.Fatal("Bound must mark the omitted middle")
	}
	if len(got) > 6*1024 {
		t.Fatalf("Bound exceeded byte budget by too much: %d bytes", len(got))
	}
}

func TestBoundBytesTrimsUnsplittableLongLine(t *testing.T) {
	// One long line with no newlines (minified JSON, a base64 blob) must still
	// be capped to the budget rather than returned in full. Multibyte runes
	// fill it so the byte cut would land mid-rune if it were not rune-safe.
	text := strings.Repeat("café→", 120*1024)
	got := Bound(text, Options{MaxBytes: 64 * 1024})
	if len(got) > 80*1024 {
		t.Fatalf("Bound did not cap an unsplittable line: %d bytes", len(got))
	}
	if !strings.Contains(got, "output trimmed") {
		t.Fatal("Bound must mark a byte-trimmed line")
	}
	if !utf8.ValidString(got) {
		t.Fatal("Bound produced invalid UTF-8 at the cut")
	}
}

func TestCleanResolvesCarriageReturns(t *testing.T) {
	got := Clean([]byte("abc\rXYZ\n"))
	if got != "XYZ\n" {
		t.Fatalf("got %q", got)
	}
}

func TestBoundMiddleOut(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 100; i++ {
		sb.WriteString("L")
		sb.WriteByte(byte('0' + i%10))
		sb.WriteByte('\n')
	}
	got := Bound(sb.String(), Options{HeadLines: 2, TailLines: 2})
	if !strings.Contains(got, "hidden") {
		t.Fatalf("expected hidden marker: %q", got)
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 5 { // 2 head + marker + 2 tail
		t.Fatalf("expected 5 lines, got %d: %q", len(lines), got)
	}
}

func TestBoundShortPassthrough(t *testing.T) {
	got := Bound("a\nb\nc\n", Options{HeadLines: 40, TailLines: 120})
	if got != "a\nb\nc\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSignalsSurfacesWarningsAndErrors(t *testing.T) {
	text := strings.Join([]string{
		"Starting install",
		"WARN: swap is not disabled",
		"normal progress line",
		"copied 0 errors so far",        // false positive, must be skipped
		"ERROR: failed to pull image x", // counts once
		"ERROR: failed to pull image x", // dup, skip
		"Installation successful",
	}, "\n")
	got := Signals(text, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 signals, got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0], "swap") || !strings.Contains(got[1], "pull image") {
		t.Fatalf("unexpected signals: %#v", got)
	}
}

func TestSignalsCap(t *testing.T) {
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, "error number "+string(rune('a'+i%26))+string(rune('0'+i%10)))
	}
	if got := Signals(strings.Join(lines, "\n"), 5); len(got) != 5 {
		t.Fatalf("expected cap 5, got %d", len(got))
	}
}
