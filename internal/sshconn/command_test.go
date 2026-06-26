package sshconn

import "testing"

func TestCommandStringPreservesArgumentBoundaries(t *testing.T) {
	got := CommandString([]string{"sh", "-lc", "cd /app && npm test"})
	want := "sh -lc 'cd /app && npm test'"
	if got != want {
		t.Fatalf("CommandString() = %q, want %q", got, want)
	}
}

func TestCommandStringQuotesSingleQuotes(t *testing.T) {
	got := CommandString([]string{"printf", "it's ready"})
	want := `printf 'it'"'"'s ready'`
	if got != want {
		t.Fatalf("CommandString() = %q, want %q", got, want)
	}
}

func TestCommandStringSingleArgIsVerbatim(t *testing.T) {
	// A single argument is a remote shell command line, passed through as-is
	// so `corv host -- "cd /app && make"` is evaluated by the remote shell.
	got := CommandString([]string{"cd /app && make"})
	want := "cd /app && make"
	if got != want {
		t.Fatalf("CommandString() = %q, want %q", got, want)
	}
}

func TestCommandStringEmptyArgQuoted(t *testing.T) {
	got := CommandString([]string{"printf", "%s", ""})
	want := "printf %s ''"
	if got != want {
		t.Fatalf("CommandString() = %q, want %q", got, want)
	}
}
