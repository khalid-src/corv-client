package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFailureKeepsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	old := []byte("previous state")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("replace failed")
	err := write(path, []byte("new state"), 0o600, func(string, string) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(old) {
		t.Fatalf("file = %q, want %q", got, old)
	}
}
