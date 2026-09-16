package vault

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestRunKeyCommandHasDeadline(t *testing.T) {
	if os.Getenv("CORV_KEY_COMMAND_HELPER") == "1" {
		time.Sleep(10 * time.Second)
		return
	}
	t.Setenv("CORV_KEY_COMMAND_HELPER", "1")
	oldTimeout := keyCommandTimeout
	keyCommandTimeout = 50 * time.Millisecond
	t.Cleanup(func() { keyCommandTimeout = oldTimeout })

	started := time.Now()
	_, err := runKeyCommand(os.Args[0], "-test.run=^TestRunKeyCommandHasDeadline$")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("key command returned after %v", elapsed)
	}
}
