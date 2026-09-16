package vault

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

var keyCommandTimeout = 10 * time.Second

func runKeyCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keyCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("keychain command timed out: %w", ctx.Err())
	}
	return out, err
}
