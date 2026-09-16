//go:build windows

package vault

import (
	"errors"
	"strings"
	"testing"
)

func TestDPAPIUnprotectFailureExplainsProcessContext(t *testing.T) {
	_, err := unprotect([]byte("not a DPAPI blob"))
	if !errors.Is(err, ErrKeyAccess) {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "same Windows user and profile") {
		t.Fatalf("error lacks recovery guidance: %v", err)
	}
}
