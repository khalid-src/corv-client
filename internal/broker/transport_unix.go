//go:build !windows

package broker

import (
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/khalid-src/corv-client/internal/paths"
)

func listenBroker() (net.Listener, string, error) {
	p, err := paths.Default()
	if err != nil {
		return nil, "", err
	}
	runDir := filepath.Join(p.Root, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, "", err
	}
	addr := filepath.Join(runDir, "broker.sock")
	_ = os.Remove(addr)
	ln, err := net.Listen("unix", addr)
	if err != nil {
		return nil, "", err
	}
	return ln, addr, nil
}

func dialBroker(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}

func cleanupBroker(addr string) {
	if addr != "" {
		_ = os.Remove(addr)
	}
}
