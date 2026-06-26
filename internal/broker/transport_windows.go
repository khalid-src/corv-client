//go:build windows

package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/khalid-src/corv-client/internal/paths"
)

const brokerPipeSDDL = "D:P(A;;GA;;;OW)"

func listenBroker() (net.Listener, string, error) {
	p, err := paths.Default()
	if err != nil {
		return nil, "", err
	}
	addr := brokerPipeName(p.Root)
	ln, err := winio.ListenPipe(addr, &winio.PipeConfig{
		SecurityDescriptor: brokerPipeSDDL,
	})
	if err != nil {
		return nil, "", err
	}
	return ln, addr, nil
}

func dialBroker(addr string, timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(addr, &timeout)
}

func cleanupBroker(string) {}

func brokerPipeName(root string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(root)))
	return `\\.\pipe\corv-broker-` + hex.EncodeToString(sum[:])[:16]
}
