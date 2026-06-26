package broker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/khalid-src/corv-client/internal/paths"
)

// endpoint records how to reach a running broker. Stored in a 0600 file under
// the Corv root; the token gates access so another local user cannot drive
// the broker over its per-user socket (Unix) or named pipe (Windows).
type endpoint struct {
	Addr       string `json:"addr"`
	Token      string `json:"token"`
	PID        int    `json:"pid"`
	Version    string `json:"version,omitempty"`
	ExePath    string `json:"exe_path,omitempty"`
	ExeModTime int64  `json:"exe_mod_time,omitempty"`
	ExeSize    int64  `json:"exe_size,omitempty"`
}

func endpointPath() (string, error) {
	p, err := paths.Default()
	if err != nil {
		return "", err
	}
	return filepath.Join(p.Root, "broker.json"), nil
}

func readEndpoint() (endpoint, error) {
	path, err := endpointPath()
	if err != nil {
		return endpoint{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return endpoint{}, err
	}
	var ep endpoint
	if err := json.Unmarshal(data, &ep); err != nil {
		return endpoint{}, err
	}
	if ep.Addr == "" || ep.Token == "" {
		return endpoint{}, errors.New("incomplete broker endpoint")
	}
	return ep, nil
}

func writeEndpoint(ep endpoint) error {
	path, err := endpointPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(ep)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func removeEndpoint() {
	if path, err := endpointPath(); err == nil {
		_ = os.Remove(path)
	}
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
