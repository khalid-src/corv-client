package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/version"
)

var spawnBroker = func(c *Client) error {
	return c.spawn()
}

// Client talks to the resident broker, starting it on first use.
type Client struct {
	self string // path to this executable, used to spawn the broker
}

// NewClient returns a broker client. self is the path to the corv binary
// (os.Executable); it is used to launch the broker process if needed.
func NewClient(self string) *Client {
	return &Client{self: self}
}

// Exec runs a command on a profile through the warm connection, starting the
// broker if it is not already running.
func (c *Client) Exec(name string, command []string) (Response, error) {
	return c.request(Request{
		Op:      OpExec,
		Name:    name,
		Command: command,
		Wait:    os.Getenv("CORV_WAIT"),
	})
}

// Output reads a completed run log through the broker.
func (c *Client) Output(runID, pattern string) (Response, error) {
	return c.request(Request{Op: OpOutput, RunID: runID, Pattern: pattern})
}

// Close drops a profile's held connection. If the broker is not running
// there is nothing to do.
func (c *Client) Close(name string) (Response, error) {
	if _, err := readEndpoint(); err != nil {
		return Response{OK: true}, nil
	}
	return c.request(Request{Op: OpClose, Name: name})
}

// Running reports whether a broker is currently up.
func (c *Client) Running() bool {
	ep, err := readEndpoint()
	if err != nil {
		return false
	}
	_, err = roundTrip(ep, Request{Op: OpPing})
	return err == nil
}

// List returns the currently held connections, or an empty list if the
// broker is not running.
func (c *Client) List() ([]HeldInfo, error) {
	if _, err := readEndpoint(); err != nil {
		return nil, nil // not running => nothing held
	}
	resp, err := c.request(Request{Op: OpList})
	if err != nil {
		return nil, err
	}
	return resp.Held, nil
}

// Shutdown stops the broker if it is running.
func (c *Client) Shutdown() error {
	if _, err := readEndpoint(); err != nil {
		return nil
	}
	_, err := c.request(Request{Op: OpShutdown})
	return err
}

func (c *Client) request(req Request) (Response, error) {
	ep, err := c.ensureRunning()
	if err != nil {
		return Response{}, err
	}
	return roundTrip(ep, req)
}

// ensureRunning returns a live broker endpoint, launching the broker if the
// recorded endpoint is missing or unresponsive.
func (c *Client) ensureRunning() (endpoint, error) {
	if ep, ok := c.currentEndpoint(); ok {
		return ep, nil
	}

	unlock, err := acquireBrokerLock()
	if err != nil {
		return endpoint{}, fmt.Errorf("lock broker startup: %w", err)
	}
	defer unlock()

	if ep, ok := c.currentEndpoint(); ok {
		return ep, nil
	}

	c.stopStaleBroker()
	removeEndpoint()
	if err := spawnBroker(c); err != nil {
		return endpoint{}, err
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ep, ok := c.currentEndpoint(); ok {
			return ep, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return endpoint{}, errors.New("broker did not start")
}

func brokerIsCurrent(ep endpoint, self string) bool {
	if ep.Version != version.Version {
		return false
	}
	if ep.ExePath == "" || !sameExecutablePath(ep.ExePath, self) {
		return true
	}
	info, err := os.Stat(self)
	if err != nil {
		return false
	}
	return info.ModTime().UnixNano() == ep.ExeModTime && info.Size() == ep.ExeSize
}

func sameExecutablePath(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func (c *Client) currentEndpoint() (endpoint, bool) {
	ep, err := readEndpoint()
	if err != nil || !brokerIsCurrent(ep, c.self) {
		return endpoint{}, false
	}
	if _, err := roundTrip(ep, Request{Op: OpPing}); err != nil {
		return endpoint{}, false
	}
	return ep, true
}

func (c *Client) stopStaleBroker() {
	ep, err := readEndpoint()
	if err != nil {
		return
	}
	if _, err := roundTrip(ep, Request{Op: OpPing}); err != nil {
		return
	}
	_, _ = roundTrip(ep, Request{Op: OpShutdown})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := roundTrip(ep, Request{Op: OpPing}); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *Client) spawn() error {
	logPath, err := brokerLogPath()
	if err != nil {
		return err
	}
	logFile, _ := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)

	cmd := exec.Command(c.self, "__broker")
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachSysProcAttr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start broker: %w", err)
	}
	// Detach: do not wait on the broker; let it outlive us.
	_ = cmd.Process.Release()
	return nil
}

func roundTrip(ep endpoint, req Request) (Response, error) {
	conn, err := dialBroker(ep.Addr, 2*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(roundTripTimeout(req)))

	if _, err := fmt.Fprintln(conn, ep.Token); err != nil {
		return Response{}, err
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func roundTripTimeout(req Request) time.Duration {
	if req.Op != OpExec && req.Op != OpOutput {
		return 30 * time.Second
	}
	timeout := parseWait(req.Wait, waitWindow()) + 4*controlOpTimeout + 15*time.Second
	if timeout > 5*time.Minute {
		return 5 * time.Minute
	}
	return timeout
}

func brokerLogPath() (string, error) {
	p, err := paths.Default()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(p.Root, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(p.Root, "broker.log"), nil
}
