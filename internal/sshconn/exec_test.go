package sshconn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/khalid-src/corv-client/internal/output"
	"github.com/khalid-src/corv-client/internal/profile"
)

// handler decides what a fake "exec" request produces.
type handler func(command string) (stdout string, exitCode int)
type stdinHandler func(command string, stdin []byte) (stdout string, exitCode int)

// startTestServer spins up an in-process SSH server that accepts any auth and
// runs commands via h. It returns the address, the host public key, and a
// cleanup func.
func startTestServer(t *testing.T, h handler) (addr string, hostKey ssh.PublicKey, cleanup func()) {
	return startTestServerStdin(t, func(command string, _ []byte) (string, int) {
		return h(command)
	})
}

func startTestServerStdin(t *testing.T, h stdinHandler) (addr string, hostKey ssh.PublicKey, cleanup func()) {
	t.Helper()

	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(nConn, cfg, h)
		}
	}()

	return ln.Addr().String(), hostSigner.PublicKey(), func() { _ = ln.Close() }
}

func serveConn(nConn net.Conn, cfg *ssh.ServerConfig, h stdinHandler) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			return
		}
		go handleSession(ch, requests, h)
	}
}

func handleSession(ch ssh.Channel, requests <-chan *ssh.Request, h stdinHandler) {
	for req := range requests {
		switch req.Type {
		case "exec":
			// Payload is a length-prefixed string; the command is the tail.
			cmd := string(req.Payload[4:])
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			stdin, _ := io.ReadAll(ch)
			out, code := h(cmd, stdin)
			_, _ = io.WriteString(ch, out)
			// Send exit-status then close, like a real server.
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			_ = ch.Close()
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func dialTest(t *testing.T, addr string, hostKey ssh.PublicKey) *Conn {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	conn, err := Dial(profile.Profile{Name: "t", Target: "tester@" + host, Port: port}, DialOptions{
		HostKey: ssh.FixedHostKey(hostKey),
		Auth:    []ssh.AuthMethod{ssh.Password("x")},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func TestExecSuccess(t *testing.T) {
	addr, hk, cleanup := startTestServer(t, func(cmd string) (string, int) {
		return "ran: " + cmd + "\n", 0
	})
	defer cleanup()

	conn := dialTest(t, addr, hk)
	defer conn.Close()

	res := conn.Exec(context.Background(), []string{"echo", "hello"}, 0, output.Options{})
	if !res.OK() {
		t.Fatalf("expected OK, got kind=%q exit=%d", res.Kind, res.ExitCode)
	}
	if res.Stdout != "ran: echo hello\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestExecPreservesQuotedArguments(t *testing.T) {
	addr, hk, cleanup := startTestServer(t, func(cmd string) (string, int) {
		return cmd + "\n", 0
	})
	defer cleanup()

	conn := dialTest(t, addr, hk)
	defer conn.Close()

	res := conn.Exec(context.Background(), []string{"sh", "-lc", "cd /app && npm test"}, 0, output.Options{})
	if !res.OK() {
		t.Fatalf("expected OK, got kind=%q exit=%d", res.Kind, res.ExitCode)
	}
	if res.Stdout != "sh -lc 'cd /app && npm test'\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestExecNonZeroExit(t *testing.T) {
	addr, hk, cleanup := startTestServer(t, func(string) (string, int) {
		return "boom\n", 7
	})
	defer cleanup()

	conn := dialTest(t, addr, hk)
	defer conn.Close()

	res := conn.Exec(context.Background(), []string{"false"}, 0, output.Options{})
	if res.ExitCode != 7 {
		t.Fatalf("exit = %d, want 7", res.ExitCode)
	}
	if res.OK() {
		t.Fatal("expected not OK for non-zero exit")
	}
}

func TestExecOutputIsFiltered(t *testing.T) {
	// A progress-bar style stream must collapse via the output broker.
	addr, hk, cleanup := startTestServer(t, func(string) (string, int) {
		var b strings.Builder
		for i := 0; i <= 100; i += 25 {
			fmt.Fprintf(&b, "\rprogress %d%%", i)
		}
		b.WriteString("\ndone\n")
		return b.String(), 0
	})
	defer cleanup()

	conn := dialTest(t, addr, hk)
	defer conn.Close()

	res := conn.Exec(context.Background(), []string{"install"}, 0, output.Options{})
	if res.Stdout != "progress 100%\ndone\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestConnAlive(t *testing.T) {
	addr, hk, cleanup := startTestServer(t, func(string) (string, int) { return "", 0 })
	conn := dialTest(t, addr, hk)
	if !conn.Alive() {
		t.Fatal("expected alive")
	}
	conn.Close()
	cleanup()
	time.Sleep(20 * time.Millisecond)
	if conn.Alive() {
		t.Fatal("expected not alive after close")
	}
}

func TestKeepaliveClosesUnresponsiveConnection(t *testing.T) {
	oldInterval := keepaliveInterval
	oldTimeout := keepaliveTimeout
	keepaliveInterval = 10 * time.Millisecond
	keepaliveTimeout = 20 * time.Millisecond
	t.Cleanup(func() {
		keepaliveInterval = oldInterval
		keepaliveTimeout = oldTimeout
	})

	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		nConn, err := ln.Accept()
		if err != nil {
			return
		}
		conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
		if err != nil {
			return
		}
		defer conn.Close()
		go func() {
			for range reqs {
			}
		}()
		for ch := range chans {
			_ = ch.Reject(ssh.UnknownChannelType, "not used")
		}
	}()

	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(profile.Profile{Name: "t", Target: "tester@" + host, Port: port}, DialOptions{
		HostKey: ssh.FixedHostKey(hostSigner.PublicKey()),
		Auth:    []ssh.AuthMethod{ssh.Password("x")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	deadline := time.Now().Add(time.Second)
	for conn.target() != nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if conn.target() != nil {
		t.Fatal("keepalive did not close the unresponsive connection")
	}
}

func TestDialHostKeyMismatch(t *testing.T) {
	addr, _, cleanup := startTestServer(t, func(string) (string, int) { return "", 0 })
	defer cleanup()

	// Present a different host key than the server actually uses.
	wrong := newSigner(t).PublicKey()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	_, err := Dial(profile.Profile{Name: "t", Target: "u@" + host, Port: port}, DialOptions{
		HostKey: ssh.FixedHostKey(wrong),
		Auth:    []ssh.AuthMethod{ssh.Password("x")},
	})
	if err == nil {
		t.Fatal("expected host key mismatch error")
	}
}

func TestLimitBufferHonorsWriterContractAtCapacity(t *testing.T) {
	w := &limitBuffer{max: 4}
	data := []byte("abcdefgh")

	n, err := w.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("Write returned %d, want %d", n, len(data))
	}
	if got := string(w.Bytes()); got != "abcd" {
		t.Fatalf("buffered data = %q, want %q", got, "abcd")
	}
	if w.Count() != int64(len(data)) {
		t.Fatalf("count = %d, want %d", w.Count(), len(data))
	}
	if !w.Truncated() {
		t.Fatal("expected truncated buffer")
	}
}

func TestExecRawStdinDeliversLargePayload(t *testing.T) {
	payload := []byte(strings.Repeat("0123456789abcdef", 20*1024))
	addr, hk, cleanup := startTestServerStdin(t, func(command string, stdin []byte) (string, int) {
		if command != "wc -c" {
			return "unexpected command", 1
		}
		return fmt.Sprintf("%d\n", len(stdin)), 0
	})
	defer cleanup()

	conn := dialTest(t, addr, hk)
	defer conn.Close()

	res := conn.ExecRawStdin(context.Background(), "wc -c", payload, 1024)
	if !res.OK() {
		t.Fatalf("result = %#v", res)
	}
	if got, want := strings.TrimSpace(string(res.Stdout)), fmt.Sprint(len(payload)); got != want {
		t.Fatalf("byte count = %s, want %s", got, want)
	}
}
