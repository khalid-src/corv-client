package sshconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestExecRawQueuesAtConnectionChannelLimit(t *testing.T) {
	t.Setenv("CORV_MAX_CHANNELS", "2")
	server := startLimitedSessionServer(t, 2, 40*time.Millisecond)
	defer server.cleanup()

	conn := dialTest(t, server.addr, server.hostKey)
	defer conn.Close()

	runConcurrentExecs(t, conn, 16)
	if got := server.rejected.Load(); got != 0 {
		t.Fatalf("server rejected %d channels, want 0", got)
	}
}

func TestExecRawRetriesServerChannelExhaustion(t *testing.T) {
	t.Setenv("CORV_MAX_CHANNELS", "8")
	server := startLimitedSessionServer(t, 2, 40*time.Millisecond)
	defer server.cleanup()

	conn := dialTest(t, server.addr, server.hostKey)
	defer conn.Close()

	runConcurrentExecs(t, conn, 16)
	if got := server.rejected.Load(); got == 0 {
		t.Fatal("server did not exercise the channel-open retry path")
	}
}

func TestExecRawReportsSustainedChannelExhaustion(t *testing.T) {
	t.Setenv("CORV_MAX_CHANNELS", "8")
	server := startLimitedSessionServer(t, 0, 0)
	defer server.cleanup()

	conn := dialTest(t, server.addr, server.hostKey)
	defer conn.Close()

	result := conn.ExecRaw(context.Background(), "true", 1024)
	if result.Kind != ErrResourceExhausted {
		t.Fatalf("kind = %q, want %q", result.Kind, ErrResourceExhausted)
	}
	if result.Started {
		t.Fatal("rejected channel must not be reported as started")
	}
}

func TestAcquireChannelHonorsContextAndReleasesSlots(t *testing.T) {
	t.Setenv("CORV_MAX_CHANNELS", "1")
	server := startLimitedSessionServer(t, 1, 150*time.Millisecond)
	defer server.cleanup()

	conn := dialTest(t, server.addr, server.hostKey)
	defer conn.Close()

	firstDone := make(chan RawResult, 1)
	go func() {
		firstDone <- conn.ExecRaw(context.Background(), "first", 1024)
	}()
	waitForActiveSessions(t, server.active, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	blocked := conn.ExecRaw(ctx, "blocked", 1024)
	if blocked.Kind != ErrTimeout || blocked.ExitCode != 124 || blocked.Started {
		t.Fatalf("blocked result = %#v", blocked)
	}
	if result := <-firstDone; !result.OK() {
		t.Fatalf("first result = %#v", result)
	}
	if result := conn.ExecRaw(context.Background(), "after", 1024); !result.OK() {
		t.Fatalf("result after release = %#v", result)
	}
}

func TestChannelLimitParsing(t *testing.T) {
	tests := []struct {
		value string
		want  int
	}{
		{value: "", want: defaultMaxChannels},
		{value: "bad", want: defaultMaxChannels},
		{value: "0", want: minMaxChannels},
		{value: "65", want: maxMaxChannels},
		{value: "12", want: 12},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv("CORV_MAX_CHANNELS", test.value)
			if got := channelLimit(); got != test.want {
				t.Fatalf("channelLimit() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestClassifyChannelResourceExhaustion(t *testing.T) {
	for _, message := range []string{
		"open failed",
		"administratively prohibited",
		"resource shortage",
		"maximum sessions reached",
		"too many sessions",
	} {
		t.Run(message, func(t *testing.T) {
			if got := classifyChannelError(errors.New(message)); got != ErrResourceExhausted {
				t.Fatalf("classifyChannelError() = %q, want %q", got, ErrResourceExhausted)
			}
		})
	}
	if got := classifyChannelError(errors.New("generic channel failure")); got != ErrSSH {
		t.Fatalf("generic error classified as %q, want %q", got, ErrSSH)
	}
}

func runConcurrentExecs(t *testing.T, conn *Conn, count int) {
	t.Helper()
	results := make(chan RawResult, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results <- conn.ExecRaw(context.Background(), fmt.Sprintf("command-%d", index), 1024)
		}(i)
	}
	wg.Wait()
	close(results)

	for result := range results {
		if !result.OK() {
			t.Fatalf("concurrent exec failed: kind=%q exit=%d stderr=%q", result.Kind, result.ExitCode, result.Stderr)
		}
	}
}

type limitedSessionServer struct {
	addr     string
	hostKey  ssh.PublicKey
	active   *atomic.Int32
	rejected *atomic.Int32
	cleanup  func()
}

func startLimitedSessionServer(t *testing.T, limit int32, hold time.Duration) limitedSessionServer {
	t.Helper()
	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	active := &atomic.Int32{}
	rejected := &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveLimitedSessionConn(conn, cfg, limit, hold, active, rejected)
		}
	}()

	return limitedSessionServer{
		addr:     listener.Addr().String(),
		hostKey:  hostSigner.PublicKey(),
		active:   active,
		rejected: rejected,
		cleanup:  func() { _ = listener.Close() },
	}
}

func serveLimitedSessionConn(
	netConn net.Conn,
	cfg *ssh.ServerConfig,
	limit int32,
	hold time.Duration,
	active *atomic.Int32,
	rejected *atomic.Int32,
) {
	conn, channels, requests, err := ssh.NewServerConn(netConn, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		if !reserveSession(active, limit) {
			rejected.Add(1)
			_ = newChannel.Reject(ssh.ResourceShortage, "maximum sessions reached")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			active.Add(-1)
			return
		}
		go func() {
			defer active.Add(-1)
			handleSession(channel, channelRequests, func(string, []byte) (string, int) {
				time.Sleep(hold)
				return "ok\n", 0
			})
		}()
	}
}

func reserveSession(active *atomic.Int32, limit int32) bool {
	for {
		current := active.Load()
		if current >= limit {
			return false
		}
		if active.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func waitForActiveSessions(t *testing.T, active *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if active.Load() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active sessions = %d, want %d", active.Load(), want)
}
