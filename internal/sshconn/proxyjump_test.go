package sshconn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/khalid-src/corv-client/internal/output"
	"github.com/khalid-src/corv-client/internal/profile"
)

func TestParseJumpChain(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want []JumpHost
	}{
		{name: "empty", spec: "", want: nil},
		{name: "none", spec: "none", want: nil},
		{name: "single", spec: "bastion", want: []JumpHost{{Host: "bastion"}}},
		{name: "multi", spec: "jump1,jump2", want: []JumpHost{{Host: "jump1"}, {Host: "jump2"}}},
		{name: "user host port", spec: "alice@bastion:2222", want: []JumpHost{{User: "alice", Host: "bastion", Port: 2222}}},
		{name: "bracketed IPv6", spec: "ops@[2001:db8::1]:2200", want: []JumpHost{{User: "ops", Host: "2001:db8::1", Port: 2200}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseJumpChain(tt.spec)
			if err != nil {
				t.Fatalf("ParseJumpChain() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseJumpChain() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseJumpChainMalformed(t *testing.T) {
	for _, spec := range []string{",", "@host", "host:", "::1", "[::1", "[]", "host:bad", "host:70000"} {
		t.Run(spec, func(t *testing.T) {
			if _, err := ParseJumpChain(spec); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestIPv6TargetHelpers(t *testing.T) {
	userName, host := splitTarget("admin@[::1]")
	if userName != "admin" || host != "::1" {
		t.Fatalf("splitTarget() = %q, %q", userName, host)
	}
	if got := joinHostPort("[::1]", 22); got != "[::1]:22" {
		t.Fatalf("joinHostPort bracketed = %q", got)
	}
	if got := joinHostPort("::1", 22); got != "[::1]:22" {
		t.Fatalf("joinHostPort IPv6 = %q", got)
	}
}

func TestDialThroughOneJump(t *testing.T) {
	target := startForwardingServer(t, func(cmd string) (string, int) {
		return "target ran " + cmd + "\n", 0
	})
	defer target.cleanup()
	jump := startForwardingServer(t, nil)
	defer jump.cleanup()

	conn := dialViaTestJumps(t, target, []testSSHServer{jump})
	res := conn.Exec(context.Background(), []string{"hostname"}, 0, output.Options{})
	if !res.OK() {
		t.Fatalf("exec failed: kind=%s exit=%d stderr=%q", res.Kind, res.ExitCode, res.Stderr)
	}
	if res.Stdout != "target ran hostname\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitInactive(t, target, jump)
}

func TestDialThroughTwoJumps(t *testing.T) {
	target := startForwardingServer(t, func(cmd string) (string, int) {
		return "through two: " + cmd + "\n", 0
	})
	defer target.cleanup()
	jump1 := startForwardingServer(t, nil)
	defer jump1.cleanup()
	jump2 := startForwardingServer(t, nil)
	defer jump2.cleanup()

	conn := dialViaTestJumps(t, target, []testSSHServer{jump1, jump2})
	res := conn.Exec(context.Background(), []string{"uptime"}, 0, output.Options{})
	if !res.OK() {
		t.Fatalf("exec failed: kind=%s exit=%d stderr=%q", res.Kind, res.ExitCode, res.Stderr)
	}
	if res.Stdout != "through two: uptime\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitInactive(t, target, jump1, jump2)
}

func TestDialThroughJumpWithPasswordAuth(t *testing.T) {
	target := startForwardingServer(t, func(cmd string) (string, int) {
		return "password jump: " + cmd + "\n", 0
	})
	defer target.cleanup()
	jump := startPasswordForwardingServer(t, "jump-secret")
	defer jump.cleanup()

	targetHost, targetPort := splitAddr(t, target.addr)
	jumpHost, jumpPort := splitAddr(t, jump.addr)
	conn, err := Dial(profile.Profile{Name: "target", Target: "tester@" + targetHost, Port: targetPort}, DialOptions{
		HostKey: acceptHostKeys(target.hostKey, jump.hostKey),
		Auth:    []ssh.AuthMethod{ssh.Password("x")},
		JumpHosts: []JumpHost{{
			User:     "jump",
			Host:     jumpHost,
			Port:     jumpPort,
			Password: "jump-secret",
		}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	res := conn.Exec(context.Background(), []string{"whoami"}, 0, output.Options{})
	if !res.OK() {
		t.Fatalf("exec failed: kind=%s exit=%d stderr=%q", res.Kind, res.ExitCode, res.Stderr)
	}
	if res.Stdout != "password jump: whoami\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestDialThroughJumpWithPrivateDNSAndKeyAuth(t *testing.T) {
	targetClientKey, targetKeyPath := newTestIdentity(t)
	target := startPublicKeyForwardingServer(t, targetClientKey.PublicKey(), func(cmd string) (string, int) {
		return "private dns: " + cmd + "\n", 0
	})
	defer target.cleanup()

	jumpClientKey, jumpKeyPath := newTestIdentity(t)
	privateName := "private-target.invalid"
	jump := startResolvingForwardingServer(t, jumpClientKey.PublicKey(), map[string]string{
		privateName: target.addr,
	})
	defer jump.cleanup()

	jumpHost, jumpPort := splitAddr(t, jump.addr)
	_, targetPort := splitAddr(t, target.addr)

	var verified []string
	hostKey := func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		verified = append(verified, hostname)
		switch hostname {
		case net.JoinHostPort(jumpHost, strconv.Itoa(jumpPort)):
			if bytes.Equal(key.Marshal(), jump.hostKey.Marshal()) {
				return nil
			}
		case net.JoinHostPort(privateName, strconv.Itoa(targetPort)):
			if bytes.Equal(key.Marshal(), target.hostKey.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("unexpected host key for %s", hostname)
	}

	conn, err := Dial(profile.Profile{
		Name:         "private-target",
		Target:       "ubuntu@" + privateName,
		Port:         targetPort,
		IdentityFile: targetKeyPath,
	}, DialOptions{
		HostKey: hostKey,
		JumpHosts: []JumpHost{{
			User:         "deploy",
			Host:         jumpHost,
			Port:         jumpPort,
			IdentityFile: jumpKeyPath,
		}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	res := conn.Exec(context.Background(), []string{"hostname"}, 0, output.Options{})
	if !res.OK() || res.Stdout != "private dns: hostname\n" {
		t.Fatalf("exec result = %#v", res)
	}
	if !reflect.DeepEqual(verified, []string{
		net.JoinHostPort(jumpHost, strconv.Itoa(jumpPort)),
		net.JoinHostPort(privateName, strconv.Itoa(targetPort)),
	}) {
		t.Fatalf("verified hosts = %#v", verified)
	}
}

func TestEnrichJumpChainByEndpointInheritsUser(t *testing.T) {
	reg := profile.Registry{}
	if err := reg.Set(profile.Profile{
		Name:         "bastion",
		Target:       "deploy@bastion.example.com",
		IdentityFile: "bastion-key",
		SecretRef:    "profile:bastion",
	}); err != nil {
		t.Fatal(err)
	}
	jumps := []JumpHost{{Host: "bastion.example.com"}}
	EnrichJumpChain(jumps, reg, func(ref string) (string, string) {
		if ref != "profile:bastion" {
			t.Fatalf("secret ref = %q", ref)
		}
		return "", "key-passphrase"
	})

	want := JumpHost{
		User:         "deploy",
		Host:         "bastion.example.com",
		IdentityFile: "bastion-key",
		Passphrase:   "key-passphrase",
	}
	if !reflect.DeepEqual(jumps[0], want) {
		t.Fatalf("jump = %#v, want %#v", jumps[0], want)
	}
}

func TestDialThroughHonorsTimeout(t *testing.T) {
	jump := startBlackholeForwardingServer(t)
	defer jump.cleanup()
	jumpHost, jumpPort := splitAddr(t, jump.addr)

	start := time.Now()
	_, err := Dial(profile.Profile{
		Name:   "unreachable-target",
		Target: "ubuntu@private-target.invalid",
	}, DialOptions{
		HostKey: ssh.FixedHostKey(jump.hostKey),
		Auth:    []ssh.AuthMethod{ssh.Password("x")},
		Timeout: 50 * time.Millisecond,
		JumpHosts: []JumpHost{{
			User: "jump",
			Host: jumpHost,
			Port: jumpPort,
		}},
	})
	if err == nil {
		t.Fatal("expected timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dial returned after %s, want bounded timeout", elapsed)
	}
}

type testSSHServer struct {
	addr    string
	hostKey ssh.PublicKey
	active  *atomic.Int32
	cleanup func()
}

func startForwardingServer(t *testing.T, h handler) testSSHServer {
	t.Helper()

	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)
	return startForwardingServerWithConfig(t, cfg, hostSigner.PublicKey(), h)
}

func startPasswordForwardingServer(t *testing.T, password string) testSSHServer {
	t.Helper()
	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("bad password")
		},
	}
	cfg.AddHostKey(hostSigner)
	return startForwardingServerWithConfig(t, cfg, hostSigner.PublicKey(), nil)
}

func startPublicKeyForwardingServer(t *testing.T, allowed ssh.PublicKey, h handler) testSSHServer {
	t.Helper()
	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected public key")
		},
	}
	cfg.AddHostKey(hostSigner)
	return startForwardingServerWithConfig(t, cfg, hostSigner.PublicKey(), h)
}

func startResolvingForwardingServer(t *testing.T, allowed ssh.PublicKey, routes map[string]string) testSSHServer {
	t.Helper()
	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected public key")
		},
	}
	cfg.AddHostKey(hostSigner)
	return startForwardingServerWithHandler(t, cfg, hostSigner.PublicKey(), nil, func(newChan ssh.NewChannel) {
		handleDirectTCPIPRoute(newChan, routes)
	})
}

func startBlackholeForwardingServer(t *testing.T) testSSHServer {
	t.Helper()
	hostSigner := newSigner(t)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)
	return startForwardingServerWithHandler(t, cfg, hostSigner.PublicKey(), nil, func(ssh.NewChannel) {
		select {}
	})
}

func startForwardingServerWithConfig(t *testing.T, cfg *ssh.ServerConfig, hostKey ssh.PublicKey, h handler) testSSHServer {
	return startForwardingServerWithHandler(t, cfg, hostKey, h, handleDirectTCPIP)
}

func startForwardingServerWithHandler(
	t *testing.T,
	cfg *ssh.ServerConfig,
	hostKey ssh.PublicKey,
	h handler,
	forward func(ssh.NewChannel),
) testSSHServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	active := &atomic.Int32{}
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			active.Add(1)
			go func() {
				defer active.Add(-1)
				serveForwardingConn(nConn, cfg, h, forward)
			}()
		}
	}()

	return testSSHServer{
		addr:    ln.Addr().String(),
		hostKey: hostKey,
		active:  active,
		cleanup: func() { _ = ln.Close() },
	}
}

func serveForwardingConn(nConn net.Conn, cfg *ssh.ServerConfig, h handler, forward func(ssh.NewChannel)) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			ch, requests, err := newChan.Accept()
			if err != nil {
				return
			}
			go handleSession(ch, requests, func(command string, _ []byte) (string, int) {
				return h(command)
			})
		case "direct-tcpip":
			go forward(newChan)
		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel")
		}
	}
}

func handleDirectTCPIP(newChan ssh.NewChannel) {
	var msg struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
		return
	}

	handleDirectTCPIPTo(newChan, net.JoinHostPort(msg.DestAddr, strconv.Itoa(int(msg.DestPort))))
}

func handleDirectTCPIPRoute(newChan ssh.NewChannel, routes map[string]string) {
	var msg struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
		return
	}
	targetAddr, ok := routes[msg.DestAddr]
	if !ok {
		_ = newChan.Reject(ssh.ConnectionFailed, "unknown private host")
		return
	}
	_, port := splitAddrText(targetAddr)
	if uint32(port) != msg.DestPort {
		_ = newChan.Reject(ssh.ConnectionFailed, "unexpected private port")
		return
	}
	handleDirectTCPIPTo(newChan, targetAddr)
}

func handleDirectTCPIPTo(newChan ssh.NewChannel, targetAddr string) {
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		_, _ = io.Copy(target, ch)
		_ = target.Close()
	}()
	go func() {
		_, _ = io.Copy(ch, target)
		_ = ch.Close()
	}()
}

func dialViaTestJumps(t *testing.T, target testSSHServer, jumps []testSSHServer) *Conn {
	t.Helper()

	targetHost, targetPort := splitAddr(t, target.addr)
	jumpHosts := make([]JumpHost, 0, len(jumps))
	keys := []ssh.PublicKey{target.hostKey}
	for i, jump := range jumps {
		host, port := splitAddr(t, jump.addr)
		jumpHosts = append(jumpHosts, JumpHost{User: fmt.Sprintf("jump%d", i+1), Host: host, Port: port})
		keys = append(keys, jump.hostKey)
	}

	conn, err := Dial(profile.Profile{Name: "target", Target: "tester@" + targetHost, Port: targetPort}, DialOptions{
		HostKey:   acceptHostKeys(keys...),
		Auth:      []ssh.AuthMethod{ssh.Password("x")},
		JumpHosts: jumpHosts,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func splitAddrText(addr string) (string, int) {
	host, portText, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portText)
	return host, port
}

func newTestIdentity(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	path := t.TempDir() + string(os.PathSeparator) + "identity"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return signer, path
}

func acceptHostKeys(keys ...ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		for _, allowed := range keys {
			if bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("unexpected host key %s", ssh.FingerprintSHA256(key))
	}
}

func waitInactive(t *testing.T, servers ...testSSHServer) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		allInactive := true
		for _, server := range servers {
			if server.active.Load() != 0 {
				allInactive = false
				break
			}
		}
		if allInactive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, server := range servers {
		if got := server.active.Load(); got != 0 {
			t.Fatalf("server %s still has %d active connections", server.addr, got)
		}
	}
}
