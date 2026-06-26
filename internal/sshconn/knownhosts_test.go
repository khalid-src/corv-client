package sshconn

import (
	"net"
	"os"
	"strings"
	"testing"
)

func TestAppendKnownHostSkipsSyntheticTunnelAddress(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "known_hosts"
	key := newSigner(t).PublicKey()

	if err := appendKnownHost(path, "private.internal:22", &net.TCPAddr{IP: net.IPv4zero}, key); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	if !strings.Contains(line, "private.internal") {
		t.Fatalf("known_hosts line = %q", line)
	}
	if strings.Contains(line, "0.0.0.0") || strings.Contains(line, ":0") {
		t.Fatalf("synthetic tunnel address recorded: %q", line)
	}
}

func TestAppendKnownHostIncludesDirectRemoteAddress(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "known_hosts"
	key := newSigner(t).PublicKey()

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}
	if err := appendKnownHost(path, "bastion.example:2222", remote, key); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	if !strings.Contains(line, "bastion.example") || !strings.Contains(line, "192.0.2.10") {
		t.Fatalf("known_hosts line = %q", line)
	}
}
