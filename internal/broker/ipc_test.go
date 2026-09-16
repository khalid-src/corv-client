package broker

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khalid-src/corv-client/internal/version"
)

func TestEndpointRoundTrip(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())

	if _, err := readEndpoint(); err == nil {
		t.Fatal("expected error reading missing endpoint")
	}

	token, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	ep := endpoint{
		Addr:         "127.0.0.1:12345",
		Token:        token,
		PID:          42,
		Version:      "v1.0.0",
		ExePath:      "corv",
		ExeModTime:   123,
		ExeSize:      456,
		ProcessStart: 789,
	}
	if err := writeEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	got, err := readEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	if got != ep {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, ep)
	}

	removeEndpoint()
	if _, err := readEndpoint(); err == nil {
		t.Fatal("expected error after remove")
	}
}

func TestRemoveEndpointIfOwnedPreservesReplacement(t *testing.T) {
	t.Setenv("CORV_HOME", t.TempDir())
	old := endpoint{Addr: "old", Token: "old-token", PID: 1}
	fresh := endpoint{Addr: "fresh", Token: "fresh-token", PID: 2}
	if err := writeEndpoint(fresh); err != nil {
		t.Fatal(err)
	}
	if removeEndpointIfOwned(old) {
		t.Fatal("stale owner removed the endpoint")
	}
	got, err := readEndpoint()
	if err != nil || got != fresh {
		t.Fatalf("replacement endpoint = %#v, err=%v", got, err)
	}
	if !removeEndpointIfOwned(fresh) {
		t.Fatal("current owner did not remove its endpoint")
	}
}

func TestBrokerIsCurrent(t *testing.T) {
	oldVersion := version.Version
	version.Version = "test-current"
	t.Cleanup(func() { version.Version = oldVersion })

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(self)
	if err != nil {
		t.Fatal(err)
	}
	current := endpoint{
		Version:    version.Version,
		ExePath:    filepath.Clean(self),
		ExeModTime: info.ModTime().UnixNano(),
		ExeSize:    info.Size(),
	}
	if !brokerIsCurrent(current, self) {
		t.Fatal("matching broker identity was not current")
	}

	staleVersion := current
	staleVersion.Version = "stale"
	if brokerIsCurrent(staleVersion, self) {
		t.Fatal("different broker version was current")
	}

	staleBinary := current
	staleBinary.ExeSize++
	if brokerIsCurrent(staleBinary, self) {
		t.Fatal("changed executable size was current")
	}

	staleModTime := current
	staleModTime.ExeModTime++
	if brokerIsCurrent(staleModTime, self) {
		t.Fatal("changed executable modification time was current")
	}

	otherPath := current
	otherPath.ExePath = filepath.Join(filepath.Dir(self), "other-corv")
	if !brokerIsCurrent(otherPath, self) {
		t.Fatal("same version from another install path was not current")
	}
}

func TestTokenIsRandom(t *testing.T) {
	a, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("tokens should differ")
	}
	if len(a) != 64 { // 32 bytes hex-encoded
		t.Fatalf("unexpected token length: %d", len(a))
	}
}

func TestTokenGenerationFailureIsReturned(t *testing.T) {
	original := tokenReader
	tokenReader = strings.NewReader("")
	t.Cleanup(func() { tokenReader = original })
	if _, err := newToken(); !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v", err)
	}
}

func TestProcessStartIDIdentifiesCurrentProcess(t *testing.T) {
	id, err := processStartID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("current process has an empty start identity")
	}
}
