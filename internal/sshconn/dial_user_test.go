package sshconn

import (
	"errors"
	"os/user"
	"testing"
)

func TestCurrentUserNormalizesOSUsername(t *testing.T) {
	original := lookupCurrentUser
	lookupCurrentUser = func() (*user.User, error) {
		return &user.User{Username: `DOMAIN\operator`}, nil
	}
	t.Cleanup(func() { lookupCurrentUser = original })

	got, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	if got != "operator" {
		t.Fatalf("currentUser() = %q, want operator", got)
	}
}

func TestCurrentUserFallsBackToEnvironment(t *testing.T) {
	original := lookupCurrentUser
	lookupCurrentUser = func() (*user.User, error) {
		return nil, errors.New("lookup failed")
	}
	t.Cleanup(func() { lookupCurrentUser = original })
	t.Setenv("USER", "")
	t.Setenv("USERNAME", `WORKGROUP\deploy`)

	got, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	if got != "deploy" {
		t.Fatalf("currentUser() = %q, want deploy", got)
	}
}

func TestCurrentUserRequiresExplicitRemoteUserWhenUnavailable(t *testing.T) {
	original := lookupCurrentUser
	lookupCurrentUser = func() (*user.User, error) {
		return nil, errors.New("lookup failed")
	}
	t.Cleanup(func() { lookupCurrentUser = original })
	t.Setenv("USER", "")
	t.Setenv("USERNAME", "")

	if _, err := currentUser(); err == nil {
		t.Fatal("expected missing username error")
	}
}
