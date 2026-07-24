package sshconn

import (
	"errors"
	"testing"
)

func TestClassifyDistinguishesAuthenticationFromHandshakeFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{
			name: "authentication",
			err:  errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]"),
			want: ErrAuth,
		},
		{
			name: "transport handshake",
			err:  errors.New("ssh: handshake failed: EOF"),
			want: ErrSSH,
		},
		{
			name: "algorithm negotiation",
			err:  errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"),
			want: ErrSSH,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Fatalf("Classify(%q) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
