package sshconn

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/khalid-src/corv-client/internal/profile"
)

func TestDialBoundsSSHHandshake(t *testing.T) {
	tests := []struct {
		name  string
		jumps func(string, int) []JumpHost
	}{
		{name: "direct"},
		{
			name: "first jump",
			jumps: func(host string, port int) []JumpHost {
				return []JumpHost{{User: "tester", Host: host, Port: port, Password: "secret"}}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					accepted <- conn
				}
			}()

			host, portText, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			targetHost, targetPort := host, port
			var jumps []JumpHost
			if tt.jumps != nil {
				jumps = tt.jumps(host, port)
				targetHost = "127.0.0.1"
				targetPort = 22
			}

			started := time.Now()
			_, err = Dial(profile.Profile{
				Name:   "target",
				Target: "tester@" + targetHost,
				Port:   targetPort,
			}, DialOptions{
				Auth:      []ssh.AuthMethod{ssh.Password("secret")},
				HostKey:   ssh.InsecureIgnoreHostKey(),
				JumpHosts: jumps,
				Timeout:   50 * time.Millisecond,
			})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want deadline exceeded", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("dial took %v", elapsed)
			}
			select {
			case conn := <-accepted:
				_ = conn.Close()
			case <-time.After(time.Second):
				t.Fatal("server did not accept connection")
			}
		})
	}
}
