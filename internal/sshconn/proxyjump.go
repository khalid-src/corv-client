package sshconn

import (
	"fmt"
	"strconv"
	"strings"
)

// JumpHost is one hop in a ProxyJump chain.
type JumpHost struct {
	User         string
	Host         string
	Port         int // 0 means 22
	IdentityFile string
	Password     string
	Passphrase   string
}

// ParseJumpChain parses an OpenSSH ProxyJump spec: a comma-separated list
// of [user@]host[:port] hops. IPv6 hosts must be bracketed, e.g.
// [2001:db8::1]:22. An empty spec or "none" returns (nil, nil).
func ParseJumpChain(spec string) ([]JumpHost, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "none") {
		return nil, nil
	}

	parts := strings.Split(spec, ",")
	hops := make([]JumpHost, 0, len(parts))
	for _, part := range parts {
		hop, err := parseJumpHost(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

func parseJumpHost(spec string) (JumpHost, error) {
	if spec == "" {
		return JumpHost{}, fmt.Errorf("empty jump host")
	}

	userName := ""
	hostSpec := spec
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		userName = spec[:at]
		hostSpec = spec[at+1:]
		if userName == "" {
			return JumpHost{}, fmt.Errorf("empty jump user in %q", spec)
		}
	}

	host, port, err := parseHostPort(hostSpec)
	if err != nil {
		return JumpHost{}, fmt.Errorf("parse jump host %q: %w", spec, err)
	}
	return JumpHost{User: userName, Host: host, Port: port}, nil
}

func parseHostPort(spec string) (string, int, error) {
	if spec == "" {
		return "", 0, fmt.Errorf("empty host")
	}

	if strings.HasPrefix(spec, "[") {
		end := strings.Index(spec, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("missing closing bracket")
		}
		host := spec[1:end]
		if host == "" {
			return "", 0, fmt.Errorf("empty host")
		}
		rest := spec[end+1:]
		switch {
		case rest == "":
			return host, 0, nil
		case strings.HasPrefix(rest, ":"):
			port, err := parsePort(rest[1:])
			if err != nil {
				return "", 0, err
			}
			return host, port, nil
		default:
			return "", 0, fmt.Errorf("unexpected data after bracketed host")
		}
	}

	if strings.Count(spec, ":") > 1 {
		return "", 0, fmt.Errorf("IPv6 jump hosts must be bracketed")
	}
	if strings.Count(spec, ":") == 1 {
		host, portText, _ := strings.Cut(spec, ":")
		if host == "" {
			return "", 0, fmt.Errorf("empty host")
		}
		port, err := parsePort(portText)
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}
	return spec, 0, nil
}

func parsePort(text string) (int, error) {
	if text == "" {
		return 0, fmt.Errorf("empty port")
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("invalid port")
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range")
	}
	return port, nil
}
