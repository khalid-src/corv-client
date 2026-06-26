package sshconn

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/khalid-src/corv-client/internal/profile"
)

const (
	defaultDialTimeout = 15 * time.Second
	defaultMaxChannels = 8
	minMaxChannels     = 1
	maxMaxChannels     = 64
)

var (
	keepaliveInterval = 15 * time.Second
	keepaliveTimeout  = 15 * time.Second
)

// DialOptions configures a connection attempt.
type DialOptions struct {
	Password     string                     // stored vault password (may be empty)
	Passphrase   string                     // private-key passphrase (may be empty)
	AllowNewHost bool                       // permit recording an unknown host key
	Prompt       func(host, fp string) bool // approve an unknown host (interactive only)
	Timeout      time.Duration              // connect timeout (0 = default)

	// HostKey, if set, overrides the default ~/.ssh/known_hosts verification.
	// Used by tests; production paths leave it nil.
	HostKey ssh.HostKeyCallback
	// Auth, if set, overrides the default key/agent/password methods.
	// Used by tests; production paths leave it nil.
	Auth []ssh.AuthMethod
	// JumpHosts is a ProxyJump chain. Empty means a direct connection.
	JumpHosts []JumpHost
}

// Conn is a live, authenticated SSH connection to one machine. It is safe
// for concurrent Exec calls; each opens its own channel over the shared
// connection.
type Conn struct {
	mu        sync.RWMutex
	closeOnce sync.Once
	clients   []*ssh.Client
	profile   profile.Profile
	stop      chan struct{}
	sem       chan struct{}
}

// Dial opens and authenticates a connection to the profile's target.
func Dial(p profile.Profile, opt DialOptions) (*Conn, error) {
	if len(opt.JumpHosts) > 0 {
		return dialViaJumps(p, opt)
	}

	user, host := splitTarget(p.Target)
	if user == "" {
		user = currentUser()
	}
	port := p.Port
	if port == 0 {
		port = 22
	}
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}

	var err error
	methods := opt.Auth
	var closers []io.Closer
	if methods == nil {
		methods, closers, err = authMethods(p.IdentityFile, opt.Passphrase, opt.Password)
		if err != nil {
			return nil, err
		}
	}
	defer closeAuthClosers(closers)
	hostKey := opt.HostKey
	if hostKey == nil {
		hostKey, err = hostKeyCallback(opt.AllowNewHost, opt.Prompt)
		if err != nil {
			return nil, err
		}
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	}

	addr := joinHostPort(host, port)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return newConn([]*ssh.Client{client}, p), nil
}

// Close tears down the connection.
func (c *Conn) Close() error {
	var first error
	c.closeOnce.Do(func() {
		close(c.stop)
		c.mu.Lock()
		clients := c.clients
		c.clients = nil
		c.mu.Unlock()
		for i := len(clients) - 1; i >= 0; i-- {
			if err := clients[i].Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

// Alive reports whether the connection still responds. It sends a cheap
// global request; a dead connection returns an error.
func (c *Conn) Alive() bool {
	client := c.target()
	if client == nil {
		return false
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@corv", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(keepaliveTimeout):
		_ = c.Close()
		return false
	}
}

func (c *Conn) target() *ssh.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.clients) == 0 {
		return nil
	}
	return c.clients[len(c.clients)-1]
}

func newConn(clients []*ssh.Client, p profile.Profile) *Conn {
	c := &Conn{
		clients: clients,
		profile: p,
		stop:    make(chan struct{}),
		sem:     make(chan struct{}, channelLimit()),
	}
	go c.keepalive()
	return c
}

func (c *Conn) acquireChannel(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Conn) releaseChannel() {
	<-c.sem
}

func channelLimit() int {
	value, err := strconv.Atoi(os.Getenv("CORV_MAX_CHANNELS"))
	if err != nil {
		return defaultMaxChannels
	}
	if value < minMaxChannels {
		return minMaxChannels
	}
	if value > maxMaxChannels {
		return maxMaxChannels
	}
	return value
}

func (c *Conn) keepalive() {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
		}

		client := c.target()
		if client == nil {
			return
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			done <- err
		}()
		select {
		case <-c.stop:
			return
		case err := <-done:
			if err != nil {
				_ = c.Close()
				return
			}
		case <-time.After(keepaliveTimeout):
			_ = c.Close()
			return
		}
	}
}

func dialViaJumps(p profile.Profile, opt DialOptions) (*Conn, error) {
	userName, host := splitTarget(p.Target)
	if userName == "" {
		userName = currentUser()
	}
	port := p.Port
	if port == 0 {
		port = 22
	}
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}

	var err error
	methods := opt.Auth
	var targetClosers []io.Closer
	if methods == nil {
		methods, targetClosers, err = authMethods(p.IdentityFile, opt.Passphrase, opt.Password)
		if err != nil {
			return nil, err
		}
	}
	defer closeAuthClosers(targetClosers)
	hostKey := opt.HostKey
	if hostKey == nil {
		hostKey, err = hostKeyCallback(opt.AllowNewHost, opt.Prompt)
		if err != nil {
			return nil, err
		}
	}

	var clients []*ssh.Client
	var jumpClosers []io.Closer
	defer closeAuthClosers(jumpClosers)
	closeClients := func() {
		for i := len(clients) - 1; i >= 0; i-- {
			_ = clients[i].Close()
		}
	}

	var previous *ssh.Client
	for i, hop := range opt.JumpHosts {
		hopUser := hop.User
		if hopUser == "" {
			hopUser = currentUser()
		}
		hopPort := hop.Port
		if hopPort == 0 {
			hopPort = 22
		}
		jumpAuth, closers, err := jumpAuthMethods(hop)
		if err != nil {
			closeClients()
			return nil, fmt.Errorf("auth jump host %s: %w", hop.Host, err)
		}
		jumpClosers = append(jumpClosers, closers...)
		addr := joinHostPort(hop.Host, hopPort)
		cfg := &ssh.ClientConfig{
			User:            hopUser,
			Auth:            jumpAuth,
			HostKeyCallback: hostKey,
			Timeout:         timeout,
		}

		var client *ssh.Client
		if i == 0 {
			client, err = ssh.Dial("tcp", addr, cfg)
		} else {
			client, err = dialThrough(previous, addr, cfg, timeout)
		}
		if err != nil {
			closeClients()
			return nil, fmt.Errorf("dial jump host %s: %w", addr, err)
		}
		clients = append(clients, client)
		previous = client
	}

	targetAddr := joinHostPort(host, port)
	targetCfg := &ssh.ClientConfig{
		User:            userName,
		Auth:            methods,
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	}
	target, err := dialThrough(previous, targetAddr, targetCfg, timeout)
	if err != nil {
		closeClients()
		return nil, fmt.Errorf("dial target through jump chain: %w", err)
	}
	clients = append(clients, target)
	return newConn(clients, p), nil
}

func dialThrough(parent *ssh.Client, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	if parent == nil {
		return nil, fmt.Errorf("missing parent connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	nc, err := parent.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return newClientThroughContext(ctx, nc, addr, cfg)
}

func newClientThroughContext(ctx context.Context, nc net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	type result struct {
		conn  ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		err   error
	}
	done := make(chan result, 1)
	go func() {
		conn, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
		done <- result{conn: conn, chans: chans, reqs: reqs, err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			_ = nc.Close()
			return nil, res.err
		}
		return ssh.NewClient(res.conn, res.chans, res.reqs), nil
	case <-ctx.Done():
		_ = nc.Close()
		res := <-done
		if res.conn != nil {
			_ = res.conn.Close()
		}
		return nil, ctx.Err()
	}
}

func jumpAuthMethods(hop JumpHost) ([]ssh.AuthMethod, []io.Closer, error) {
	if hop.IdentityFile != "" || hop.Password != "" || hop.Passphrase != "" {
		return authMethods(hop.IdentityFile, hop.Passphrase, hop.Password)
	}
	var methods []ssh.AuthMethod
	var closers []io.Closer
	if a, closer := agentMethod(); a != nil {
		methods = append(methods, a)
		closers = append(closers, closer)
	}
	if signers := defaultKeySigners(""); len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if len(methods) == 0 {
		return nil, closers, fmt.Errorf("no jump authentication methods available")
	}
	return methods, closers, nil
}

func closeAuthClosers(closers []io.Closer) {
	for _, closer := range closers {
		if closer != nil {
			_ = closer.Close()
		}
	}
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(unbracketHost(host), strconv.Itoa(port))
}

func unbracketHost(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return host
}

func splitTarget(target string) (user, host string) {
	if at := strings.LastIndex(target, "@"); at > 0 {
		return target[:at], unbracketHost(target[at+1:])
	}
	return "", unbracketHost(target)
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		// On Windows the username can be DOMAIN\user; keep only the name.
		name := u.Username
		if i := strings.LastIndexAny(name, `\/`); i >= 0 {
			name = name[i+1:]
		}
		return name
	}
	return "root"
}
