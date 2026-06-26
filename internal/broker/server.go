package broker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
	"github.com/khalid-src/corv-client/internal/vault"
	"github.com/khalid-src/corv-client/internal/version"
)

var dialSSH = sshconn.Dial
var testDialOptions func(profile.Profile) sshconn.DialOptions
var brokerLog = log.New(os.Stderr, "corv broker: ", log.LstdFlags)

// idleTimeout is how long the broker stays up with no requests before it
// exits on its own, so it never lingers forever.
const idleTimeout = 15 * time.Minute

var controlOpTimeout = 30 * time.Second

var errStartUncertain = errors.New("remote job start outcome is uncertain")

// entry is one held connection plus a lock that serializes (re)dialing for
// that profile while allowing other profiles to proceed in parallel.
type entry struct {
	mu          sync.Mutex
	cond        *sync.Cond
	conn        *sshconn.Conn
	target      string
	fingerprint string
	dialing     bool
	closed      bool
	lastUsed    time.Time
	jobs        map[string]*job
	swept       bool
}

// server holds the warm connections and serves IPC requests.
type server struct {
	store   *profile.Store
	secrets *vault.Store

	mu      sync.Mutex
	entries map[string]*entry
	jobsMu  sync.Mutex
	jobs    jobRegistry

	activity   chan struct{}
	brokerAddr string
}

// Serve runs the broker until it is told to shut down or goes idle. It is
// the body of the hidden \`corv __broker\` process.
func Serve() error {
	p, err := paths.Default()
	if err != nil {
		return err
	}
	jobs, err := loadJobRegistry()
	if err != nil {
		return err
	}
	secrets := vault.New(p.VaultFile, p.VaultKey)
	s := &server{
		store:    profile.NewStore(p.ConfigFile, secrets),
		secrets:  secrets,
		entries:  map[string]*entry{},
		jobs:     jobs,
		activity: make(chan struct{}, 1),
	}
	s.sweepLocalRuns()

	ln, addr, err := listenBroker()
	if err != nil {
		return err
	}
	s.brokerAddr = addr
	defer ln.Close()
	defer cleanupBroker(addr)

	token := newToken()
	ep := endpoint{
		Addr:    addr,
		Token:   token,
		PID:     os.Getpid(),
		Version: version.Version,
	}
	if exe, err := os.Executable(); err == nil {
		ep.ExePath = exe
		if info, err := os.Stat(exe); err == nil {
			ep.ExeModTime = info.ModTime().UnixNano()
			ep.ExeSize = info.Size()
		}
	}
	if err := writeEndpoint(ep); err != nil {
		return err
	}
	defer removeEndpoint()

	stop := make(chan struct{})
	var stopOnce sync.Once
	shutdown := func() {
		stopOnce.Do(func() {
			close(stop)
			_ = ln.Close()
		})
	}
	go s.idleWatcher(stop, shutdown)

	var handlers sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				handlers.Wait()
				s.closeAll()
				return nil
			default:
				return err
			}
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			if s.handle(conn, token) {
				shutdown()
			}
		}()
	}
}

// handle serves one request connection. It returns true if the broker
// should shut down.
func (s *server) handle(conn net.Conn, token string) bool {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	gotToken, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimRight(gotToken, "\n")), []byte(token)) != 1 {
		return false
	}
	s.touch()

	var req Request
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		writeResp(conn, Response{OK: false, Error: "bad request"})
		return false
	}

	switch req.Op {
	case OpPing:
		writeResp(conn, Response{OK: true})
	case OpExec:
		writeResp(conn, s.exec(req))
	case OpOutput:
		writeResp(conn, s.output(req))
	case OpClose:
		s.closeOne(req.Name)
		writeResp(conn, Response{OK: true})
	case OpList:
		writeResp(conn, Response{OK: true, Held: s.list()})
	case OpShutdown:
		writeResp(conn, Response{OK: true})
		return true
	default:
		writeResp(conn, Response{OK: false, Error: "unknown op"})
	}
	return false
}

func writeResp(conn net.Conn, resp Response) {
	_ = json.NewEncoder(conn).Encode(resp)
}

// exec resolves the profile, attaches to an existing detached job when one
// is running for the same command, or starts a new one.
func (s *server) exec(req Request) Response {
	reg, err := s.store.Load()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	p, ok := reg.Get(req.Name)
	if !ok {
		return Response{OK: false, Error: "unknown connection: " + req.Name}
	}

	fingerprint, err := s.profileFingerprint(p, reg)
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	e := s.entryFor(req.Name)
	s.prepareEntry(e, p.Name, fingerprint)
	command := sshconn.CommandString(req.Command)
	j := s.jobFor(e, p.Name, command, fingerprint)
	if err := s.ensureJobStarted(e, p, reg, j); err != nil {
		if errors.Is(err, errStartUncertain) {
			return Response{
				OK:         false,
				ExitCode:   75,
				Highlights: []string{"Remote start timed out; Corv will verify the existing run on the next call"},
				Running:    true,
				RunID:      j.id,
			}
		}
		s.removeJob(e, p.Name, command, j)
		kind := sshconn.Classify(err)
		var se *startError
		if errors.As(err, &se) && se.kind != sshconn.ErrNone {
			kind = se.kind
		}
		return Response{OK: false, Error: err.Error(), Kind: string(kind), RunID: j.id}
	}

	resp, saved := s.watchJob(e, p, reg, j, parseWait(req.Wait, waitWindow()))
	if !resp.Running && (saved || j.failed()) {
		s.removeJob(e, p.Name, command, j)
	}
	return resp
}

func (s *server) connFor(e *entry, p profile.Profile, reg profile.Registry, fingerprint string) (*sshconn.Conn, error) {
	for {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return nil, errors.New("connection closed")
		}
		if e.fingerprint != fingerprint {
			e.mu.Unlock()
			return nil, errors.New("connection profile changed during dial")
		}
		if e.conn != nil {
			e.lastUsed = time.Now()
			conn := e.conn
			shouldSweep := !e.swept
			e.swept = true
			e.mu.Unlock()
			if shouldSweep {
				ctx, cancel := context.WithTimeout(context.Background(), controlOpTimeout)
				_ = conn.ExecRaw(ctx, sweepRemoteCommand(), maxDeltaBytes)
				cancel()
			}
			return conn, nil
		}
		if e.dialing {
			e.cond.Wait()
			e.mu.Unlock()
			continue
		}
		e.dialing = true
		e.mu.Unlock()

		conn, err := s.dial(p, reg)

		e.mu.Lock()
		e.dialing = false
		e.cond.Broadcast()
		if err != nil {
			e.mu.Unlock()
			return nil, err
		}
		if e.closed || e.fingerprint != fingerprint {
			e.mu.Unlock()
			_ = conn.Close()
			if e.closed {
				return nil, errors.New("connection closed")
			}
			return nil, errors.New("connection profile changed during dial")
		}
		e.conn = conn
		e.target = p.Target
		e.lastUsed = time.Now()
		shouldSweep := !e.swept
		e.swept = true
		e.mu.Unlock()

		if shouldSweep {
			ctx, cancel := context.WithTimeout(context.Background(), controlOpTimeout)
			_ = conn.ExecRaw(ctx, sweepRemoteCommand(), maxDeltaBytes)
			cancel()
		}
		return conn, nil
	}
}

func (s *server) resetConn(e *entry) {
	e.mu.Lock()
	conn := e.conn
	e.conn = nil
	e.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *server) runRaw(e *entry, p profile.Profile, reg profile.Registry, cmd string, maxBytes int64) (sshconn.RawResult, error) {
	return s.runRawStdin(e, p, reg, cmd, nil, maxBytes)
}

func (s *server) runRawStdin(e *entry, p profile.Profile, reg profile.Registry, cmd string, stdin []byte, maxBytes int64) (sshconn.RawResult, error) {
	fingerprint, err := s.profileFingerprint(p, reg)
	if err != nil {
		return sshconn.RawResult{}, err
	}
	conn, err := s.connFor(e, p, reg, fingerprint)
	if err != nil {
		return sshconn.RawResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlOpTimeout)
	res := conn.ExecRawStdin(ctx, cmd, stdin, maxBytes)
	cancel()
	if res.Kind == sshconn.ErrTimeout {
		s.resetConn(e)
		return res, nil
	}
	if res.Kind == sshconn.ErrDisconnect && !res.Started {
		s.resetConn(e)
		conn, err = s.connFor(e, p, reg, fingerprint)
		if err != nil {
			return sshconn.RawResult{}, err
		}
		ctx, cancel = context.WithTimeout(context.Background(), controlOpTimeout)
		res = conn.ExecRawStdin(ctx, cmd, stdin, maxBytes)
		cancel()
	}
	return res, nil
}

func (s *server) dial(p profile.Profile, reg profile.Registry) (*sshconn.Conn, error) {
	secret := vault.Secret{}
	if p.SecretRef != "" {
		if stored, ok, err := s.secrets.Get(p.SecretRef); err == nil && ok {
			secret = stored
		}
	}
	jumps, err := sshconn.ParseJumpChain(p.ProxyJump)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy jump %q: %w", p.ProxyJump, err)
	}
	sshconn.EnrichJumpChain(jumps, reg, s.jumpSecret)
	opt := sshconn.DialOptions{
		Password:     secret.Password,
		Passphrase:   secret.Passphrase,
		AllowNewHost: false,
		JumpHosts:    jumps,
	}
	if testDialOptions != nil {
		testOpt := testDialOptions(p)
		opt.HostKey = testOpt.HostKey
		opt.Auth = testOpt.Auth
	}
	// The broker is non-interactive: it never prompts for an unknown host.
	return dialSSH(p, opt)
}

// jumpSecret resolves a profile's vault reference for sshconn.EnrichJumpChain.
func (s *server) jumpSecret(ref string) (password, passphrase string) {
	if secret, ok, err := s.secrets.Get(ref); err == nil && ok {
		return secret.Password, secret.Passphrase
	}
	return "", ""
}

func (s *server) entryFor(name string) *entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[name]
	if !ok {
		e = &entry{jobs: map[string]*job{}}
		e.cond = sync.NewCond(&e.mu)
		s.entries[name] = e
	}
	return e
}

func (s *server) jobFor(e *entry, profileName, command, fingerprint string) *job {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.jobs == nil {
		e.jobs = map[string]*job{}
	}
	if j, ok := e.jobs[command]; ok && j.fingerprint == fingerprint {
		if !j.finished() {
			return j
		}
	}
	if rec, ok := s.persistedJob(profileName, command); ok &&
		(rec.Fingerprint == "" || rec.Fingerprint == fingerprint) &&
		(rec.Status == jobStatusStarting || rec.Status == jobStatusRunning) {
		j := recordToJob(rec)
		j.fingerprint = fingerprint
		e.jobs[command] = j
		return j
	}
	j := newJob(command, fingerprint)
	e.jobs[command] = j
	return j
}

func (s *server) removeJob(e *entry, profileName, command string, j *job) {
	e.mu.Lock()
	if e.jobs[command] == j {
		delete(e.jobs, command)
	}
	e.mu.Unlock()
	s.deletePersistedJob(profileName, command)
}

func (s *server) list() []HeldInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []HeldInfo
	for name, e := range s.entries {
		e.mu.Lock()
		if e.conn == nil {
			e.mu.Unlock()
			continue
		}
		out = append(out, HeldInfo{Name: name, Target: e.target, IdleMS: time.Since(e.lastUsed).Milliseconds()})
		e.mu.Unlock()
	}
	return out
}

func (s *server) closeOne(name string) {
	s.mu.Lock()
	e, ok := s.entries[name]
	if ok {
		delete(s.entries, name)
	}
	s.mu.Unlock()
	if ok {
		e.mu.Lock()
		conn := e.conn
		e.conn = nil
		e.closed = true
		e.cond.Broadcast()
		e.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func (s *server) closeAll() {
	s.mu.Lock()
	entries := s.entries
	s.entries = map[string]*entry{}
	s.mu.Unlock()
	for _, e := range entries {
		e.mu.Lock()
		conn := e.conn
		e.conn = nil
		e.closed = true
		e.cond.Broadcast()
		e.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func (s *server) prepareEntry(e *entry, profileName, fingerprint string) {
	e.mu.Lock()
	if e.fingerprint == "" {
		e.fingerprint = fingerprint
		e.mu.Unlock()
		return
	}
	if e.fingerprint == fingerprint {
		e.mu.Unlock()
		return
	}
	conn := e.conn
	e.conn = nil
	e.target = ""
	e.fingerprint = fingerprint
	e.jobs = map[string]*job{}
	e.swept = false
	e.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if err := s.deletePersistedJobs(profileName); err != nil {
		brokerLog.Printf("delete stale jobs for profile %s: %v", profileName, err)
	}
}

func (s *server) profileFingerprint(p profile.Profile, reg profile.Registry) (string, error) {
	secret := vault.Secret{}
	if p.SecretRef != "" {
		stored, ok, err := s.secrets.Get(p.SecretRef)
		if err != nil {
			return "", fmt.Errorf("read credentials for %s: %w", p.Name, err)
		}
		if ok {
			secret = stored
		}
	}
	jumps, err := sshconn.ParseJumpChain(p.ProxyJump)
	if err != nil {
		return "", fmt.Errorf("invalid proxy jump %q: %w", p.ProxyJump, err)
	}
	sshconn.EnrichJumpChain(jumps, reg, s.jumpSecret)

	credentials := sha256.Sum256([]byte(secret.Password + "\x00" + secret.Passphrase))
	sum := sha256.New()
	for _, field := range []string{
		p.Target,
		strconv.Itoa(p.Port),
		p.IdentityFile,
		p.ProxyJump,
		fmt.Sprintf("%x", credentials),
	} {
		_, _ = sum.Write([]byte(field))
		_, _ = sum.Write([]byte{0})
	}
	for _, jump := range jumps {
		jumpCredentials := sha256.Sum256([]byte(jump.Password + "\x00" + jump.Passphrase))
		for _, field := range []string{
			jump.User,
			jump.Host,
			strconv.Itoa(jump.Port),
			jump.IdentityFile,
			fmt.Sprintf("%x", jumpCredentials),
		} {
			_, _ = sum.Write([]byte(field))
			_, _ = sum.Write([]byte{0})
		}
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

func (s *server) touch() {
	select {
	case s.activity <- struct{}{}:
	default:
	}
}

func (s *server) idleWatcher(stop <-chan struct{}, shutdown func()) {
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-s.activity:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idleTimeout)
		case <-timer.C:
			if s.hasRunningJobs() {
				timer.Reset(idleTimeout)
				continue
			}
			shutdown()
			return
		}
	}
}

func (s *server) hasRunningJobs() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		e.mu.Lock()
		for _, j := range e.jobs {
			if !j.finished() {
				e.mu.Unlock()
				return true
			}
		}
		e.mu.Unlock()
	}
	return false
}

func (s *server) persistedJob(profileName, command string) (jobRecord, bool) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	rec, ok := s.jobs.Jobs[jobKey(profileName, command)]
	return rec, ok
}

func (s *server) persistedJobByRunID(runID string) (jobRecord, bool) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	for _, rec := range s.jobs.Jobs {
		if rec.RunID == runID {
			return rec, true
		}
	}
	return jobRecord{}, false
}

func (s *server) savePersistedJob(profileName string, j *job) error {
	if !s.currentJob(profileName, j) {
		return nil
	}
	j.mu.Lock()
	rec := newJobRecord(profileName, j)
	if j.done {
		rec.ExitCode = j.exitCode
	}
	j.mu.Unlock()

	s.jobsMu.Lock()
	if s.jobs.Jobs == nil {
		s.jobs.Jobs = map[string]jobRecord{}
	}
	s.jobs.Jobs[rec.Key] = rec
	err := saveJobRegistry(s.jobs)
	s.jobsMu.Unlock()
	return err
}

func (s *server) currentJob(profileName string, j *job) bool {
	s.mu.Lock()
	e, ok := s.entries[profileName]
	s.mu.Unlock()
	if !ok {
		return false
	}
	e.mu.Lock()
	current := e.jobs[j.command] == j && e.fingerprint == j.fingerprint
	e.mu.Unlock()
	return current
}

func (s *server) deletePersistedJob(profileName, command string) {
	s.jobsMu.Lock()
	delete(s.jobs.Jobs, jobKey(profileName, command))
	_ = saveJobRegistry(s.jobs)
	s.jobsMu.Unlock()
}

func (s *server) deletePersistedJobs(profileName string) error {
	s.jobsMu.Lock()
	for key, rec := range s.jobs.Jobs {
		if rec.Profile == profileName {
			delete(s.jobs.Jobs, key)
		}
	}
	err := saveJobRegistry(s.jobs)
	s.jobsMu.Unlock()
	return err
}
