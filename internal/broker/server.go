package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/khalid-src/corv-client/internal/audit"
	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
	"github.com/khalid-src/corv-client/internal/statelock"
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
var fullLogTransferTimeout = 2 * time.Minute

var errStartUncertain = errors.New("remote job start outcome is uncertain")
var errRunKeyConflict = errors.New("run key was already used with different command or connection state")

// entry is one held connection plus a lock that serializes (re)dialing for
// that profile while allowing other profiles to proceed in parallel.
type entry struct {
	mu          sync.Mutex
	cond        *sync.Cond
	conn        *sshconn.Conn
	target      string
	fingerprint string
	snapshot    connectionSnapshot
	dialing     bool
	closed      bool
	lastUsed    time.Time
	jobs        map[string]*job
	swept       bool
}

type connectionSnapshot struct {
	profile           profile.Profile
	registry          profile.Registry
	secret            vault.Secret
	jumps             []sshconn.JumpHost
	fingerprint       string
	legacyFingerprint string
}

// server holds the warm connections and serves IPC requests.
type server struct {
	store   *profile.Store
	secrets *vault.Store
	audit   *audit.Log
	now     func() time.Time

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
		audit:    audit.NewLog(p.AuditFile),
		now:      time.Now,
		entries:  map[string]*entry{},
		jobs:     jobs,
		activity: make(chan struct{}, 1),
	}
	s.sweepLocalRuns()
	s.pruneExpiredKeyedJobs(s.currentTime())

	ln, addr, err := listenBroker()
	if err != nil {
		return err
	}
	s.brokerAddr = addr
	var published endpoint
	defer func() {
		_ = ln.Close()
		if published.Addr == "" || removeEndpointIfOwned(published) {
			cleanupBroker(addr)
		}
	}()

	token, err := newToken()
	if err != nil {
		return fmt.Errorf("generate broker token: %w", err)
	}
	ep := endpoint{
		Addr:    addr,
		Token:   token,
		PID:     os.Getpid(),
		Version: version.Version,
	}
	if id, err := processStartID(ep.PID); err == nil {
		ep.ProcessStart = id
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
	published = ep

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
	case OpJobs:
		runs, err := s.listRuns()
		if err != nil {
			writeResp(conn, Response{OK: false, Error: err.Error()})
		} else {
			writeResp(conn, Response{OK: true, Runs: runs})
		}
	case OpClose:
		s.closeOne(req.Name)
		writeResp(conn, Response{OK: true})
	case OpList:
		writeResp(conn, Response{OK: true, Held: s.list()})
	case OpStatus:
		writeResp(conn, Response{OK: true, Connections: s.status()})
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
	if req.RunKey != "" && !validRunKey(req.RunKey) {
		return Response{OK: false, Error: "run key must be 1-128 characters using letters, numbers, '.', '_', ':', or '-'", Kind: "bad_request"}
	}
	snapshot, ok, err := s.loadConnectionSnapshot(req.Name)
	if err != nil {
		return Response{OK: false, Error: err.Error(), Kind: "local_error"}
	}
	if !ok {
		return Response{OK: false, Error: "unknown connection: " + req.Name, Kind: "unknown_connection"}
	}
	p := snapshot.profile
	reg := snapshot.registry
	fingerprint := snapshot.fingerprint
	e := s.entryFor(req.Name)
	s.prepareEntry(e, snapshot)
	command := sshconn.CommandString(req.Command)
	j, err := s.jobForRequest(e, p.Name, command, fingerprint, req.RunKey)
	if err != nil {
		return Response{OK: false, Error: err.Error(), Kind: "run_key_conflict"}
	}
	if req.RunKey != "" && j.expired() {
		return expiredRunResponse(j.id)
	}
	if req.RunKey != "" && j.completed() {
		return s.output(Request{RunID: j.id})
	}
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
	if req.RunKey != "" && j.expired() {
		s.releaseJob(e, j)
		return resp
	}
	if !resp.Running && (saved || j.failed()) {
		if req.RunKey != "" && saved && !j.failed() {
			s.releaseJob(e, j)
		} else {
			s.removeJob(e, p.Name, command, j)
		}
	}
	return resp
}

func (s *server) connFor(e *entry, fingerprint string) (*sshconn.Conn, error) {
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
				_ = conn.ExecRaw(ctx, sweepRemoteCommand(s.currentTime()), maxDeltaBytes)
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
		snapshot := e.snapshot
		e.mu.Unlock()

		conn, err := s.dialSnapshot(snapshot)

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
		e.target = snapshot.profile.Target
		e.lastUsed = time.Now()
		shouldSweep := !e.swept
		e.swept = true
		e.mu.Unlock()

		if shouldSweep {
			ctx, cancel := context.WithTimeout(context.Background(), controlOpTimeout)
			_ = conn.ExecRaw(ctx, sweepRemoteCommand(s.currentTime()), maxDeltaBytes)
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
	return s.runRawStdinTimeout(e, p, reg, cmd, stdin, maxBytes, controlOpTimeout)
}

func (s *server) runRawTimeout(e *entry, p profile.Profile, reg profile.Registry, cmd string, maxBytes int64, timeout time.Duration) (sshconn.RawResult, error) {
	return s.runRawStdinTimeout(e, p, reg, cmd, nil, maxBytes, timeout)
}

func (s *server) runRawStdinTimeout(e *entry, p profile.Profile, reg profile.Registry, cmd string, stdin []byte, maxBytes int64, timeout time.Duration) (sshconn.RawResult, error) {
	e.mu.Lock()
	fingerprint := e.fingerprint
	e.mu.Unlock()
	conn, err := s.connFor(e, fingerprint)
	if err != nil {
		return sshconn.RawResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	res := conn.ExecRawStdin(ctx, cmd, stdin, maxBytes)
	cancel()
	if res.Kind == sshconn.ErrTimeout {
		s.resetConn(e)
		return res, nil
	}
	if res.Kind == sshconn.ErrDisconnect && !res.Started {
		s.resetConn(e)
		conn, err = s.connFor(e, fingerprint)
		if err != nil {
			return sshconn.RawResult{}, err
		}
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		res = conn.ExecRawStdin(ctx, cmd, stdin, maxBytes)
		cancel()
	}
	return res, nil
}

func (s *server) dial(p profile.Profile, reg profile.Registry) (*sshconn.Conn, error) {
	snapshot, err := s.connectionSnapshotFor(p, reg)
	if err != nil {
		return nil, err
	}
	return s.dialSnapshot(snapshot)
}

func (s *server) dialSnapshot(snapshot connectionSnapshot) (*sshconn.Conn, error) {
	p := snapshot.profile
	secret := vault.Secret{}
	secret = snapshot.secret
	opt := sshconn.DialOptions{
		Password:     secret.Password,
		Passphrase:   secret.Passphrase,
		AllowNewHost: false,
		JumpHosts:    snapshot.jumps,
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
func (s *server) jumpSecret(ref string) (password, passphrase string, err error) {
	secret, ok, err := s.secrets.Get(ref)
	if err != nil {
		return "", "", fmt.Errorf("read stored jump credentials %q: %w", ref, err)
	}
	if !ok {
		return "", "", fmt.Errorf("stored jump credentials %q were not found", ref)
	}
	return secret.Password, secret.Passphrase, nil
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
	j, _ := s.jobForRequest(e, profileName, command, fingerprint, "")
	return j
}

func (s *server) jobForRequest(e *entry, profileName, command, fingerprint, runKey string) (*job, error) {
	key := jobKey(profileName, command)
	commandHash := ""
	runKeyHash := ""
	if runKey != "" {
		s.pruneExpiredKeyedJobs(s.currentTime())
		key = keyedJobKey(profileName, runKey)
		commandHash = valueHash(command)
		runKeyHash = valueHash(runKey)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.jobs == nil {
		e.jobs = map[string]*job{}
	}
	if j, ok := e.jobs[key]; ok {
		if runKey != "" && (j.commandHash != commandHash || j.runKeyHash != runKeyHash || j.fingerprint != fingerprint) {
			return nil, errRunKeyConflict
		}
		if j.fingerprint != fingerprint {
			delete(e.jobs, key)
		} else if !j.finished() || j.finalizePending() || runKey != "" {
			return j, nil
		}
	}
	if rec, ok := s.persistedJobByKey(key); ok {
		if runKey != "" && (rec.CommandHash != commandHash || rec.RunKeyHash != runKeyHash || rec.Fingerprint != fingerprint) {
			return nil, errRunKeyConflict
		}
		needsFinalization := rec.Status == jobStatusDone && !retainedRunLogExists(rec.RunID)
		if (rec.Fingerprint == "" || rec.Fingerprint == fingerprint) &&
			(rec.Status == jobStatusStarting || rec.Status == jobStatusRunning || rec.Status == jobStatusFinalizePending ||
				needsFinalization || (runKey != "" && (rec.Status == jobStatusDone || rec.Status == jobStatusExpired))) {
			j := recordToJob(rec)
			if needsFinalization {
				j.status = jobStatusFinalizePending
			}
			j.key = key
			j.command = command
			j.commandHash = commandHash
			j.runKeyHash = runKeyHash
			j.fingerprint = fingerprint
			e.jobs[key] = j
			return j, nil
		}
	}
	j := newJob(command, fingerprint)
	j.key = key
	j.commandHash = commandHash
	j.runKeyHash = runKeyHash
	e.jobs[key] = j
	return j, nil
}

func (s *server) releaseJob(e *entry, j *job) {
	e.mu.Lock()
	if e.jobs[j.key] == j {
		delete(e.jobs, j.key)
	}
	e.mu.Unlock()
}

func (s *server) expireJob(e *entry, profileName string, j *job) error {
	j.mu.Lock()
	j.done = true
	j.status = jobStatusExpired
	j.finishedAt = time.Time{}
	j.durationMS = 0
	j.mu.Unlock()
	if err := s.savePersistedJob(profileName, j); err != nil {
		return err
	}
	s.releaseJob(e, j)
	return nil
}

func (s *server) removeJob(e *entry, profileName, key string, j *job) {
	if j.key != "" {
		key = j.key
	} else {
		key = jobKey(profileName, key)
	}
	e.mu.Lock()
	if e.jobs[key] == j {
		delete(e.jobs, key)
	}
	e.mu.Unlock()
	s.deletePersistedJobByKey(key)
}

func (s *server) list() []HeldInfo {
	status := s.status()
	out := make([]HeldInfo, 0, len(status))
	for _, info := range status {
		out = append(out, HeldInfo{Name: info.Name, Target: info.Target, IdleMS: info.IdleMS})
	}
	return out
}

func (s *server) status() []StatusInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []StatusInfo
	for name, e := range s.entries {
		e.mu.Lock()
		if e.conn == nil {
			e.mu.Unlock()
			continue
		}
		runningJobs := 0
		for _, j := range e.jobs {
			if !j.finished() {
				runningJobs++
			}
		}
		out = append(out, StatusInfo{
			Name: name, Target: e.target, IdleMS: time.Since(e.lastUsed).Milliseconds(), RunningJobs: runningJobs,
		})
		e.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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

func (s *server) prepareEntry(e *entry, snapshot connectionSnapshot) {
	profileName := snapshot.profile.Name
	fingerprint := snapshot.fingerprint
	e.mu.Lock()
	if e.fingerprint == "" {
		e.fingerprint = fingerprint
		e.snapshot = snapshot
		e.mu.Unlock()
		return
	}
	if e.fingerprint == fingerprint {
		e.snapshot = snapshot
		e.mu.Unlock()
		return
	}
	conn := e.conn
	e.conn = nil
	e.target = ""
	e.fingerprint = fingerprint
	e.snapshot = snapshot
	e.jobs = map[string]*job{}
	e.swept = false
	e.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if err := s.deleteUnkeyedPersistedJobs(profileName); err != nil {
		brokerLog.Printf("delete stale jobs for profile %s: %v", profileName, err)
	}
}

func (s *server) loadConnectionSnapshot(name string) (connectionSnapshot, bool, error) {
	var snapshot connectionSnapshot
	var found bool
	err := statelock.WithLock(func() error {
		reg, err := s.store.Load()
		if err != nil {
			return err
		}
		p, ok := reg.Get(name)
		if !ok {
			return nil
		}
		found = true
		snapshot, err = s.connectionSnapshotFor(p, reg)
		return err
	})
	if err == nil && found {
		if err := s.migrateLegacyFingerprints(name, snapshot.fingerprint, snapshot.legacyFingerprint); err != nil {
			return connectionSnapshot{}, false, fmt.Errorf("migrate saved run identity: %w", err)
		}
	}
	return snapshot, found, err
}

func (s *server) connectionSnapshotFor(p profile.Profile, reg profile.Registry) (connectionSnapshot, error) {
	secret := vault.Secret{}
	if p.SecretRef != "" {
		stored, ok, err := s.secrets.Get(p.SecretRef)
		if err != nil {
			return connectionSnapshot{}, fmt.Errorf("read stored credentials for %q: %w", p.Name, err)
		}
		if !ok {
			return connectionSnapshot{}, fmt.Errorf("stored credentials for %q were not found", p.Name)
		}
		secret = stored
	}
	jumps, err := sshconn.ParseJumpChain(p.ProxyJump)
	if err != nil {
		return connectionSnapshot{}, fmt.Errorf("invalid proxy jump %q: %w", p.ProxyJump, err)
	}
	if err := sshconn.EnrichJumpChain(jumps, reg, s.jumpSecret); err != nil {
		return connectionSnapshot{}, err
	}

	legacyCredentials := sha256.Sum256([]byte(secret.Password + "\x00" + secret.Passphrase))
	legacy := sha256.New()
	var current bytes.Buffer
	writeFingerprintField := func(value string) {
		_ = binary.Write(&current, binary.BigEndian, uint64(len(value)))
		_, _ = current.WriteString(value)
	}
	for _, field := range []string{
		p.Target,
		strconv.Itoa(p.Port),
		p.IdentityFile,
		p.ProxyJump,
		secret.Password,
		secret.Passphrase,
	} {
		writeFingerprintField(field)
	}
	for _, field := range []string{
		p.Target,
		strconv.Itoa(p.Port),
		p.IdentityFile,
		p.ProxyJump,
		fmt.Sprintf("%x", legacyCredentials),
	} {
		_, _ = legacy.Write([]byte(field))
		_, _ = legacy.Write([]byte{0})
	}
	for _, jump := range jumps {
		for _, field := range []string{
			jump.User,
			jump.Host,
			strconv.Itoa(jump.Port),
			jump.IdentityFile,
			jump.Password,
			jump.Passphrase,
		} {
			writeFingerprintField(field)
		}
		jumpCredentials := sha256.Sum256([]byte(jump.Password + "\x00" + jump.Passphrase))
		for _, field := range []string{
			jump.User,
			jump.Host,
			strconv.Itoa(jump.Port),
			jump.IdentityFile,
			fmt.Sprintf("%x", jumpCredentials),
		} {
			_, _ = legacy.Write([]byte(field))
			_, _ = legacy.Write([]byte{0})
		}
	}
	fingerprint, err := s.secrets.Fingerprint(current.Bytes())
	if err != nil {
		return connectionSnapshot{}, fmt.Errorf("fingerprint connection state: %w", err)
	}
	return connectionSnapshot{
		profile:           p,
		registry:          reg,
		secret:            secret,
		jumps:             jumps,
		fingerprint:       fingerprint,
		legacyFingerprint: fmt.Sprintf("%x", legacy.Sum(nil)),
	}, nil
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

func (s *server) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}
