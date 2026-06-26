package broker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/khalid-src/corv-client/internal/output"
	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
)

const (
	maxDeltaBytes    = 512 * 1024
	maxLocalLogBytes = 20 * 1024 * 1024
	// maxInlineOutputBytes bounds the output returned inline for a finished
	// command; larger output is trimmed middle-out and the full log stays
	// available via corv output.
	maxInlineOutputBytes = 64 * 1024
	jobTTL               = 24 * time.Hour
	defaultWait          = 60 * time.Second
	maxWait              = 2 * time.Minute
	pollEvery            = time.Second
	remoteJobDir         = "${TMPDIR:-/tmp}/corv-jobs-$(id -u)"
)

const (
	jobStatusPending  = "pending"
	jobStatusStarting = "starting"
	jobStatusRunning  = "running"
	jobStatusFailed   = "failed"
	jobStatusDone     = "done"
)

type job struct {
	startMu     sync.Mutex
	pollMu      sync.Mutex
	mu          sync.Mutex
	id          string
	command     string
	fingerprint string
	offset      int64
	started     bool
	startedAt   time.Time
	finishedAt  time.Time
	done        bool
	exitCode    int
	startErr    error
	status      string
}

type jobPoll struct {
	delta        string
	emittedBytes int64
	done         bool
	exitCode     int
	errResp      *Response
}

func newJob(command, fingerprint string) *job {
	return &job{
		id:          fmt.Sprintf("%016x-%s", time.Now().Unix(), randomHex(8)),
		command:     command,
		fingerprint: fingerprint,
		status:      jobStatusPending,
	}
}

func (j *job) finished() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.done
}

func (j *job) failed() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status == jobStatusFailed
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// startError carries the transport ErrorKind of a remote-start failure so the
// caller can report it without re-classifying the wrapped message.
type startError struct {
	kind sshconn.ErrorKind
	msg  string
}

func (e *startError) Error() string { return e.msg }

func (s *server) ensureJobStarted(e *entry, p profile.Profile, reg profile.Registry, j *job) error {
	j.startMu.Lock()
	defer j.startMu.Unlock()

	j.mu.Lock()
	if j.started {
		err := j.startErr
		j.mu.Unlock()
		return err
	}
	j.started = true
	j.startedAt = time.Now()
	j.status = jobStatusStarting
	j.mu.Unlock()

	if err := s.savePersistedJob(p.Name, j); err != nil {
		j.mu.Lock()
		j.started = false
		j.startedAt = time.Time{}
		j.status = jobStatusPending
		j.mu.Unlock()
		return fmt.Errorf("persist remote job before start: %w", err)
	}

	res, err := s.runRawStdin(e, p, reg, startJobCommand(j.id), []byte(j.command), maxDeltaBytes)
	if err != nil {
		s.failJobStart(p.Name, j, 1, err)
		return err
	}
	if res.Kind == sshconn.ErrDisconnect {
		j.mu.Lock()
		j.status = jobStatusRunning
		j.mu.Unlock()
		if err := s.savePersistedJob(p.Name, j); err != nil {
			brokerLog.Printf("persist uncertain remote start for run %s: %v", j.id, err)
		}
		return errStartUncertain
	}
	if res.Kind == sshconn.ErrTimeout {
		j.mu.Lock()
		j.status = jobStatusRunning
		j.mu.Unlock()
		if err := s.savePersistedJob(p.Name, j); err != nil {
			brokerLog.Printf("persist uncertain remote start for run %s: %v", j.id, err)
		}
		return errStartUncertain
	}
	if strings.Contains(string(res.Stdout), "CORV_NO_POSIX") {
		err := errors.New("remote shell lacks required POSIX tools")
		s.failJobStart(p.Name, j, res.ExitCode, err)
		return err
	}
	if !res.OK() || !strings.Contains(string(res.Stdout), "CORV_STARTED") {
		msg := fmt.Sprintf("start remote job failed: %s", strings.TrimSpace(string(res.Stderr)))
		if res.Kind != sshconn.ErrNone {
			msg = fmt.Sprintf("start remote job: %s", res.Kind)
		}
		// Carry the transport kind so the caller reports it directly instead of
		// re-classifying the wrapped message (which would lose, e.g.,
		// resource_exhausted and report a generic ssh_error).
		err := &startError{kind: res.Kind, msg: msg}
		s.failJobStart(p.Name, j, res.ExitCode, err)
		return err
	}
	j.mu.Lock()
	j.status = jobStatusRunning
	j.mu.Unlock()
	if err := s.savePersistedJob(p.Name, j); err != nil {
		brokerLog.Printf("persist started remote job %s: %v", j.id, err)
	}
	return nil
}

func (s *server) failJobStart(profileName string, j *job, exitCode int, err error) {
	j.mu.Lock()
	j.done = true
	j.exitCode = exitCode
	j.startErr = err
	j.status = jobStatusFailed
	j.mu.Unlock()
	if saveErr := s.savePersistedJob(profileName, j); saveErr != nil {
		brokerLog.Printf("persist failed remote start for run %s: %v", j.id, saveErr)
	}
}

func (s *server) watchJob(e *entry, p profile.Profile, reg profile.Registry, j *job, wait time.Duration) (Response, bool) {
	j.pollMu.Lock()
	defer j.pollMu.Unlock()

	deadline := time.Now().Add(wait)
	var delta strings.Builder
	var emittedBytes int64

	for {
		remaining := int64(maxDeltaBytes) - emittedBytes
		if remaining <= 0 {
			return s.finishJobPoll(e, p, reg, j, jobPoll{}, delta.String(), emittedBytes)
		}
		poll := s.pollJob(e, p, reg, j, emittedBytes, remaining)
		if poll.errResp != nil {
			return *poll.errResp, false
		}
		delta.WriteString(poll.delta)
		emittedBytes += poll.emittedBytes
		if poll.done || emittedBytes >= int64(maxDeltaBytes) || time.Now().After(deadline) {
			return s.finishJobPoll(e, p, reg, j, poll, delta.String(), emittedBytes)
		}
		sleep := time.Until(deadline)
		if sleep > pollEvery {
			sleep = pollEvery
		}
		if sleep > 0 {
			time.Sleep(sleep)
		}
	}
}

func (s *server) pollJob(e *entry, p profile.Profile, reg profile.Registry, j *job, pendingBytes, maxRead int64) jobPoll {
	j.mu.Lock()
	offset := j.offset + pendingBytes
	j.mu.Unlock()

	state, errResp := s.readRemoteState(e, p, reg, j.id)
	if errResp != nil {
		return jobPoll{errResp: errResp}
	}
	if state == "missing" {
		err := errors.New("remote job did not start or its state was lost")
		j.mu.Lock()
		j.done = true
		j.exitCode = 1
		j.startErr = err
		j.status = jobStatusFailed
		j.mu.Unlock()
		if saveErr := s.savePersistedJob(p.Name, j); saveErr != nil {
			brokerLog.Printf("persist missing remote job %s: %v", j.id, saveErr)
		}
		return jobPoll{errResp: &Response{
			OK:       false,
			ExitCode: 1,
			Error:    err.Error(),
			Kind:     string(sshconn.ErrSSH),
			RunID:    j.id,
		}}
	}

	delta, emittedBytes, errResp := s.readRemoteDelta(e, p, reg, j.id, offset, maxRead)
	if errResp != nil {
		return jobPoll{errResp: errResp}
	}

	rc, errResp := s.readRemoteRC(e, p, reg, j.id)
	if errResp != nil {
		return jobPoll{errResp: errResp}
	}

	exitCode := 0
	done := false
	if rc != "" {
		code, err := strconv.Atoi(strings.TrimSpace(rc))
		if err != nil {
			code = 1
		}
		done = true
		exitCode = code
	}

	return jobPoll{
		delta:        delta,
		emittedBytes: emittedBytes,
		done:         done,
		exitCode:     exitCode,
	}
}

func (s *server) finishJobPoll(e *entry, p profile.Profile, reg profile.Registry, j *job, poll jobPoll, delta string, emittedBytes int64) (Response, bool) {
	j.mu.Lock()
	j.offset += emittedBytes
	if poll.done {
		j.done = true
		j.exitCode = poll.exitCode
		j.status = jobStatusDone
		if j.finishedAt.IsZero() {
			j.finishedAt = time.Now().UTC()
		}
	}
	done := j.done
	exitCode := j.exitCode
	runID := j.id
	startedAt := j.startedAt
	finishedAt := j.finishedAt
	j.mu.Unlock()
	if err := s.savePersistedJob(p.Name, j); err != nil {
		brokerLog.Printf("persist progress for run %s: %v", runID, err)
	}

	cleaned := output.Clean([]byte(delta))
	highlights := output.Signals(cleaned, 8)

	if done {
		// A finished command returns its output in full up to a generous byte
		// budget, so callers rarely need a second corv output call; only large
		// output is trimmed middle-out.
		bounded := output.Bound(cleaned, output.Options{MaxBytes: maxInlineOutputBytes})
		localPath, truncated := s.copyAndCleanupRemote(e, p, reg, runID, runMetadata{
			ExitCode:   exitCode,
			OK:         exitCode == 0,
			Connection: p.Name,
			StartedAt:  startedAt.UTC(),
			FinishedAt: finishedAt,
		})
		if truncated {
			highlights = append(highlights, fmt.Sprintf("Corv saved log was truncated at %d MiB", maxLocalLogBytes/(1024*1024)))
		}
		if localPath == "" {
			highlights = append(highlights, "Corv could not save the run log locally; remote copy retained")
		}
		return Response{
			OK:         exitCode == 0,
			ExitCode:   exitCode,
			Stdout:     bounded,
			Highlights: highlights,
			DurationMS: time.Since(startedAt).Milliseconds(),
			RunID:      runID,
		}, localPath != ""
	}

	// A still-running command returns a budget-bounded peek; the full log is
	// retrievable with corv output once it finishes.
	return Response{
		OK:         false,
		ExitCode:   75,
		Stdout:     output.Bound(cleaned, output.Options{MaxBytes: maxInlineOutputBytes}),
		Highlights: highlights,
		DurationMS: time.Since(startedAt).Milliseconds(),
		Running:    true,
		RunID:      runID,
	}, false
}

func (s *server) readRemoteDelta(e *entry, p profile.Profile, reg profile.Registry, id string, offset, maxRead int64) (string, int64, *Response) {
	res, err := s.runRaw(e, p, reg, tailJobCommand(id, offset, maxRead), maxRead)
	if err != nil {
		return "", 0, &Response{OK: false, Error: err.Error(), Kind: string(sshconn.Classify(err)), RunID: id}
	}
	if !res.OK() {
		return "", 0, &Response{OK: false, ExitCode: res.ExitCode, Kind: string(res.Kind), Error: strings.TrimSpace(string(res.Stderr)), RunID: id}
	}
	return string(res.Stdout), int64(len(res.Stdout)), nil
}

func (s *server) readRemoteRC(e *entry, p profile.Profile, reg profile.Registry, id string) (string, *Response) {
	res, err := s.runRaw(e, p, reg, rcJobCommand(id), maxDeltaBytes)
	if err != nil {
		return "", &Response{OK: false, Error: err.Error(), Kind: string(sshconn.Classify(err)), RunID: id}
	}
	if !res.OK() {
		return "", &Response{OK: false, ExitCode: res.ExitCode, Kind: string(res.Kind), Error: strings.TrimSpace(string(res.Stderr)), RunID: id}
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

func (s *server) readRemoteState(e *entry, p profile.Profile, reg profile.Registry, id string) (string, *Response) {
	res, err := s.runRaw(e, p, reg, stateJobCommand(id), maxDeltaBytes)
	if err != nil {
		return "", &Response{OK: false, Error: err.Error(), Kind: string(sshconn.Classify(err)), RunID: id}
	}
	if !res.OK() {
		return "", &Response{OK: false, ExitCode: res.ExitCode, Kind: string(res.Kind), Error: strings.TrimSpace(string(res.Stderr)), RunID: id}
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

func startJobCommand(id string) string {
	return fmt.Sprintf(
		"umask 077; if ! command -v id >/dev/null 2>&1 || ! command -v tail >/dev/null 2>&1 || ! command -v head >/dev/null 2>&1; then echo CORV_NO_POSIX; exit 127; fi; if command -v setsid >/dev/null 2>&1; then runner=setsid; elif command -v nohup >/dev/null 2>&1; then runner=nohup; else echo CORV_NO_POSIX; exit 127; fi; dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); mkdir -p \"$dir\" && chmod 700 \"$dir\" && cat > \"$dir/%s.sh\" && : > \"$dir/%s.log\" && { \"$runner\" sh -c 'sh \"$0\" > \"$1\" 2>&1; echo $? > \"$2\"' \"$dir/%s.sh\" \"$dir/%s.log\" \"$dir/%s.rc\" >/dev/null 2>&1 & echo CORV_STARTED; }",
		id, id, id, id, id,
	)
}

func remoteLogPath(id string) string { return remoteJobDir + "/" + id + ".log" }
func remoteRCPath(id string) string  { return remoteJobDir + "/" + id + ".rc" }

func tailJobCommand(id string, offset, maxBytes int64) string {
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); tail -c +%d \"$dir/%s.log\" 2>/dev/null | head -c %d || true", offset+1, id, maxBytes)
}

func rcJobCommand(id string) string {
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); cat \"$dir/%s.rc\" 2>/dev/null || true", id)
}

func stateJobCommand(id string) string {
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); if [ -f \"$dir/%s.rc\" ]; then printf done; elif [ -f \"$dir/%s.log\" ]; then printf running; else printf missing; fi", id, id)
}

func cleanupJobCommand(id string) string {
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); rm -f \"$dir/%s.sh\" \"$dir/%s.log\" \"$dir/%s.rc\"", id, id, id)
}

func (s *server) copyAndCleanupRemote(e *entry, p profile.Profile, reg profile.Registry, id string, metadata runMetadata) (string, bool) {
	// Cleanup on reattach; startup sweep removes abandoned jobs after jobTTL.
	fetchLimit := int64(maxLocalLogBytes + 1)
	res, err := s.runRaw(e, p, reg, fullLogCommand(id), fetchLimit)
	truncated := false
	if err == nil && res.OK() {
		data := res.Stdout
		if len(data) > maxLocalLogBytes {
			truncated = true
			data = data[:maxLocalLogBytes]
		}
		metadata.Truncated = truncated
		path := s.saveRunLog(id, data, metadata)
		if path != "" {
			_, _ = s.runRaw(e, p, reg, cleanupJobCommand(id), maxDeltaBytes)
		}
		return path, truncated
	}
	return "", false
}

func fullLogCommand(id string) string {
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); cat \"$dir/%s.log\" 2>/dev/null | head -c %d || true", id, maxLocalLogBytes+1)
}

type runMetadata struct {
	ExitCode   int       `json:"exit_code"`
	OK         bool      `json:"ok"`
	Connection string    `json:"connection"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Truncated  bool      `json:"truncated"`
}

func (s *server) saveRunLog(id string, data []byte, metadata runMetadata) string {
	p, err := pathsDefault()
	if err != nil {
		return ""
	}
	if err := os.MkdirAll(p.RunsDir, 0o700); err != nil {
		return ""
	}
	path := filepath.Join(p.RunsDir, id+".log")
	if metadata.Truncated {
		data = append(data, []byte(fmt.Sprintf("\n[Corv log truncated at %d MiB]\n", maxLocalLogBytes/(1024*1024)))...)
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return ""
	}
	metaPath := filepath.Join(p.RunsDir, id+".meta.json")
	logTmp := path + ".tmp"
	metaTmp := metaPath + ".tmp"
	if err := os.WriteFile(logTmp, data, 0o600); err != nil {
		return ""
	}
	if err := os.WriteFile(metaTmp, meta, 0o600); err != nil {
		_ = os.Remove(logTmp)
		return ""
	}
	if err := os.Rename(metaTmp, metaPath); err != nil {
		_ = os.Remove(logTmp)
		_ = os.Remove(metaTmp)
		return ""
	}
	if err := os.Rename(logTmp, path); err != nil {
		_ = os.Remove(logTmp)
		_ = os.Remove(metaPath)
		return ""
	}
	return path
}

// readRunFile reads a saved run file, retrying briefly on a Windows sharing
// violation: a concurrent finalizer renaming the file into place can momentarily
// block an open, unlike POSIX where rename is transparent to readers. ErrNotExist
// is returned immediately so the caller can finalize.
func readRunFile(path string) ([]byte, error) {
	var err error
	for i := 0; i < 50; i++ {
		var data []byte
		data, err = os.ReadFile(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return data, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, err
}

func (s *server) output(req Request) Response {
	if !validRunID(req.RunID) {
		return Response{OK: false, Error: "valid run id is required"}
	}
	p, err := pathsDefault()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	path := filepath.Join(p.RunsDir, req.RunID+".log")
	data, err := readRunFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if resp, done := s.finalizeOutput(req.RunID); done {
				return resp
			}
			data, err = readRunFile(path)
			if errors.Is(err, os.ErrNotExist) {
				return Response{OK: false, Error: "unknown run id", Kind: "bad_request", RunID: req.RunID}
			}
			if err != nil {
				return Response{OK: false, Error: err.Error(), RunID: req.RunID}
			}
		} else {
			return Response{OK: false, Error: err.Error(), RunID: req.RunID}
		}
	}
	text := output.Clean(data)
	if req.Pattern != "" {
		text = grepText(text, req.Pattern)
	}
	resp := Response{
		OK:         true,
		Stdout:     output.Bound(text, output.Options{Unbounded: true}),
		Highlights: output.Signals(text, 8),
		RunID:      req.RunID,
	}
	metaData, err := readRunFile(filepath.Join(p.RunsDir, req.RunID+".meta.json"))
	if errors.Is(err, os.ErrNotExist) {
		return resp
	}
	if err != nil {
		return Response{OK: false, Error: err.Error(), RunID: req.RunID}
	}
	var metadata runMetadata
	if err := json.Unmarshal(metaData, &metadata); err != nil {
		return Response{OK: false, Error: fmt.Sprintf("read run metadata: %v", err), RunID: req.RunID}
	}
	if metadata.Connection == "" || metadata.StartedAt.IsZero() || metadata.FinishedAt.IsZero() ||
		metadata.FinishedAt.Before(metadata.StartedAt) {
		return Response{OK: false, Error: "read run metadata: invalid metadata", RunID: req.RunID}
	}
	resp.OK = metadata.OK
	resp.ExitCode = metadata.ExitCode
	resp.Connection = metadata.Connection
	resp.StartedAt = &metadata.StartedAt
	resp.FinishedAt = &metadata.FinishedAt
	resp.Truncated = metadata.Truncated
	if metadata.Truncated {
		resp.Highlights = append(resp.Highlights, fmt.Sprintf("saved log was truncated at %d MiB; output is incomplete", maxLocalLogBytes/(1024*1024)))
	}
	resp.RunMetadata = true
	return resp
}

func (s *server) finalizeOutput(runID string) (Response, bool) {
	rec, ok := s.persistedJobByRunID(runID)
	if !ok {
		return Response{}, false
	}
	reg, err := s.store.Load()
	if err != nil {
		return Response{OK: false, Error: err.Error(), RunID: runID}, true
	}
	p, ok := reg.Get(rec.Profile)
	if !ok {
		return Response{OK: false, Error: "saved connection for this run no longer exists", RunID: runID}, true
	}
	fingerprint, err := s.profileFingerprint(p, reg)
	if err != nil {
		return Response{OK: false, Error: err.Error(), RunID: runID}, true
	}
	if rec.Fingerprint != "" && rec.Fingerprint != fingerprint {
		return Response{OK: false, Error: "saved connection changed; cannot finalize the previous remote run safely", RunID: runID}, true
	}

	e := s.entryFor(p.Name)
	s.prepareEntry(e, p.Name, fingerprint)
	// Register the rebuilt job so concurrent finalizers and a watching exec
	// share one *job (and one pollMu); otherwise two callers could each fetch
	// and clean up the same remote run and race to overwrite the saved log.
	e.mu.Lock()
	j := e.jobs[rec.Command]
	if j == nil || j.id != runID {
		j = recordToJob(rec)
		j.fingerprint = fingerprint
		e.jobs[rec.Command] = j
	}
	e.mu.Unlock()

	j.pollMu.Lock()
	defer j.pollMu.Unlock()

	// A finalizer that held pollMu before us may have already saved the log;
	// yield to output()'s re-read instead of re-fetching and overwriting it.
	if pp, perr := pathsDefault(); perr == nil {
		if _, serr := os.Stat(filepath.Join(pp.RunsDir, runID+".log")); serr == nil {
			return Response{}, false
		}
	}

	state, errResp := s.readRemoteState(e, p, reg, runID)
	if errResp != nil {
		return *errResp, true
	}
	if state == "running" {
		return Response{
			OK:       false,
			ExitCode: 75,
			Error:    "run still in progress; re-run the command or corv output later",
			Running:  true,
			RunID:    runID,
		}, true
	}
	if state != "done" {
		return Response{OK: false, Error: "run state expired before its log could be saved", RunID: runID}, true
	}
	rc, errResp := s.readRemoteRC(e, p, reg, runID)
	if errResp != nil {
		return *errResp, true
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(rc))
	if err != nil {
		return Response{OK: false, Error: "remote run has an invalid exit status", RunID: runID}, true
	}

	j.mu.Lock()
	j.done = true
	j.exitCode = exitCode
	j.status = jobStatusDone
	if j.finishedAt.IsZero() {
		j.finishedAt = time.Now().UTC()
	}
	startedAt := j.startedAt
	finishedAt := j.finishedAt
	j.mu.Unlock()
	if err := s.savePersistedJob(p.Name, j); err != nil {
		return Response{OK: false, Error: fmt.Sprintf("save run state: %v", err), RunID: runID}, true
	}

	localPath, _ := s.copyAndCleanupRemote(e, p, reg, runID, runMetadata{
		ExitCode:   exitCode,
		OK:         exitCode == 0,
		Connection: p.Name,
		StartedAt:  startedAt.UTC(),
		FinishedAt: finishedAt,
	})
	if localPath == "" {
		return Response{
			OK:    false,
			Error: "run finished, but Corv could not save its log locally; remote copy retained",
			RunID: runID,
		}, true
	}
	s.removeJob(e, p.Name, rec.Command, j)
	return Response{}, false
}

func grepText(text, pattern string) string {
	var b strings.Builder
	if re, err := regexp.Compile(pattern); err == nil {
		for _, line := range strings.Split(text, "\n") {
			if re.MatchString(line) {
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
		return b.String()
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, pattern) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// waitWindow returns the broker's default wait window from its own CORV_WAIT,
// used when a request does not carry one.
func waitWindow() time.Duration {
	return parseWait(os.Getenv("CORV_WAIT"), defaultWait)
}

// parseWait interprets a CORV_WAIT value (bare seconds or a Go duration),
// capped at maxWait. An empty or invalid value returns fallback.
func parseWait(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	var d time.Duration
	if seconds, err := strconv.ParseUint(raw, 10, 63); err == nil {
		if seconds > uint64(maxWait/time.Second) {
			return maxWait
		}
		d = time.Duration(seconds) * time.Second
	} else {
		var err error
		d, err = time.ParseDuration(raw)
		if err != nil || d < 0 {
			return fallback
		}
	}
	if d > maxWait {
		return maxWait
	}
	return d
}

func sweepRemoteCommand() string {
	cutoff := fmt.Sprintf("%016x", time.Now().Add(-jobTTL).Unix())
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); command -v find >/dev/null 2>&1 || exit 0; for f in \"$dir\"/*.sh \"$dir\"/*.log \"$dir\"/*.rc; do [ -e \"$f\" ] || continue; base=${f##*/}; stem=${base%%.*}; log=\"$dir/$stem.log\"; recent=$(find \"$log\" -mtime -1 -print 2>/dev/null); [ -n \"$recent\" ] && continue; ts=${base%%-*}; [ \"$ts\" \\< \"%s\" ] && rm -f \"$f\"; done", cutoff)
}

func validRunID(id string) bool {
	if len(id) < 18 || len(id) > 80 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'f') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *server) sweepLocalRuns() {
	p, err := pathsDefault()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(p.RunsDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-jobTTL)
	for _, ent := range entries {
		if ent.IsDir() || (filepath.Ext(ent.Name()) != ".log" && !strings.HasSuffix(ent.Name(), ".meta.json")) {
			continue
		}
		path := filepath.Join(p.RunsDir, ent.Name())
		info, err := ent.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(path)
		}
	}
}

var pathsDefault = paths.Default
