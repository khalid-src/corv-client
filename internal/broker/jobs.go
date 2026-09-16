package broker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/khalid-src/corv-client/internal/output"
	"github.com/khalid-src/corv-client/internal/paths"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
)

const (
	maxDeltaBytes          = 512 * 1024
	maxLocalLogBytes       = 20 * 1024 * 1024
	maxInlineOutputBytes   = 32 * 1024
	maxRunningOutputBytes  = 16 * 1024
	retainedLogHeadBytes   = 4 * 1024 * 1024
	retainedLogFrameMargin = 256
	retainedLogTailBytes   = maxLocalLogBytes - retainedLogHeadBytes - retainedLogFrameMargin
	jobTTL                 = 24 * time.Hour
	defaultWait            = 60 * time.Second
	maxWait                = 2 * time.Minute
	pollEvery              = time.Second
	remoteJobDir           = "${TMPDIR:-/tmp}/corv-jobs-$(id -u)"
)

const (
	jobStatusPending         = "pending"
	jobStatusStarting        = "starting"
	jobStatusRunning         = "running"
	jobStatusFinalizePending = "finalize_pending"
	jobStatusFailed          = "failed"
	jobStatusDone            = "done"
	jobStatusExpired         = "expired"
	jobStatusUnknown         = "unknown"
)

type job struct {
	startMu            sync.Mutex
	pollMu             sync.Mutex
	mu                 sync.Mutex
	id                 string
	key                string
	command            string
	commandHash        string
	runKeyHash         string
	fingerprint        string
	fingerprintVersion int
	offset             int64
	started            bool
	startedAt          time.Time
	lastSeenAt         time.Time
	finishedAt         time.Time
	durationMS         int64
	done               bool
	exitCode           int
	startErr           error
	status             string
}

type jobPoll struct {
	delta        string
	emittedBytes int64
	done         bool
	exit         remoteExit
	errResp      *Response
}

type remoteExit struct {
	code       int
	finishedAt time.Time
	duration   time.Duration
}

func newJob(command, fingerprint string) *job {
	return &job{
		id:                 fmt.Sprintf("%016x-%s", time.Now().Unix(), randomHex(8)),
		command:            command,
		fingerprint:        fingerprint,
		fingerprintVersion: connectionFingerprintVersion,
		status:             jobStatusPending,
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

func (j *job) finalizePending() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status == jobStatusFinalizePending
}

func (j *job) completed() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status == jobStatusDone
}

func (j *job) expired() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status == jobStatusExpired
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

	payload := []byte(j.command)
	res, err := s.runRawStdin(e, p, reg, startJobCommand(j.id, int64(len(payload))), payload, maxDeltaBytes)
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
	if strings.Contains(string(res.Stdout), "CORV_UPLOAD_INCOMPLETE") {
		err := errors.New("remote command upload was incomplete; the job was not started")
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
		j.mu.Lock()
		keyed := j.runKeyHash != ""
		terminalKnown := j.done && (j.status == jobStatusFinalizePending || j.status == jobStatusDone)
		exitCode := j.exitCode
		j.mu.Unlock()
		if terminalKnown {
			resp := unavailableRunOutputResponse(j.id, exitCode)
			return jobPoll{errResp: &resp}
		}
		if keyed {
			if err := s.expireJob(e, p.Name, j); err != nil {
				return jobPoll{errResp: &Response{
					OK:    false,
					Error: fmt.Sprintf("save expired run state: %v", err),
					Kind:  "local_error",
					RunID: j.id,
				}}
			}
			resp := expiredRunResponse(j.id)
			return jobPoll{errResp: &resp}
		}
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

	done := false
	exit := remoteExit{}
	if rc != "" {
		var err error
		exit, err = parseRemoteExit(rc)
		if err != nil {
			return jobPoll{errResp: &Response{
				OK: false, Error: "remote run has an invalid exit status", Kind: string(sshconn.ErrSSH), RunID: j.id,
			}}
		}
		done = true
	}

	return jobPoll{
		delta:        delta,
		emittedBytes: emittedBytes,
		done:         done,
		exit:         exit,
	}
}

func (s *server) finishJobPoll(e *entry, p profile.Profile, reg profile.Registry, j *job, poll jobPoll, delta string, emittedBytes int64) (Response, bool) {
	j.mu.Lock()
	j.offset += emittedBytes
	observedAt := time.Now().UTC()
	j.lastSeenAt = observedAt
	if poll.done {
		j.done = true
		j.exitCode = poll.exit.code
		j.status = jobStatusFinalizePending
		if j.finishedAt.IsZero() {
			finishedAt, duration := resolveRemoteTiming(j.startedAt, observedAt, poll.exit)
			j.finishedAt = finishedAt
			j.durationMS = duration.Milliseconds()
		}
	}
	done := j.done
	exitCode := j.exitCode
	runID := j.id
	startedAt := j.startedAt
	finishedAt := j.finishedAt
	durationMS := j.durationMS
	j.mu.Unlock()
	if err := s.savePersistedJob(p.Name, j); err != nil {
		brokerLog.Printf("persist progress for run %s: %v", runID, err)
		if done {
			return Response{
				OK:         false,
				ExitCode:   1,
				Error:      fmt.Sprintf("remote process exited, but Corv could not persist its run state: %v", err),
				Kind:       "local_error",
				Highlights: []string{"Remote output was retained and finalization can be retried with the same command or run id"},
				RunID:      runID,
			}, false
		}
	}

	if done {
		localPath, retained, finalizeErr := s.finalizeRunLog(e, p, reg, j, runMetadata{
			ExitCode:   exitCode,
			OK:         exitCode == 0,
			Connection: p.Name,
			StartedAt:  startedAt.UTC(),
			FinishedAt: finishedAt,
			DurationMS: durationMS,
		})
		lossy := retained.lossy
		cleaned := output.Clean(retained.data)
		rendered := output.Bound(cleaned, output.Options{MaxBytes: maxInlineOutputBytes})
		highlights := output.Signals(cleaned, 8)
		if retained.truncated {
			highlights = append(highlights, fmt.Sprintf("Corv retained log exceeded %d MiB; middle bytes were omitted", maxLocalLogBytes/(1024*1024)))
		}
		if finalizeErr != nil {
			finalizeErr.Stdout = rendered
			finalizeErr.Highlights = append(highlights, finalizeErr.Highlights...)
			finalizeErr.DurationMS = durationMS
			finalizeErr.Truncated = retained.truncated
			finalizeErr.OutputTruncated = rendered != cleaned
			finalizeErr.Lossy = lossy
			finalizeErr.OriginalBytes = retained.originalBytes
			finalizeErr.SavedBytes = int64(len(retained.data))
			finalizeErr.ReturnedBytes = int64(len(rendered))
			return *finalizeErr, false
		}
		return Response{
			OK:              exitCode == 0,
			ExitCode:        exitCode,
			Stdout:          rendered,
			Highlights:      highlights,
			DurationMS:      durationMS,
			RunID:           runID,
			Truncated:       retained.truncated,
			OutputTruncated: rendered != cleaned,
			Lossy:           lossy,
			OriginalBytes:   retained.originalBytes,
			SavedBytes:      int64(len(retained.data)),
			ReturnedBytes:   int64(len(rendered)),
		}, localPath != ""
	}

	lossy := !utf8.ValidString(delta)
	cleaned := output.Clean([]byte(delta))
	rendered := output.Bound(cleaned, output.Options{MaxBytes: maxRunningOutputBytes})
	highlights := output.Signals(cleaned, 8)
	return Response{
		OK:              false,
		ExitCode:        75,
		Stdout:          rendered,
		Highlights:      highlights,
		DurationMS:      time.Since(startedAt).Milliseconds(),
		Running:         true,
		RunID:           runID,
		OutputTruncated: rendered != cleaned,
		Lossy:           lossy,
		ReturnedBytes:   int64(len(rendered)),
	}, false
}

func parseRemoteExit(raw string) (remoteExit, error) {
	fields := strings.Fields(raw)
	if len(fields) == 1 {
		code, err := strconv.Atoi(fields[0])
		if err != nil || code < 0 || code > 255 {
			return remoteExit{}, errors.New("invalid legacy exit status")
		}
		return remoteExit{code: code}, nil
	}
	if len(fields) != 4 || fields[0] != "CORV_RC_V2" {
		return remoteExit{}, errors.New("invalid exit record")
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code < 0 || code > 255 {
		return remoteExit{}, errors.New("invalid exit code")
	}
	finishedUnix, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || finishedUnix <= 0 {
		return remoteExit{}, errors.New("invalid finish time")
	}
	durationSeconds, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || durationSeconds < 0 || durationSeconds > int64((365*24*time.Hour)/time.Second) {
		return remoteExit{}, errors.New("invalid duration")
	}
	return remoteExit{
		code:       code,
		finishedAt: time.Unix(finishedUnix, 0).UTC(),
		duration:   time.Duration(durationSeconds) * time.Second,
	}, nil
}

func resolveRemoteTiming(startedAt, observedAt time.Time, exit remoteExit) (time.Time, time.Duration) {
	if !exit.finishedAt.IsZero() {
		finishedAt := exit.finishedAt
		if finishedAt.Before(startedAt) {
			finishedAt = startedAt.Add(exit.duration)
		}
		if finishedAt.After(observedAt) {
			finishedAt = observedAt
		}
		if finishedAt.Before(startedAt) {
			finishedAt = startedAt
		}
		return finishedAt.UTC(), exit.duration
	}
	if observedAt.Before(startedAt) {
		observedAt = startedAt
	}
	return observedAt.UTC(), observedAt.Sub(startedAt)
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

func sweepRemoteCommand(now time.Time) string {
	cutoffHex := fmt.Sprintf("%016x", now.Add(-jobTTL).Unix())
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); now=$(date +%%s 2>/dev/null) || now=; for rc in \"$dir\"/*.rc; do [ -s \"$rc\" ] || continue; base=${rc##*/}; stem=${base%%.*}; kind= code= finished= duration=; IFS=' ' read -r kind code finished duration < \"$rc\" || true; if [ \"$kind\" = CORV_RC_V2 ]; then case \"$finished\" in ''|*[!0-9]*) continue ;; esac; [ -n \"$now\" ] || continue; cutoff=$((now-%d)); [ \"$finished\" -lt \"$cutoff\" ] || continue; else ts=${stem%%%%-*}; [ \"$ts\" \\< \"%s\" ] || continue; fi; rm -f \"$dir/$stem.sh\" \"$dir/$stem.log\" \"$dir/$stem.rc\"; done", int64(jobTTL/time.Second), cutoffHex)
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

func validRunKey(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == ':' || r == '-' {
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
	cutoff := s.currentTime().Add(-jobTTL)
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
