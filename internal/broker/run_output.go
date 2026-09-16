package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/khalid-src/corv-client/internal/output"
	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
)

type retainedLog struct {
	data          []byte
	originalBytes int64
	truncated     bool
	lossy         bool
	missing       bool
}

type retainedLogError struct {
	kind string
	err  error
}

func (e *retainedLogError) Error() string {
	return e.err.Error()
}

func (s *server) copyRemoteLog(e *entry, p profile.Profile, reg profile.Registry, id string, metadata runMetadata) (string, retainedLog, error) {
	fetchLimit := int64(maxLocalLogBytes + retainedLogFrameMargin)
	res, err := s.runRawTimeout(e, p, reg, fullLogCommand(id), fetchLimit, fullLogTransferTimeout)
	if err != nil {
		return "", retainedLog{}, &retainedLogError{
			kind: string(sshconn.Classify(err)),
			err:  fmt.Errorf("fetch retained run log: %w", err),
		}
	}
	if !res.OK() {
		kind := res.Kind
		if kind == sshconn.ErrNone {
			kind = sshconn.ErrSSH
		}
		detail := strings.TrimSpace(string(res.Stderr))
		if detail == "" {
			detail = fmt.Sprintf("remote log command exited with status %d", res.ExitCode)
		}
		return "", retainedLog{}, &retainedLogError{
			kind: string(kind),
			err:  fmt.Errorf("fetch retained run log: %s", detail),
		}
	}
	retained, err := parseRetainedLog(res.Stdout)
	if err != nil {
		return "", retainedLog{}, &retainedLogError{
			kind: string(sshconn.ErrSSH),
			err:  fmt.Errorf("read retained run log: %w", err),
		}
	}
	if retained.missing {
		return "", retained, nil
	}
	metadata.Truncated = retained.truncated
	metadata.OriginalBytes = retained.originalBytes
	metadata.SavedBytes = int64(len(retained.data))
	retained.lossy = !utf8.Valid(retained.data)
	metadata.Lossy = retained.lossy
	path, err := s.saveRunLog(id, retained.data, metadata)
	if err != nil {
		return "", retained, &retainedLogError{
			kind: "local_error",
			err:  fmt.Errorf("save retained run log locally: %w", err),
		}
	}
	return path, retained, nil
}

func (s *server) cleanupRemoteJob(e *entry, p profile.Profile, reg profile.Registry, id string) {
	res, err := s.runRaw(e, p, reg, cleanupJobCommand(id), maxDeltaBytes)
	if err != nil {
		brokerLog.Printf("clean remote files for run %s: %v", id, err)
		return
	}
	if !res.OK() {
		brokerLog.Printf("clean remote files for run %s: remote command exited with status %d", id, res.ExitCode)
	}
}

func fullLogCommand(id string) string {
	return fmt.Sprintf(
		"dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); log=\"$dir/%s.log\"; if [ ! -f \"$log\" ]; then printf 'CORV_LOG_MISSING\\n'; exit 0; fi; size=$(wc -c < \"$log\") || exit 1; size=$((size + 0)); if [ \"$size\" -le %d ]; then printf 'CORV_LOG_V1 %%s %%s 0\\n' \"$size\" \"$size\"; cat \"$log\"; else printf 'CORV_LOG_V1 %%s %d %d\\n' \"$size\"; head -c %d \"$log\"; tail -c %d \"$log\"; fi",
		id, maxLocalLogBytes, retainedLogHeadBytes, retainedLogTailBytes, retainedLogHeadBytes, retainedLogTailBytes,
	)
}

func parseRetainedLog(raw []byte) (retainedLog, error) {
	if bytes.Equal(raw, []byte("CORV_LOG_MISSING\n")) {
		return retainedLog{missing: true}, nil
	}
	lineEnd := bytes.IndexByte(raw, '\n')
	if lineEnd < 0 || lineEnd >= retainedLogFrameMargin {
		return retainedLog{}, errors.New("invalid remote log frame")
	}
	fields := strings.Fields(string(raw[:lineEnd]))
	if len(fields) != 4 || fields[0] != "CORV_LOG_V1" {
		return retainedLog{}, errors.New("invalid remote log frame")
	}
	originalBytes, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return retainedLog{}, errors.New("invalid remote log sizes")
	}
	headBytes, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return retainedLog{}, errors.New("invalid remote log sizes")
	}
	tailBytes, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return retainedLog{}, errors.New("invalid remote log sizes")
	}
	if originalBytes < 0 || headBytes < 0 || tailBytes < 0 ||
		headBytes+tailBytes > int64(maxLocalLogBytes) ||
		originalBytes < headBytes+tailBytes {
		return retainedLog{}, errors.New("invalid remote log sizes")
	}
	payload := raw[lineEnd+1:]
	if int64(len(payload)) != headBytes+tailBytes {
		return retainedLog{}, errors.New("incomplete remote log frame")
	}
	if originalBytes == int64(len(payload)) {
		return retainedLog{data: append([]byte(nil), payload...), originalBytes: originalBytes}, nil
	}

	omitted := originalBytes - headBytes - tailBytes
	marker := []byte(fmt.Sprintf("\n[Corv retained first %d bytes and last %d bytes; %d bytes omitted]\n", headBytes, tailBytes, omitted))
	if len(payload)+len(marker) > maxLocalLogBytes {
		return retainedLog{}, errors.New("retained log exceeds local limit")
	}
	data := make([]byte, 0, len(payload)+len(marker))
	data = append(data, payload[:headBytes]...)
	data = append(data, marker...)
	data = append(data, payload[headBytes:]...)
	return retainedLog{data: data, originalBytes: originalBytes, truncated: true}, nil
}

type runMetadata struct {
	ExitCode      int       `json:"exit_code"`
	OK            bool      `json:"ok"`
	Connection    string    `json:"connection"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	DurationMS    int64     `json:"duration_ms,omitempty"`
	Truncated     bool      `json:"truncated"`
	Lossy         bool      `json:"lossy,omitempty"`
	OriginalBytes int64     `json:"original_bytes,omitempty"`
	SavedBytes    int64     `json:"saved_bytes,omitempty"`
}

func (s *server) saveRunLog(id string, data []byte, metadata runMetadata) (string, error) {
	p, err := pathsDefault()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(p.RunsDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(p.RunsDir, id+".log")
	meta, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	metaPath := filepath.Join(p.RunsDir, id+".meta.json")
	if err := writeJobFile(metaPath, meta, 0o600); err != nil {
		return "", err
	}
	if err := writeJobFile(path, data, 0o600); err != nil {
		_ = os.Remove(metaPath)
		return "", err
	}
	return path, nil
}

func (s *server) finalizeRunLog(e *entry, p profile.Profile, reg profile.Registry, j *job, metadata runMetadata) (string, retainedLog, *Response) {
	runID := j.id
	localPath, retained, err := s.copyRemoteLog(e, p, reg, runID, metadata)
	if err != nil {
		kind := "local_error"
		var logErr *retainedLogError
		if errors.As(err, &logErr) && logErr.kind != "" {
			kind = logErr.kind
		}
		resp := Response{
			OK:         false,
			ExitCode:   1,
			Error:      err.Error(),
			Kind:       kind,
			Highlights: []string{"Remote output was retained and finalization can be retried with the same command or run id"},
			RunID:      runID,
		}
		if kind == "local_error" && strings.Contains(err.Error(), "save retained run log locally") {
			resp.Highlights = append(resp.Highlights, "Corv could not save the run log locally; remote copy retained")
		}
		return "", retained, &resp
	}
	if retained.missing {
		resp := unavailableRunOutputResponse(runID, metadata.ExitCode)
		return "", retained, &resp
	}

	j.mu.Lock()
	j.status = jobStatusDone
	j.mu.Unlock()
	if err := s.savePersistedJob(p.Name, j); err != nil {
		j.mu.Lock()
		j.status = jobStatusFinalizePending
		j.mu.Unlock()
		resp := Response{
			OK:         false,
			ExitCode:   1,
			Error:      fmt.Sprintf("retained run log was saved, but Corv could not persist its final state: %v", err),
			Kind:       "local_error",
			Highlights: []string{"Remote output was retained and finalization can be retried with the same command or run id"},
			RunID:      runID,
		}
		return "", retained, &resp
	}

	s.cleanupRemoteJob(e, p, reg, runID)
	return localPath, retained, nil
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

func retainedRunLogExists(runID string) bool {
	p, err := pathsDefault()
	if err != nil {
		return false
	}
	info, err := os.Stat(filepath.Join(p.RunsDir, runID+".log"))
	return err == nil && !info.IsDir()
}

func (s *server) output(req Request) Response {
	if !validRunID(req.RunID) {
		return Response{OK: false, Error: "valid run id is required", Kind: "bad_request"}
	}
	p, err := pathsDefault()
	if err != nil {
		return Response{OK: false, Error: err.Error(), Kind: "local_error", RunID: req.RunID}
	}
	path := filepath.Join(p.RunsDir, req.RunID+".log")
	data, err := readRunFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if resp, done := s.finalizeOutput(req.RunID, req.Pattern); done {
				return resp
			}
			data, err = readRunFile(path)
			if errors.Is(err, os.ErrNotExist) {
				return Response{OK: false, Error: "unknown run id", Kind: "bad_request", RunID: req.RunID}
			}
			if err != nil {
				return Response{OK: false, Error: err.Error(), Kind: "local_error", RunID: req.RunID}
			}
		} else {
			return Response{OK: false, Error: err.Error(), Kind: "local_error", RunID: req.RunID}
		}
	}
	lossy := !utf8.Valid(data)
	text := output.Clean(data)
	if req.Pattern != "" {
		text = grepText(text, req.Pattern)
	}
	rendered := output.Bound(text, output.Options{MaxBytes: maxInlineOutputBytes})
	resp := Response{
		OK:              true,
		Stdout:          rendered,
		Highlights:      output.Signals(text, 8),
		RunID:           req.RunID,
		OutputTruncated: rendered != text,
		OriginalBytes:   int64(len(data)),
		SavedBytes:      int64(len(data)),
		ReturnedBytes:   int64(len(rendered)),
		Lossy:           lossy,
	}
	metaData, err := readRunFile(filepath.Join(p.RunsDir, req.RunID+".meta.json"))
	if errors.Is(err, os.ErrNotExist) {
		return resp
	}
	if err != nil {
		return Response{OK: false, Error: err.Error(), Kind: "local_error", RunID: req.RunID}
	}
	var metadata runMetadata
	if err := json.Unmarshal(metaData, &metadata); err != nil {
		return Response{OK: false, Error: fmt.Sprintf("read run metadata: %v", err), Kind: "local_error", RunID: req.RunID}
	}
	if metadata.Connection == "" || metadata.StartedAt.IsZero() || metadata.FinishedAt.IsZero() ||
		metadata.FinishedAt.Before(metadata.StartedAt) {
		return Response{OK: false, Error: "read run metadata: invalid metadata", Kind: "local_error", RunID: req.RunID}
	}
	resp.OK = metadata.OK
	resp.ExitCode = metadata.ExitCode
	resp.Connection = metadata.Connection
	resp.StartedAt = &metadata.StartedAt
	resp.FinishedAt = &metadata.FinishedAt
	resp.DurationMS = metadata.DurationMS
	resp.Truncated = metadata.Truncated
	resp.Lossy = resp.Lossy || metadata.Lossy
	if metadata.OriginalBytes > 0 {
		resp.OriginalBytes = metadata.OriginalBytes
	}
	if metadata.SavedBytes > 0 {
		resp.SavedBytes = metadata.SavedBytes
	}
	if metadata.Truncated {
		resp.Highlights = append(resp.Highlights, fmt.Sprintf("retained log exceeded %d MiB; middle bytes were omitted", maxLocalLogBytes/(1024*1024)))
	}
	resp.RunMetadata = true
	if s.audit != nil {
		if err := s.audit.Complete(req.RunID, metadata.StartedAt, metadata.FinishedAt, metadata.ExitCode); err != nil {
			brokerLog.Printf("record completion for run %s: %v", req.RunID, err)
		}
	}
	return resp
}

func (s *server) listRuns() ([]RunInfo, error) {
	now := s.currentTime()
	s.pruneExpiredKeyedJobs(now)
	runsByID := make(map[string]RunInfo)
	s.jobsMu.Lock()
	for _, rec := range s.jobs.Jobs {
		running := rec.Status == jobStatusStarting || rec.Status == jobStatusRunning
		status := rec.Status
		observedAt := time.Unix(rec.StartedAt, 0)
		if rec.LastSeenAt != 0 {
			observedAt = time.Unix(0, rec.LastSeenAt)
		}
		if running && observedAt.Before(now.Add(-jobTTL)) {
			status = jobStatusUnknown
			running = false
		}
		var exitCode *int
		if running {
			code := 75
			exitCode = &code
		} else if status != jobStatusUnknown && status != jobStatusExpired {
			code := rec.ExitCode
			exitCode = &code
		}
		info := RunInfo{
			RunID:      rec.RunID,
			Connection: rec.Profile,
			Status:     status,
			Running:    running,
			ExitCode:   exitCode,
			StartedAt:  time.Unix(rec.StartedAt, 0).UTC(),
		}
		if rec.FinishedAt != 0 && status != jobStatusUnknown && status != jobStatusExpired {
			finishedAt := time.Unix(0, rec.FinishedAt).UTC()
			info.FinishedAt = &finishedAt
		}
		runsByID[rec.RunID] = info
	}
	s.jobsMu.Unlock()

	p, err := pathsDefault()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(p.RunsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read retained runs: %w", err)
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".meta.json") {
			continue
		}
		runID := strings.TrimSuffix(ent.Name(), ".meta.json")
		if !validRunID(runID) {
			continue
		}
		data, err := readRunFile(filepath.Join(p.RunsDir, ent.Name()))
		if err != nil {
			continue
		}
		var metadata runMetadata
		if json.Unmarshal(data, &metadata) != nil || metadata.Connection == "" || metadata.StartedAt.IsZero() || metadata.FinishedAt.IsZero() {
			continue
		}
		finishedAt := metadata.FinishedAt.UTC()
		exitCode := metadata.ExitCode
		runsByID[runID] = RunInfo{
			RunID:      runID,
			Connection: metadata.Connection,
			Status:     jobStatusDone,
			ExitCode:   &exitCode,
			StartedAt:  metadata.StartedAt.UTC(),
			FinishedAt: &finishedAt,
			Truncated:  metadata.Truncated,
		}
	}

	runs := make([]RunInfo, 0, len(runsByID))
	for _, info := range runsByID {
		runs = append(runs, info)
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].StartedAt.Equal(runs[j].StartedAt) {
			return runs[i].RunID < runs[j].RunID
		}
		return runs[i].StartedAt.After(runs[j].StartedAt)
	})
	return runs, nil
}

func (s *server) finalizeOutput(runID, pattern string) (Response, bool) {
	rec, ok := s.persistedJobByRunID(runID)
	if !ok {
		return Response{}, false
	}
	if rec.Status == jobStatusExpired {
		return expiredRunResponse(runID), true
	}
	snapshot, ok, err := s.loadConnectionSnapshot(rec.Profile)
	if err != nil {
		return Response{OK: false, Error: err.Error(), Kind: "local_error", RunID: runID}, true
	}
	if !ok {
		return Response{OK: false, Error: "saved connection for this run no longer exists", Kind: "unknown_connection", RunID: runID}, true
	}
	if migrated, ok := s.persistedJobByRunID(runID); ok {
		rec = migrated
	}
	p := snapshot.profile
	reg := snapshot.registry
	fingerprint := snapshot.fingerprint
	if rec.Fingerprint != "" && rec.Fingerprint != fingerprint {
		return Response{OK: false, Error: "saved connection changed; cannot finalize the previous remote run safely", Kind: "run_key_conflict", RunID: runID}, true
	}

	e := s.entryFor(p.Name)
	s.prepareEntry(e, snapshot)
	// Register the rebuilt job so concurrent finalizers and a watching exec
	// share one *job (and one pollMu); otherwise two callers could each fetch
	// and clean up the same remote run and race to overwrite the saved log.
	e.mu.Lock()
	j := e.jobs[rec.Key]
	if j == nil || j.id != runID {
		j = recordToJob(rec)
		j.fingerprint = fingerprint
		e.jobs[rec.Key] = j
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

	progress, errResp := s.readRemoteProgress(e, p, reg, runID)
	if errResp != nil {
		return *errResp, true
	}
	if progress.state == "running" {
		j.mu.Lock()
		j.lastSeenAt = s.currentTime().UTC()
		j.mu.Unlock()
		if err := s.savePersistedJob(p.Name, j); err != nil {
			brokerLog.Printf("persist observation for run %s: %v", runID, err)
		}
		cleaned := output.Clean(progress.data)
		if pattern != "" {
			cleaned = grepText(cleaned, pattern)
		}
		rendered := output.Bound(cleaned, output.Options{MaxBytes: maxRunningOutputBytes})
		return Response{
			OK:              false,
			ExitCode:        75,
			Stdout:          rendered,
			Highlights:      output.Signals(cleaned, 8),
			DurationMS:      time.Since(time.Unix(rec.StartedAt, 0)).Milliseconds(),
			Error:           "remote process has not exited; recent output follows",
			Running:         true,
			RunID:           runID,
			OutputTruncated: progress.originalBytes > int64(len(progress.data)) || rendered != cleaned,
			Lossy:           !utf8.Valid(progress.data),
			OriginalBytes:   progress.originalBytes,
			ReturnedBytes:   int64(len(rendered)),
		}, true
	}
	if progress.state != "done" {
		j.mu.Lock()
		terminalKnown := j.done && (j.status == jobStatusFinalizePending || j.status == jobStatusDone)
		exitCode := j.exitCode
		j.mu.Unlock()
		if terminalKnown {
			return unavailableRunOutputResponse(runID, exitCode), true
		}
		if err := s.expireJob(e, p.Name, j); err != nil {
			return Response{OK: false, Error: fmt.Sprintf("save expired run state: %v", err), Kind: "local_error", RunID: runID}, true
		}
		return expiredRunResponse(runID), true
	}
	rc, errResp := s.readRemoteRC(e, p, reg, runID)
	if errResp != nil {
		return *errResp, true
	}
	exit, err := parseRemoteExit(rc)
	if err != nil {
		return Response{OK: false, Error: "remote run has an invalid exit status", Kind: string(sshconn.ErrSSH), RunID: runID}, true
	}
	observedAt := time.Now().UTC()
	finishedAt, duration := resolveRemoteTiming(j.startedAt, observedAt, exit)

	j.mu.Lock()
	j.done = true
	j.exitCode = exit.code
	j.status = jobStatusFinalizePending
	j.finishedAt = finishedAt
	j.durationMS = duration.Milliseconds()
	startedAt := j.startedAt
	durationMS := j.durationMS
	j.mu.Unlock()
	if err := s.savePersistedJob(p.Name, j); err != nil {
		return Response{OK: false, Error: fmt.Sprintf("save run state: %v", err), Kind: "local_error", RunID: runID}, true
	}

	_, _, finalizeErr := s.finalizeRunLog(e, p, reg, j, runMetadata{
		ExitCode:   exit.code,
		OK:         exit.code == 0,
		Connection: p.Name,
		StartedAt:  startedAt.UTC(),
		FinishedAt: finishedAt,
		DurationMS: durationMS,
	})
	if finalizeErr != nil {
		return *finalizeErr, true
	}
	if rec.RunKeyHash != "" {
		s.releaseJob(e, j)
	} else {
		s.removeJob(e, p.Name, rec.Key, j)
	}
	return Response{}, false
}

func expiredRunResponse(runID string) Response {
	return Response{
		OK:    false,
		Error: "remote run state is no longer available; its exit status is unknown",
		Kind:  "run_expired",
		RunID: runID,
	}
}

func unavailableRunOutputResponse(runID string, exitCode int) Response {
	return Response{
		OK:       false,
		ExitCode: 1,
		Error:    fmt.Sprintf("remote run exited with status %d, but its output is no longer available", exitCode),
		Kind:     "output_unavailable",
		RunID:    runID,
	}
}
