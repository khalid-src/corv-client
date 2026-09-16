package broker

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/khalid-src/corv-client/internal/profile"
	"github.com/khalid-src/corv-client/internal/sshconn"
)

type jobProgress struct {
	state         string
	data          []byte
	originalBytes int64
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

func startJobCommand(id string, payloadBytes int64) string {
	return fmt.Sprintf(
		"umask 077; for tool in id tail head wc mkdir chmod cat rm mv sh date; do command -v \"$tool\" >/dev/null 2>&1 || { echo CORV_NO_POSIX; exit 127; }; done; if command -v setsid >/dev/null 2>&1; then runner=setsid; elif command -v nohup >/dev/null 2>&1; then runner=nohup; else echo CORV_NO_POSIX; exit 127; fi; dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); mkdir -p \"$dir\" && chmod 700 \"$dir\" || exit 1; upload=\"$dir/%s.upload\"; script=\"$dir/%s.sh\"; rm -f \"$upload\"; if ! cat > \"$upload\"; then rm -f \"$upload\"; echo CORV_UPLOAD_INCOMPLETE; exit 125; fi; size=$(wc -c < \"$upload\") || exit 1; if [ \"$size\" -ne %d ]; then rm -f \"$upload\"; echo CORV_UPLOAD_INCOMPLETE; exit 125; fi; mv \"$upload\" \"$script\" && : > \"$dir/%s.log\" && { \"$runner\" sh -c 'started=$(date +%%s); sh \"$0\" > \"$1\" 2>&1; code=$?; finished=$(date +%%s); duration=$((finished-started)); [ \"$duration\" -ge 0 ] || duration=0; printf \"CORV_RC_V2 %%s %%s %%s\\n\" \"$code\" \"$finished\" \"$duration\" > \"$2.tmp\" && mv \"$2.tmp\" \"$2\"' \"$script\" \"$dir/%s.log\" \"$dir/%s.rc\" >/dev/null 2>&1 & echo CORV_STARTED; }",
		id, id, payloadBytes, id, id, id,
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
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); rm -f \"$dir/%s.upload\" \"$dir/%s.sh\" \"$dir/%s.log\" \"$dir/%s.rc\" \"$dir/%s.rc.tmp\"", id, id, id, id, id)
}

func (s *server) readRemoteProgress(e *entry, p profile.Profile, reg profile.Registry, runID string) (jobProgress, *Response) {
	res, err := s.runRaw(e, p, reg, progressJobCommand(runID), maxRunningOutputBytes+retainedLogFrameMargin)
	if err != nil {
		return jobProgress{}, &Response{OK: false, Error: err.Error(), Kind: string(sshconn.Classify(err)), RunID: runID}
	}
	if !res.OK() {
		return jobProgress{}, &Response{OK: false, ExitCode: res.ExitCode, Error: strings.TrimSpace(string(res.Stderr)), Kind: string(res.Kind), RunID: runID}
	}
	progress, err := parseJobProgress(res.Stdout)
	if err != nil {
		return jobProgress{}, &Response{OK: false, Error: fmt.Sprintf("read remote run progress: %v", err), Kind: string(sshconn.ErrSSH), RunID: runID}
	}
	return progress, nil
}

func progressJobCommand(id string) string {
	return fmt.Sprintf("dir=${TMPDIR:-/tmp}/corv-jobs-$(id -u); log=\"$dir/%s.log\"; if [ -f \"$dir/%s.rc\" ]; then state=done; elif [ -f \"$log\" ]; then state=running; else state=missing; fi; size=$(wc -c < \"$log\" 2>/dev/null) || size=0; printf 'CORV_PROGRESS_V1 %%s %%s\\n' \"$state\" \"$size\"; [ -f \"$log\" ] && tail -c %d \"$log\" 2>/dev/null || true", id, id, maxRunningOutputBytes)
}

func parseJobProgress(raw []byte) (jobProgress, error) {
	lineEnd := bytes.IndexByte(raw, '\n')
	if lineEnd < 0 || lineEnd >= retainedLogFrameMargin {
		return jobProgress{}, errors.New("invalid progress frame")
	}
	fields := strings.Fields(string(raw[:lineEnd]))
	if len(fields) != 3 || fields[0] != "CORV_PROGRESS_V1" {
		return jobProgress{}, errors.New("invalid progress frame")
	}
	if fields[1] != "running" && fields[1] != "done" && fields[1] != "missing" {
		return jobProgress{}, errors.New("invalid progress state")
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return jobProgress{}, errors.New("invalid progress size")
	}
	payload := append([]byte(nil), raw[lineEnd+1:]...)
	if len(payload) > maxRunningOutputBytes {
		return jobProgress{}, errors.New("progress payload exceeds limit")
	}
	if size < int64(len(payload)) {
		size = int64(len(payload))
	}
	return jobProgress{state: fields[1], data: payload, originalBytes: size}, nil
}
