package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type jobRecord struct {
	Key         string `json:"key"`
	RunID       string `json:"run_id"`
	Profile     string `json:"profile"`
	Command     string `json:"command"`
	Fingerprint string `json:"fingerprint"`
	RemoteDir   string `json:"remote_dir"`
	LogPath     string `json:"log_path"`
	RCPath      string `json:"rc_path"`
	Offset      int64  `json:"offset"`
	StartedAt   int64  `json:"started_at"`
	FinishedAt  int64  `json:"finished_at,omitempty"`
	Status      string `json:"status"`
	ExitCode    int    `json:"exit_code"`
	PID         string `json:"pid,omitempty"`
}

type jobRegistry struct {
	Jobs map[string]jobRecord `json:"jobs"`
}

func jobKey(profile, command string) string {
	sum := sha256.Sum256([]byte(profile + "\x00" + command))
	return hex.EncodeToString(sum[:])
}

func jobsFile() (string, error) {
	p, err := pathsDefault()
	if err != nil {
		return "", err
	}
	return filepath.Join(p.RunsDir, "jobs.json"), nil
}

func loadJobRegistry() (jobRegistry, error) {
	path, err := jobsFile()
	if err != nil {
		return jobRegistry{Jobs: map[string]jobRecord{}}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return jobRegistry{Jobs: map[string]jobRecord{}}, nil
		}
		return jobRegistry{Jobs: map[string]jobRecord{}}, err
	}
	var reg jobRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return jobRegistry{Jobs: map[string]jobRecord{}}, err
	}
	if reg.Jobs == nil {
		reg.Jobs = map[string]jobRecord{}
	}
	return reg, nil
}

func saveJobRegistry(reg jobRegistry) error {
	path, err := jobsFile()
	if err != nil {
		return err
	}
	if reg.Jobs == nil {
		reg.Jobs = map[string]jobRecord{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newJobRecord(profile string, j *job) jobRecord {
	var finishedAt int64
	if !j.finishedAt.IsZero() {
		finishedAt = j.finishedAt.UnixNano()
	}
	return jobRecord{
		Key:         jobKey(profile, j.command),
		RunID:       j.id,
		Profile:     profile,
		Command:     j.command,
		Fingerprint: j.fingerprint,
		RemoteDir:   remoteJobDir,
		LogPath:     remoteLogPath(j.id),
		RCPath:      remoteRCPath(j.id),
		Offset:      j.offset,
		StartedAt:   j.startedAt.Unix(),
		FinishedAt:  finishedAt,
		Status:      j.status,
		ExitCode:    0,
	}
}

func recordToJob(rec jobRecord) *job {
	startedAt := time.Unix(rec.StartedAt, 0)
	if rec.StartedAt == 0 {
		startedAt = time.Now()
	}
	var finishedAt time.Time
	if rec.FinishedAt != 0 {
		finishedAt = time.Unix(0, rec.FinishedAt)
	}
	return &job{
		id:          rec.RunID,
		command:     rec.Command,
		fingerprint: rec.Fingerprint,
		offset:      rec.Offset,
		started:     true,
		startedAt:   startedAt,
		finishedAt:  finishedAt,
		done:        rec.Status == jobStatusDone || rec.Status == jobStatusFailed,
		exitCode:    rec.ExitCode,
		status:      rec.Status,
	}
}
