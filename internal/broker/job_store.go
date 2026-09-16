package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/khalid-src/corv-client/internal/atomicfile"
)

var writeJobFile = atomicfile.Write

type jobRecord struct {
	Key                string `json:"key"`
	RunID              string `json:"run_id"`
	Profile            string `json:"profile"`
	Command            string `json:"command,omitempty"`
	CommandHash        string `json:"command_hash,omitempty"`
	RunKeyHash         string `json:"run_key_hash,omitempty"`
	Fingerprint        string `json:"fingerprint"`
	FingerprintVersion int    `json:"fingerprint_version,omitempty"`
	RemoteDir          string `json:"remote_dir"`
	LogPath            string `json:"log_path"`
	RCPath             string `json:"rc_path"`
	Offset             int64  `json:"offset"`
	StartedAt          int64  `json:"started_at"`
	LastSeenAt         int64  `json:"last_seen_at,omitempty"`
	FinishedAt         int64  `json:"finished_at,omitempty"`
	DurationMS         int64  `json:"duration_ms,omitempty"`
	Status             string `json:"status"`
	ExitCode           int    `json:"exit_code"`
	PID                string `json:"pid,omitempty"`
}

type jobRegistry struct {
	Jobs map[string]jobRecord `json:"jobs"`
}

func jobKey(profile, command string) string {
	sum := sha256.Sum256([]byte(profile + "\x00" + command))
	return hex.EncodeToString(sum[:])
}

func keyedJobKey(profile, runKey string) string {
	sum := sha256.Sum256([]byte(profile + "\x00run-key\x00" + runKey))
	return hex.EncodeToString(sum[:])
}

func valueHash(value string) string {
	sum := sha256.Sum256([]byte(value))
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
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return writeJobFile(path, data, 0o600)
}

func newJobRecord(profile string, j *job) jobRecord {
	key := j.key
	if key == "" {
		key = jobKey(profile, j.command)
	}
	var finishedAt int64
	if !j.finishedAt.IsZero() {
		finishedAt = j.finishedAt.UnixNano()
	}
	var lastSeenAt int64
	if !j.lastSeenAt.IsZero() {
		lastSeenAt = j.lastSeenAt.UnixNano()
	}
	return jobRecord{
		Key:                key,
		RunID:              j.id,
		Profile:            profile,
		CommandHash:        j.commandHash,
		RunKeyHash:         j.runKeyHash,
		Fingerprint:        j.fingerprint,
		FingerprintVersion: j.fingerprintVersion,
		RemoteDir:          remoteJobDir,
		LogPath:            remoteLogPath(j.id),
		RCPath:             remoteRCPath(j.id),
		Offset:             j.offset,
		StartedAt:          j.startedAt.Unix(),
		LastSeenAt:         lastSeenAt,
		FinishedAt:         finishedAt,
		DurationMS:         j.durationMS,
		Status:             j.status,
		ExitCode:           j.exitCode,
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
	var lastSeenAt time.Time
	if rec.LastSeenAt != 0 {
		lastSeenAt = time.Unix(0, rec.LastSeenAt)
	}
	return &job{
		id:                 rec.RunID,
		key:                rec.Key,
		command:            rec.Command,
		commandHash:        rec.CommandHash,
		runKeyHash:         rec.RunKeyHash,
		fingerprint:        rec.Fingerprint,
		fingerprintVersion: rec.FingerprintVersion,
		offset:             rec.Offset,
		started:            true,
		startedAt:          startedAt,
		lastSeenAt:         lastSeenAt,
		finishedAt:         finishedAt,
		durationMS:         rec.DurationMS,
		done:               rec.Status == jobStatusDone || rec.Status == jobStatusFinalizePending || rec.Status == jobStatusFailed || rec.Status == jobStatusExpired,
		exitCode:           rec.ExitCode,
		status:             rec.Status,
	}
}
