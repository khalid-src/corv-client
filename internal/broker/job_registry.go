package broker

import "time"

const connectionFingerprintVersion = 1

func (s *server) migrateLegacyFingerprints(profileName, current, legacy string) error {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	next := cloneJobRegistry(s.jobs)
	changed := false
	for key, rec := range next.Jobs {
		if rec.Profile != profileName || rec.FingerprintVersion != 0 {
			continue
		}
		if rec.Fingerprint != "" && rec.Fingerprint != current && rec.Fingerprint != legacy {
			continue
		}
		rec.Fingerprint = current
		rec.FingerprintVersion = connectionFingerprintVersion
		next.Jobs[key] = rec
		changed = true
	}
	if !changed {
		return nil
	}
	if err := saveJobRegistry(next); err != nil {
		return err
	}
	s.jobs = next
	return nil
}

func (s *server) persistedJob(profileName, command string) (jobRecord, bool) {
	return s.persistedJobByKey(jobKey(profileName, command))
}

func (s *server) persistedJobByKey(key string) (jobRecord, bool) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	rec, ok := s.jobs.Jobs[key]
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
	defer s.jobsMu.Unlock()
	next := cloneJobRegistry(s.jobs)
	next.Jobs[rec.Key] = rec
	if err := saveJobRegistry(next); err != nil {
		return err
	}
	s.jobs = next
	return nil
}

func cloneJobRegistry(reg jobRegistry) jobRegistry {
	jobs := make(map[string]jobRecord, len(reg.Jobs))
	for key, rec := range reg.Jobs {
		jobs[key] = rec
	}
	return jobRegistry{Jobs: jobs}
}

func (s *server) currentJob(profileName string, j *job) bool {
	s.mu.Lock()
	e, ok := s.entries[profileName]
	s.mu.Unlock()
	if !ok {
		return false
	}
	e.mu.Lock()
	key := j.key
	if key == "" {
		key = jobKey(profileName, j.command)
	}
	current := e.jobs[key] == j && e.fingerprint == j.fingerprint
	e.mu.Unlock()
	return current
}

func (s *server) deletePersistedJobByKey(key string) {
	s.jobsMu.Lock()
	next := cloneJobRegistry(s.jobs)
	delete(next.Jobs, key)
	if err := saveJobRegistry(next); err != nil {
		brokerLog.Printf("persist job removal: %v", err)
	} else {
		s.jobs = next
	}
	s.jobsMu.Unlock()
}

func (s *server) deleteUnkeyedPersistedJobs(profileName string) error {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	next := cloneJobRegistry(s.jobs)
	for key, rec := range next.Jobs {
		if rec.Profile == profileName && rec.RunKeyHash == "" {
			delete(next.Jobs, key)
		}
	}
	if err := saveJobRegistry(next); err != nil {
		return err
	}
	s.jobs = next
	return nil
}

func (s *server) pruneExpiredKeyedJobs(now time.Time) {
	cutoff := now.Add(-jobTTL)
	s.jobsMu.Lock()
	next := cloneJobRegistry(s.jobs)
	changed := false
	for key, rec := range next.Jobs {
		if rec.RunKeyHash == "" || rec.Status != jobStatusDone || rec.FinishedAt == 0 {
			continue
		}
		if time.Unix(0, rec.FinishedAt).Before(cutoff) {
			delete(next.Jobs, key)
			changed = true
		}
	}
	if changed {
		if err := saveJobRegistry(next); err != nil {
			brokerLog.Printf("prune retained run keys: %v", err)
		} else {
			s.jobs = next
		}
	}
	s.jobsMu.Unlock()
}
