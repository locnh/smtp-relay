package quota

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const stateVersion = 1

type stateFile struct {
	Version   int                      `json:"version"`
	SavedAt   string                   `json:"saved_at"`
	Upstreams map[string]upstreamState `json:"upstreams"`
}

type upstreamState struct {
	Buckets map[string]int64 `json:"buckets"`
}

// writeFileAtomic replaces path with data so that readers (and a restart after
// a crash) see either the old or the new content, never a partial file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// checkWritable creates the state directory if needed and proves that files
// can be created in it.
func checkWritable(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("quota: create state dir: %w", err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".probe-*")
	if err != nil {
		return fmt.Errorf("quota: state dir not writable: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("quota: state dir not writable: %w", err)
	}
	return nil
}

// parseState decodes and validates a state file's content.
func parseState(data []byte) (map[string]map[int64]int64, error) {
	var sf stateFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, err
	}
	if sf.Version != stateVersion {
		return nil, fmt.Errorf("unsupported state version %d", sf.Version)
	}
	out := make(map[string]map[int64]int64, len(sf.Upstreams))
	for name, us := range sf.Upstreams {
		b := make(map[int64]int64, len(us.Buckets))
		for k, v := range us.Buckets {
			minute, err := strconv.ParseInt(k, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("upstream %q: bad bucket key %q", name, k)
			}
			if v < 0 {
				return nil, fmt.Errorf("upstream %q: negative count in bucket %q", name, k)
			}
			b[minute] = v
		}
		out[name] = b
	}
	return out, nil
}

func encodeState(now time.Time, buckets map[string]map[int64]int64) ([]byte, error) {
	sf := stateFile{
		Version:   stateVersion,
		SavedAt:   now.UTC().Format(time.RFC3339),
		Upstreams: make(map[string]upstreamState, len(buckets)),
	}
	for name, b := range buckets {
		us := upstreamState{Buckets: make(map[string]int64, len(b))}
		for minute, n := range b {
			us.Buckets[strconv.FormatInt(minute, 10)] = n
		}
		sf.Upstreams[name] = us
	}
	return json.Marshal(sf)
}

// load reads the state file into the manager. It never fails: a missing file
// is a first run, and an unusable file is set aside so the relay keeps running.
func (m *Manager) load() {
	data, err := os.ReadFile(m.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		m.log.Warn().Err(err).Str("file", m.stateFile).Msg("cannot read quota state file, starting with empty counters")
		return
	}

	loaded, err := parseState(data)
	if err != nil {
		dst := fmt.Sprintf("%s.corrupt-%d", m.stateFile, m.now().Unix())
		if rerr := os.Rename(m.stateFile, dst); rerr != nil {
			m.log.Warn().Err(rerr).Str("file", m.stateFile).Msg("cannot rename corrupt quota state file")
			dst = ""
		}
		m.log.Warn().Err(err).Str("file", m.stateFile).Str("renamed_to", dst).
			Msg("corrupt quota state file, starting with empty counters")
		return
	}

	nowMin := m.nowMinute()
	for name, b := range loaded {
		u, ok := m.byName[name]
		if !ok {
			m.log.Info().Str("upstream", name).Msg("dropping quota state of upstream no longer configured")
			continue
		}
		for minute, n := range b {
			if minute > nowMin || minute <= nowMin-u.windowMinutes || n == 0 {
				continue
			}
			u.buckets[minute] = n
		}
	}
}
