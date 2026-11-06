package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	recordSize    = 36
	journalDays   = 16
	journalPrefix = "identities-"
)

type identityEntry struct {
	hash [16]byte
	day  uint32
}

// identityStore records delivered identities in a daily journal, read back at start, so a restart
// cannot reopen a replay window. An entry is written only after the event is acknowledged. Holding
// more days than maxEventAge means no event old enough to be forgotten can be accepted again.
type identityStore struct {
	mu      sync.RWMutex
	dir     string
	entries map[[16]byte]identityEntry
	maxKept int
	file    *os.File
	day     uint32
}

func dayNumber(t time.Time) uint32 { return uint32(t.Unix() / 86400) }

func journalName(day uint32) string {
	return journalPrefix + time.Unix(int64(day)*86400, 0).UTC().Format("20060102") + ".log"
}

// openIdentityStore fails if the journal cannot be read, because the service must not run without
// its replay protection.
func openIdentityStore(dir string, maxKept int, now time.Time) (*identityStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	store := &identityStore{dir: dir, entries: map[[16]byte]identityEntry{}, maxKept: maxKept}
	today := dayNumber(now)
	paths, err := filepath.Glob(filepath.Join(dir, journalPrefix+"*.log"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	for _, path := range paths {
		day, err := parseDay(path)
		if err != nil {
			return nil, err
		}
		if today-day >= journalDays {
			if err := os.Remove(path); err != nil {
				return nil, err
			}
			continue
		}
		if err := store.load(path, day); err != nil {
			return nil, err
		}
	}
	return store, store.roll(today)
}

func parseDay(path string) (uint32, error) {
	var stamp string
	name := filepath.Base(path)
	if _, err := fmt.Sscanf(name, journalPrefix+"%8s.log", &stamp); err != nil {
		return 0, fmt.Errorf("unexpected journal file %s", name)
	}
	when, err := time.Parse("20060102", stamp)
	if err != nil {
		return 0, fmt.Errorf("unexpected journal file %s", name)
	}
	return dayNumber(when), nil
}

// load keeps complete, valid records. A crash can leave a partial final record, and that event is
// simply delivered again, which is safe because the document ID is the same.
func (s *identityStore) load(path string, day uint32) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for len(data) >= recordSize {
		record := data[:recordSize]
		data = data[recordSize:]
		if crc32.ChecksumIEEE(record[:32]) != binary.BigEndian.Uint32(record[32:]) {
			continue
		}
		var uid, hash [16]byte
		copy(uid[:], record[:16])
		copy(hash[:], record[16:32])
		s.entries[uid] = identityEntry{hash, day}
	}
	return nil
}

func (s *identityStore) roll(today uint32) error {
	if s.file != nil && s.day == today {
		return nil
	}
	if s.file != nil {
		s.file.Close()
	}
	file, err := os.OpenFile(filepath.Join(s.dir, journalName(today)), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.file, s.day = file, today
	return nil
}

func (s *identityStore) lookup(uid [16]byte) ([16]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[uid]
	return entry.hash, ok
}

type identity struct{ uid, hash [16]byte }

// commit is durable when it returns. Old days leave memory first if the store grows past its limit.
func (s *identityStore) commit(items []identity, now time.Time) error {
	if len(items) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	today := dayNumber(now)
	if err := s.roll(today); err != nil {
		return err
	}
	buffer := make([]byte, 0, len(items)*recordSize)
	for _, item := range items {
		start := len(buffer)
		buffer = append(buffer, item.uid[:]...)
		buffer = append(buffer, item.hash[:]...)
		buffer = binary.BigEndian.AppendUint32(buffer, crc32.ChecksumIEEE(buffer[start:]))
	}
	if _, err := s.file.Write(buffer); err != nil {
		return err
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	for _, item := range items {
		s.entries[item.uid] = identityEntry{item.hash, today}
	}
	if len(s.entries) > s.maxKept {
		oldest := today
		for _, entry := range s.entries {
			if entry.day < oldest {
				oldest = entry.day
			}
		}
		for uid, entry := range s.entries {
			if entry.day == oldest {
				delete(s.entries, uid)
			}
		}
	}
	return nil
}

func (s *identityStore) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *identityStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		s.file.Close()
	}
}
