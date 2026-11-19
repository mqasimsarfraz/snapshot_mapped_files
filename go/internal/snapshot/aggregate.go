// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The gadget authors

package snapshot

import (
	"fmt"
	"path"
	"strings"
)

type FileKey struct {
	Mntns, ProcessStart, Inode uint64
	PID, Major, Minor, Flags   uint32
}

type Mapping struct {
	FileKey
	Start, End, OffsetPages uint64
	Comm, Fname             string
	PathError               int32
	Deleted                 bool
}

type vmaKey struct {
	FileKey
	start, end, offsetPages uint64
}

type File struct {
	Mapping
	MappingCount, MappedBytes uint64
	PathVariants              map[string]struct{}
	Library                   bool
}

type Snapshot struct {
	Files []File
	index map[FileKey]int
	seen  map[vmaKey]struct{}
}

func New() *Snapshot {
	return &Snapshot{index: make(map[FileKey]int), seen: make(map[vmaKey]struct{})}
}

func (s *Snapshot) Add(m Mapping) error {
	if m.End <= m.Start {
		return fmt.Errorf("invalid VMA range %#x-%#x for pid %d", m.Start, m.End, m.PID)
	}
	vma := vmaKey{m.FileKey, m.Start, m.End, m.OffsetPages}
	if _, ok := s.seen[vma]; ok {
		return nil
	}
	s.seen[vma] = struct{}{}

	idx, ok := s.index[m.FileKey]
	if !ok {
		idx = len(s.Files)
		s.index[m.FileKey] = idx
		s.Files = append(s.Files, File{Mapping: m, PathVariants: make(map[string]struct{})})
	}
	f := &s.Files[idx]
	f.MappingCount++
	f.MappedBytes += m.End - m.Start
	f.Deleted = f.Deleted || m.Deleted || strings.HasSuffix(m.Fname, " (deleted)")
	if m.PathError == 0 && m.Fname != "" {
		f.PathVariants[m.Fname] = struct{}{}
		f.Library = f.Library || isSharedLibrary(m.Fname)
		if f.PathError != 0 || f.Fname == "" {
			f.Fname = m.Fname
			f.PathError = 0
		}
	}
	return nil
}

func isSharedLibrary(fname string) bool {
	name := path.Base(strings.TrimSuffix(fname, " (deleted)"))
	return strings.HasSuffix(name, ".so") || strings.Contains(name, ".so.")
}

func Permissions(flags uint32) string {
	p := []byte("---p")
	for i, bit := range []uint32{1, 2, 4} {
		if flags&bit != 0 {
			p[i] = "rwx"[i]
		}
	}
	if flags&8 != 0 {
		p[3] = 's'
	}
	return string(p)
}
