// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The gadget authors

package snapshot

import "testing"

func TestGrouping(t *testing.T) {
	first := Mapping{
		FileKey: FileKey{PID: 123, Inode: 42, Flags: 1},
		Start:   0x1000, End: 0x2000, Fname: "/lib/example.so.1",
	}
	second := first
	second.Start, second.End = 0x3000, 0x4000
	executable := first
	executable.Flags = 5
	shared := first
	shared.Flags = 9
	replaced := first
	replaced.Inode++
	s := New()
	for _, m := range []Mapping{first, first, second, executable, shared, replaced} {
		if err := s.Add(m); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Files) != 4 || s.Files[0].MappingCount != 2 || s.Files[0].MappedBytes != 8192 {
		t.Fatalf("incorrect grouping: %+v", s.Files)
	}
	if Permissions(s.Files[1].Flags) != "r-xp" {
		t.Fatal("executable mapping lost its permissions")
	}
	if Permissions(s.Files[2].Flags) != "r--s" {
		t.Fatal("read-only shared mapping lost its permissions")
	}
	next := New()
	if err := next.Add(first); err != nil {
		t.Fatal(err)
	}
	if next.Files[0].MappingCount != 1 {
		t.Fatal("deduplication leaked across snapshots")
	}
}

func TestPathResolution(t *testing.T) {
	m := Mapping{FileKey: FileKey{Inode: 42}, Start: 1, End: 2, PathError: -36}
	s := New()
	if err := s.Add(m); err != nil {
		t.Fatal(err)
	}
	if s.Files[0].PathError != -36 {
		t.Fatal("path failure must remain visible")
	}
	m.Start, m.End, m.PathError, m.Fname = 3, 4, 0, "/lib/example.so.1 (deleted)"
	if err := s.Add(m); err != nil {
		t.Fatal(err)
	}
	f := s.Files[0]
	if len(s.Files) != 1 || !f.Deleted || !f.Library || f.PathError != 0 || f.Fname != m.Fname {
		t.Fatalf("failed to merge resolved, deleted library: %+v", f)
	}
}
