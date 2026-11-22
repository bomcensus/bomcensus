// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package updater

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestMountPointRoundTrip(t *testing.T) {
	for _, target := range []string{`C:\Program Files\bomcensus\versions\1.2.3`, `d:\x`, `C:\Programme\bömcensus\versions\1.0.0-rc.1`} {
		b, err := encodeMountPoint(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		le := binary.LittleEndian
		if le.Uint32(b) != reparseTagMountPoint || int(le.Uint16(b[4:]))+8 != len(b) {
			t.Fatalf("%s: bad header % x", target, b[:8])
		}
		got, err := decodeReparse(b)
		if err != nil || got != target {
			t.Fatalf("%s: decoded %q %v", target, got, err)
		}
	}
	for _, bad := range []string{`versions\1.0.0`, `\\server\share\x`, `C:relative`, ``} {
		if _, err := encodeMountPoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func symlinkBuffer(sub string, flags uint32) []byte {
	u := utf16.Encode([]rune(sub))
	path := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(path[2*i:], c)
	}
	data := make([]byte, 12+len(path))
	le := binary.LittleEndian
	le.PutUint16(data[0:], 0)
	le.PutUint16(data[2:], uint16(len(path)))
	le.PutUint16(data[4:], 0)
	le.PutUint16(data[6:], uint16(len(path)))
	le.PutUint32(data[8:], flags)
	copy(data[12:], path)
	b := make([]byte, 8+len(data))
	le.PutUint32(b, reparseTagSymlink)
	le.PutUint16(b[4:], uint16(len(data)))
	copy(b[8:], data)
	return b
}

func TestDecodeReparse(t *testing.T) {
	if got, err := decodeReparse(symlinkBuffer(`versions\1.0.0`, symlinkFlagRelative)); err != nil || got != `versions\1.0.0` {
		t.Fatalf("relative symlink: %q %v", got, err)
	}
	if got, err := decodeReparse(symlinkBuffer(`\??\C:\x\versions\1.0.0`, 0)); err != nil || got != `C:\x\versions\1.0.0` {
		t.Fatalf("absolute symlink: %q %v", got, err)
	}
	if got, err := decodeReparse(symlinkBuffer(`\??\UNC\srv\share\v`, 0)); err != nil || got != `\\srv\share\v` {
		t.Fatalf("UNC symlink: %q %v", got, err)
	}
	good, _ := encodeMountPoint(`C:\x`)
	other := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(other, 0x80000017) // IO_REPARSE_TAG_WOF
	bigOffset := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(bigOffset[8:], 0x1000)
	for name, b := range map[string][]byte{
		"empty":     nil,
		"truncated": good[:len(good)-4],
		"other tag": other,
		"offset":    bigOffset,
	} {
		if _, err := decodeReparse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPlatformNames(t *testing.T) {
	w := nameSet("windows", agentBaseNames)
	if !w["bomcensus-agent.exe"] || !w["bomcensus-probe.exe"] || !w["bomcensus-updater.exe"] || w["bomcensus-agent"] || len(w) != 3 {
		t.Fatalf("windows names %v", w)
	}
	for name, want := range map[string]bool{
		RollbackName:                true,
		ConfirmName("1.2.3"):        true,
		BundleName("1.2.3"):         true,
		BundleName("v1.2.3"):        false,
		"confirm-":                  false,
		".bomcensus-1.2.3.tar.part": false,
		"bomcensus-1.2.3.tar.part":  false,
		"state.json":                false,
	} {
		if IsSpoolEntry(name) != want {
			t.Errorf("IsSpoolEntry(%q) = %v", name, !want)
		}
	}
}
