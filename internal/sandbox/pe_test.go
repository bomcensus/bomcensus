// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sandbox

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// peImage builds the headers of a PE file.
func peImage(machine, chars, magic, subsystem uint16) []byte {
	b := make([]byte, 0x200)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3C:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	fh := b[0x84:]
	binary.LittleEndian.PutUint16(fh[0:], machine)
	binary.LittleEndian.PutUint16(fh[16:], 240) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(fh[18:], chars)
	opt := b[0x98:]
	binary.LittleEndian.PutUint16(opt[0:], magic)
	binary.LittleEndian.PutUint16(opt[68:], subsystem)
	return b
}

func TestNativeConsolePE(t *testing.T) {
	const exe = peFileExecutableImage
	for _, tc := range []struct {
		name   string
		img    []byte
		goarch string
		ok     bool
	}{
		{"amd64 console", peImage(0x8664, exe, 0x20B, 3), "amd64", true},
		{"arm64 console", peImage(0xAA64, exe, 0x20B, 3), "arm64", true},
		{"amd64 on arm64", peImage(0x8664, exe, 0x20B, 3), "arm64", false},
		{"x86", peImage(0x14C, exe, 0x10B, 3), "amd64", false},
		{"dll", peImage(0x8664, exe|peFileDLL, 0x20B, 3), "amd64", false},
		{"not executable", peImage(0x8664, 0, 0x20B, 3), "amd64", false},
		{"gui", peImage(0x8664, exe, 0x20B, 2), "amd64", false},
		{"pe32 magic", peImage(0x8664, exe, 0x10B, 3), "amd64", false},
		{"script", []byte("@echo off\r\necho hi\r\n" + string(make([]byte, 300))), "amd64", false},
		{"short", []byte("MZ"), "amd64", false},
		{"no arch", peImage(0x8664, exe, 0x20B, 3), "riscv64", false},
	} {
		err := NativeConsolePE(bytes.NewReader(tc.img), tc.goarch)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrNotNativePE)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	bad := peImage(0x8664, exe, 0x20B, 3)
	binary.LittleEndian.PutUint32(bad[0x3C:], 1<<30)
	if err := NativeConsolePE(bytes.NewReader(bad), "amd64"); err == nil {
		t.Error("PE offset out of range accepted")
	}
}
