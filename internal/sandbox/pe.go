// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PE machine types of the architectures version commands run on.
var peMachines = map[string]uint16{
	"amd64": 0x8664,
	"arm64": 0xAA64,
}

const (
	peFileExecutableImage = 0x0002
	peFileDLL             = 0x2000
	peSubsystemConsole    = 3
)

// ErrNotNativePE is returned by NativeConsolePE for files that are not a
// console executable of the given architecture.
var ErrNotNativePE = errors.New("not a native console executable")

// NativeConsolePE checks that r is a PE executable (not a DLL) for goarch
// with the console subsystem. Scripts (.bat, .cmd), which Windows runs
// through cmd.exe with its own argument parsing, other architectures that
// would run under emulation, and GUI programs are refused.
func NativeConsolePE(r io.ReaderAt, goarch string) error {
	want, ok := peMachines[goarch]
	if !ok {
		return fmt.Errorf("%w: no PE machine for %s", ErrNotNativePE, goarch)
	}
	var dos [64]byte
	if _, err := r.ReadAt(dos[:], 0); err != nil {
		return fmt.Errorf("%w: %v", ErrNotNativePE, err)
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return fmt.Errorf("%w: no MZ header", ErrNotNativePE)
	}
	off := int64(binary.LittleEndian.Uint32(dos[0x3C:]))
	if off < 64 || off > 1<<20 {
		return fmt.Errorf("%w: PE header offset %d", ErrNotNativePE, off)
	}
	// Signature, file header (20 bytes) and the optional header up to
	// Subsystem (offset 68 in both PE32 and PE32+).
	var h [4 + 20 + 70]byte
	if _, err := r.ReadAt(h[:], off); err != nil {
		return fmt.Errorf("%w: %v", ErrNotNativePE, err)
	}
	if string(h[:4]) != "PE\x00\x00" {
		return fmt.Errorf("%w: no PE signature", ErrNotNativePE)
	}
	machine := binary.LittleEndian.Uint16(h[4:])
	if machine != want {
		return fmt.Errorf("%w: machine 0x%04x, want 0x%04x (%s)", ErrNotNativePE, machine, want, goarch)
	}
	chars := binary.LittleEndian.Uint16(h[4+18:])
	if chars&peFileExecutableImage == 0 || chars&peFileDLL != 0 {
		return fmt.Errorf("%w: characteristics 0x%04x", ErrNotNativePE, chars)
	}
	if size := binary.LittleEndian.Uint16(h[4+16:]); size < 70 {
		return fmt.Errorf("%w: optional header of %d bytes", ErrNotNativePE, size)
	}
	opt := h[24:]
	if magic := binary.LittleEndian.Uint16(opt); magic != 0x20B {
		return fmt.Errorf("%w: optional header magic 0x%x, want PE32+", ErrNotNativePE, magic)
	}
	if sub := binary.LittleEndian.Uint16(opt[68:]); sub != peSubsystemConsole {
		return fmt.Errorf("%w: subsystem %d, want console", ErrNotNativePE, sub)
	}
	return nil
}
