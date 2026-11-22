// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package updater

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Windows reparse point encoding, used for the current link on Windows. A
// directory junction (mount point) is used instead of a symbolic link
// because creating one needs no privilege, and because retargeting an
// existing junction (FSCTL_SET_REPARSE_POINT on it) replaces its target in
// one file system operation, which a directory rename cannot do on Windows.
// The functions here only build and parse REPARSE_DATA_BUFFER contents and
// are tested on every platform.

const (
	reparseTagMountPoint = 0xA0000003
	reparseTagSymlink    = 0xA000000C
	symlinkFlagRelative  = 1
	maxReparseData       = 16 * 1024
	ntPathPrefix         = `\??\`
)

// encodeMountPoint returns the REPARSE_DATA_BUFFER of a junction to target,
// an absolute path with a drive letter such as C:\Program Files\x.
func encodeMountPoint(target string) ([]byte, error) {
	if !isDrivePath(target) {
		return nil, fmt.Errorf("junction target %q is not an absolute path with a drive letter", target)
	}
	sub := utf16.Encode([]rune(ntPathPrefix + target))
	printName := utf16.Encode([]rune(target))
	// PathBuffer: substitute name, NUL, print name, NUL.
	pathLen := (len(sub) + 1 + len(printName) + 1) * 2
	dataLen := 8 + pathLen
	if 8+dataLen > maxReparseData {
		return nil, fmt.Errorf("junction target %q is too long", target)
	}
	b := make([]byte, 8+dataLen)
	le := binary.LittleEndian
	le.PutUint32(b[0:], reparseTagMountPoint)
	le.PutUint16(b[4:], uint16(dataLen))
	le.PutUint16(b[8:], 0)                         // SubstituteNameOffset
	le.PutUint16(b[10:], uint16(len(sub)*2))       // SubstituteNameLength
	le.PutUint16(b[12:], uint16((len(sub)+1)*2))   // PrintNameOffset
	le.PutUint16(b[14:], uint16(len(printName)*2)) // PrintNameLength
	off := 16
	for _, c := range sub {
		le.PutUint16(b[off:], c)
		off += 2
	}
	off += 2
	for _, c := range printName {
		le.PutUint16(b[off:], c)
		off += 2
	}
	return b, nil
}

// decodeReparse returns the target of a junction or symbolic link reparse
// buffer. Absolute targets are returned in Win32 form (C:\...); a relative
// symbolic link target is returned as stored.
func decodeReparse(b []byte) (string, error) {
	le := binary.LittleEndian
	if len(b) < 8 {
		return "", errors.New("reparse data too short")
	}
	tag := le.Uint32(b[0:])
	dataLen := int(le.Uint16(b[4:]))
	if 8+dataLen > len(b) {
		return "", errors.New("reparse data truncated")
	}
	data := b[8 : 8+dataLen]
	var hdr int
	relative := false
	switch tag {
	case reparseTagMountPoint:
		hdr = 8
	case reparseTagSymlink:
		hdr = 12
		if len(data) < hdr {
			return "", errors.New("reparse data too short")
		}
		relative = le.Uint32(data[8:])&symlinkFlagRelative != 0
	default:
		return "", fmt.Errorf("reparse tag %#x is not a junction or symbolic link", tag)
	}
	if len(data) < hdr {
		return "", errors.New("reparse data too short")
	}
	subOff, subLen := int(le.Uint16(data[0:])), int(le.Uint16(data[2:]))
	path := data[hdr:]
	if subOff%2 != 0 || subLen%2 != 0 || subOff+subLen > len(path) {
		return "", errors.New("reparse substitute name out of range")
	}
	u := make([]uint16, subLen/2)
	for i := range u {
		u[i] = le.Uint16(path[subOff+2*i:])
	}
	name := string(utf16.Decode(u))
	if relative {
		return name, nil
	}
	switch {
	case strings.HasPrefix(name, ntPathPrefix+`UNC\`):
		return `\\` + name[len(ntPathPrefix)+4:], nil
	case strings.HasPrefix(name, ntPathPrefix):
		return name[len(ntPathPrefix):], nil
	}
	return name, nil
}

func isDrivePath(p string) bool {
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
		return false
	}
	c := p[0] | 0x20
	return c >= 'a' && c <= 'z'
}
