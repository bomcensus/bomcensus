// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package signtest

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/bomcensus/bomcensus/internal/sign"
)

// PE machine types for the supported architectures.
var peMachines = map[string]uint16{
	"amd64": 0x8664, // IMAGE_FILE_MACHINE_AMD64
	"arm64": 0xaa64, // IMAGE_FILE_MACHINE_ARM64
}

// Entry point code of MinimalPE: return 0.
var peCode = map[string][]byte{
	"amd64": {0x31, 0xc0, 0xc3},                               // xor eax, eax; ret
	"arm64": {0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6}, // mov w0, #0; ret
}

// MinimalPE returns a 1 KiB PE32+ console executable for windows/<goarch>
// with one .text section and no imports. It is structurally valid, which is
// all signing and verification need; it is not meant to be run.
func MinimalPE(goarch string) ([]byte, error) {
	machine, ok := peMachines[goarch]
	if !ok {
		return nil, fmt.Errorf("signtest: no PE machine for %q", goarch)
	}
	const (
		peOff       = 0x40
		optOff      = peOff + 4 + 20
		optSize     = 112 + 16*8
		sectOff     = optOff + optSize
		fileAlign   = 0x200
		sectAlign   = 0x1000
		headersSize = fileAlign
		textRVA     = sectAlign
		textSize    = fileAlign
	)
	b := make([]byte, headersSize+textSize)
	le := binary.LittleEndian

	copy(b, "MZ")
	le.PutUint32(b[0x3c:], peOff)

	copy(b[peOff:], "PE\x00\x00")
	coff := b[peOff+4:]
	le.PutUint16(coff[0:], machine)
	le.PutUint16(coff[2:], 1) // NumberOfSections
	le.PutUint16(coff[16:], optSize)
	le.PutUint16(coff[18:], 0x0022) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	opt := b[optOff:]
	le.PutUint16(opt[0:], 0x20b) // PE32+
	opt[2] = 14                  // linker version
	le.PutUint32(opt[4:], textSize)
	le.PutUint32(opt[16:], textRVA) // AddressOfEntryPoint
	le.PutUint32(opt[20:], textRVA) // BaseOfCode
	le.PutUint64(opt[24:], 0x140000000)
	le.PutUint32(opt[32:], sectAlign)
	le.PutUint32(opt[36:], fileAlign)
	le.PutUint16(opt[40:], 6)                 // OS version
	le.PutUint16(opt[48:], 6)                 // subsystem version
	le.PutUint32(opt[56:], textRVA+sectAlign) // SizeOfImage
	le.PutUint32(opt[60:], headersSize)
	le.PutUint16(opt[68:], 3)      // IMAGE_SUBSYSTEM_WINDOWS_CUI
	le.PutUint16(opt[70:], 0x8160) // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
	le.PutUint64(opt[72:], 0x100000)
	le.PutUint64(opt[80:], 0x1000)
	le.PutUint64(opt[88:], 0x100000)
	le.PutUint64(opt[96:], 0x1000)
	le.PutUint32(opt[108:], 16) // NumberOfRvaAndSizes

	sect := b[sectOff:]
	copy(sect, ".text")
	le.PutUint32(sect[8:], uint32(len(peCode[goarch]))) // VirtualSize
	le.PutUint32(sect[12:], textRVA)
	le.PutUint32(sect[16:], textSize)
	le.PutUint32(sect[20:], headersSize)
	le.PutUint32(sect[36:], 0x60000020) // CODE | EXECUTE | READ

	copy(b[headersSize:], peCode[goarch])
	return b, nil
}

// PE returns MinimalPE(goarch). Callers get their own copy.
func PE(t testing.TB, goarch string) []byte {
	t.Helper()
	b, err := MinimalPE(goarch)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SignPE returns data with an Authenticode signature by the leaf
// certificate.
func (tr *Trust) SignPE(t testing.TB, data []byte) []byte {
	t.Helper()
	out, err := sign.SignPE(context.Background(), data, &sign.CodeSigner{Key: tr.CodeKey, Certificate: tr.CodeCert})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
