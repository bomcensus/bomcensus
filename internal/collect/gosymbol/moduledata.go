// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package gosymbol

import (
	"debug/elf"
	"errors"
	"io"
)

// The runtime's moduledata (runtime/symtab.go) starts with pointers into the
// pclntab and holds the address of go:func.* in its gofunc field, so a binary
// without a symbol table still has it. Fields, in pointer-size words:
//
//	0      pcHeader
//	1-3    funcnametab slice
//	13-15  pclntable slice
//	38     gofunc (Go 1.18, 1.19)
//	40     gofunc (Go 1.20 and later, after covctrs, ecovctrs)
const (
	mdHeader      = 0
	mdFuncnametab = 1
	mdPclntable   = 13
	mdGofunc118   = 38
	mdGofunc120   = 40
)

// Bounds of the module data search.
const (
	maxDataScan = 256 << 20 // writable section bytes
	maxRelocs   = 4 << 20
	maxRelaSize = 256 << 20
)

type reloc struct{ off, addend uint64 }

// findGofunc returns the gofunc field of the module data that points at the
// pclntab, or 0. A candidate counts only when its name table and function
// table pointers match the pclntab header too.
func findGofunc(img *image, tb *table) uint64 {
	if img.tableAddr == 0 || len(img.data) == 0 {
		return 0
	}
	ps := uint64(tb.ptrSize)
	last := mdGofunc118
	if tb.go120 {
		last = mdGofunc120
	}
	want := map[int]uint64{
		mdHeader:      img.tableAddr,
		mdFuncnametab: img.tableAddr + tb.hdr[3],
		mdPclntable:   img.tableAddr + tb.hdr[7],
	}
	ptr := func(b []byte) uint64 {
		if ps == 4 {
			return uint64(img.order.Uint32(b))
		}
		return img.order.Uint64(b)
	}
	// check reads the module data at addr, with words patched by rel.
	check := func(addr uint64, rel map[uint64]uint64) uint64 {
		raw, err := img.read(addr, (last+1)*int(ps))
		if err != nil || len(raw) < (last+1)*int(ps) {
			return 0
		}
		word := func(i int) uint64 {
			a := addr + uint64(i)*ps
			if v, ok := rel[a]; ok {
				return v
			}
			return ptr(raw[uint64(i)*ps:])
		}
		for i, v := range want {
			if word(i) != v {
				return 0
			}
		}
		return word(last)
	}

	// Pointers stored in place: executables that are not position
	// independent, and PE files, which keep the preferred addresses.
	var scanned int64
	for _, s := range img.data {
		if s.size <= 0 || scanned+s.size > maxDataScan {
			continue
		}
		scanned += s.size
		buf := make([]byte, s.size)
		if _, err := s.r.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
			continue
		}
		for off := uint64(0); off+ps <= uint64(len(buf)); off += ps {
			if ptr(buf[off:]) != img.tableAddr {
				continue
			}
			if g := check(s.addr+off, nil); g != 0 {
				return g
			}
		}
	}

	// Position-independent ELF: the pointers are relocation addends.
	if img.relative == nil {
		return 0
	}
	rels := img.relative()
	for _, r := range rels {
		if r.addend != img.tableAddr {
			continue
		}
		patch := map[uint64]uint64{}
		end := r.off + uint64(last+1)*ps
		for _, q := range rels {
			if q.off >= r.off && q.off < end {
				patch[q.off] = q.addend
			}
		}
		if g := check(r.off, patch); g != 0 {
			return g
		}
	}
	return 0
}

// relativeType is the relative relocation type of each machine Go supports
// as position-independent ELF.
var relativeType = map[elf.Machine]uint32{
	elf.EM_X86_64:    uint32(elf.R_X86_64_RELATIVE),
	elf.EM_AARCH64:   uint32(elf.R_AARCH64_RELATIVE),
	elf.EM_PPC64:     uint32(elf.R_PPC64_RELATIVE),
	elf.EM_RISCV:     uint32(elf.R_RISCV_RELATIVE),
	elf.EM_S390:      uint32(elf.R_390_RELATIVE),
	elf.EM_LOONGARCH: uint32(elf.R_LARCH_RELATIVE),
}

// elfRelative reads the relative relocations with explicit addends of a
// 64-bit ELF file. 32-bit targets keep the addend in place (REL).
func elfRelative(f *elf.File) []reloc {
	typ, ok := relativeType[f.Machine]
	if !ok || f.Class != elf.ELFCLASS64 {
		return nil
	}
	var out []reloc
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA || s.Size > maxRelaSize {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		for off := 0; off+24 <= len(data); off += 24 {
			info := f.ByteOrder.Uint64(data[off+8:])
			if elf.R_SYM64(info) != 0 || elf.R_TYPE64(info) != typ {
				continue
			}
			if len(out) >= maxRelocs {
				return out
			}
			out = append(out, reloc{
				off:    f.ByteOrder.Uint64(data[off:]),
				addend: f.ByteOrder.Uint64(data[off+16:]),
			})
		}
	}
	return out
}
