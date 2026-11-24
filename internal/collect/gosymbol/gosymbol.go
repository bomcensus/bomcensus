// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package gosymbol tells which functions a Go executable links, from its
// function table (pclntab), including functions inlined into others.
//
// It reads ELF and PE files built by Go 1.18 or later. Names are looked up
// in the table; the file is never searched for byte strings. Inlined
// functions leave no entry of their own, so a name missing from the table is
// reported absent only when the inline trees of all functions could be
// read. Their offsets are relative to go:func.*, whose address comes from
// the symbol table or, in a binary stripped of it (-ldflags=-s), from the
// runtime's module data (moduledata.go). When neither yields it, a missing
// name is not checked.
//
// The input is untrusted: sizes and counts are bounded and a malformed file
// gives an error, never a panic.
package gosymbol

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Result of looking up one name.
type Result string

const (
	Present    Result = "present"
	Absent     Result = "absent"
	NotChecked Result = "not_checked"
)

// Bounds of the input.
const (
	maxTable      = 512 << 20 // pclntab bytes
	maxFuncs      = 4 << 20
	maxScan       = 1 << 30 // section bytes searched for a pclntab header
	maxInlineRead = 64 << 20
)

// ErrNotGo is returned for a file without a Go function table.
var ErrNotGo = errors.New("gosymbol: no Go function table")

// Binary is the function names of one executable.
type Binary struct {
	// funcs are the normalized names of the functions in the table and,
	// when inlineKnown, of the functions inlined into them.
	funcs       map[string]bool
	inlineKnown bool
}

// InlineKnown reports whether inlined functions were read, so that a name
// missing from the binary is absent rather than not checked.
func (b *Binary) InlineKnown() bool { return b.inlineKnown }

// Lookup reports whether the binary links the function named path.Symbol as
// the Go vulnerability database writes it ("net/http.Server.Serve",
// "pkg.(*T).M" or "pkg.T.M"). A closure of the function counts as the
// function.
func (b *Binary) Lookup(name string) Result {
	if b.funcs[Normalize(name)] {
		return Present
	}
	if b.inlineKnown {
		return Absent
	}
	return NotChecked
}

// Normalize returns the form names are compared in: receiver parentheses
// and the star removed ("pkg.(*T).M" → "pkg.T.M"), type arguments removed
// ("pkg.F[...]" → "pkg.F"), and the vendor prefix of the standard library
// and the Go command removed.
func Normalize(name string) string {
	name = strings.TrimPrefix(name, "vendor/")
	name = strings.TrimPrefix(name, "cmd/vendor/")
	if strings.IndexByte(name, '[') >= 0 {
		var sb strings.Builder
		depth := 0
		for _, r := range name {
			switch {
			case r == '[':
				depth++
			case r == ']' && depth > 0:
				depth--
			case depth == 0:
				sb.WriteRune(r)
			}
		}
		name = sb.String()
	}
	name = strings.ReplaceAll(name, "(*", "")
	return strings.ReplaceAll(name, ")", "")
}

// closureBase trims the closure and wrapper suffixes the compiler adds
// ("F.func1.2", "F.gowrap1", "T.M-fm").
func closureBase(name string) string {
	for {
		trimmed := strings.TrimSuffix(name, "-fm")
		i := strings.LastIndexByte(trimmed, '.')
		if i < 0 {
			return trimmed
		}
		last := trimmed[i+1:]
		if !isGenerated(last) {
			return trimmed
		}
		name = trimmed[:i]
	}
}

func isGenerated(seg string) bool {
	for _, p := range []string{"func", "gowrap", "deferwrap"} {
		if rest, ok := strings.CutPrefix(seg, p); ok && rest != "" && allDigits(rest) {
			return true
		}
	}
	return seg != "" && allDigits(seg)
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// image is what Open needs from an executable format.
type image struct {
	order binary.ByteOrder
	// table is the pclntab, nil when not found by name, and tableAddr its
	// virtual address.
	table     []byte
	tableAddr uint64
	// gofunc is the address of go:func.*, 0 when unknown.
	gofunc uint64
	// read reads n bytes at a virtual address.
	read func(addr uint64, n int) ([]byte, error)
	// scan are the sections to search for a pclntab header, data the
	// writable ones that hold the module data.
	scan, data []section
	// relative returns the relative relocations of a position-independent
	// ELF file (address and addend), nil for other files.
	relative func() []reloc
}

type section struct {
	r    io.ReaderAt
	size int64
	addr uint64
}

// Open reads the function table of an ELF or PE executable.
func Open(r io.ReaderAt) (b *Binary, err error) {
	defer func() {
		if p := recover(); p != nil {
			b, err = nil, fmt.Errorf("gosymbol: malformed executable: %v", p)
		}
	}()
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		return nil, ErrNotGo
	}
	var img *image
	switch {
	case bytes.Equal(magic[:], []byte("\x7fELF")):
		img, err = openELF(r)
	case magic[0] == 'M' && magic[1] == 'Z':
		img, err = openPE(r)
	default:
		return nil, ErrNotGo
	}
	if err != nil {
		return nil, err
	}
	table := img.table
	if table == nil {
		if table, err = findTable(img); err != nil {
			return nil, err
		}
	}
	return parse(img, table)
}

func openELF(r io.ReaderAt) (*image, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, ErrNotGo
	}
	img := &image{order: f.ByteOrder}
	for _, name := range []string{".gopclntab", ".data.rel.ro.gopclntab"} {
		if s := f.Section(name); s != nil && s.Type != elf.SHT_NOBITS {
			if s.Size > maxTable {
				return nil, errors.New("gosymbol: function table too large")
			}
			if img.table, err = s.Data(); err != nil {
				return nil, fmt.Errorf("gosymbol: read function table: %w", err)
			}
			img.tableAddr = s.Addr
			break
		}
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name == "go:func.*" || s.Name == "go.func.*" {
				img.gofunc = s.Value
				break
			}
		}
	}
	img.read = func(addr uint64, n int) ([]byte, error) {
		for _, s := range f.Sections {
			if s.Type == elf.SHT_NOBITS || s.Flags&elf.SHF_ALLOC == 0 || addr < s.Addr || addr-s.Addr >= s.Size {
				continue
			}
			if uint64(n) > s.Size-(addr-s.Addr) {
				n = int(s.Size - (addr - s.Addr))
			}
			buf := make([]byte, n)
			if _, err := s.ReadAt(buf, int64(addr-s.Addr)); err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return buf, nil
		}
		return nil, fmt.Errorf("gosymbol: address %#x is in no section", addr)
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOBITS && s.Flags&elf.SHF_ALLOC != 0 && s.Flags&elf.SHF_EXECINSTR == 0 {
			sec := section{r: s, size: int64(s.Size), addr: s.Addr}
			img.scan = append(img.scan, sec)
			if s.Flags&elf.SHF_WRITE != 0 {
				img.data = append(img.data, sec)
			}
		}
	}
	img.relative = func() []reloc { return elfRelative(f) }
	return img, nil
}

func openPE(r io.ReaderAt) (*image, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, ErrNotGo
	}
	var base uint64
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		base = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		base = oh.ImageBase
	}
	img := &image{order: binary.LittleEndian}
	sym := func(name string) (uint64, *pe.Section, bool) {
		for _, s := range f.Symbols {
			if s.Name != name || s.SectionNumber <= 0 || int(s.SectionNumber) > len(f.Sections) {
				continue
			}
			sec := f.Sections[s.SectionNumber-1]
			return base + uint64(sec.VirtualAddress) + uint64(s.Value), sec, true
		}
		return 0, nil, false
	}
	if start, sec, ok := sym("runtime.pclntab"); ok {
		if end, _, ok := sym("runtime.epclntab"); ok && end > start && end-start <= maxTable {
			off := start - base - uint64(sec.VirtualAddress)
			buf := make([]byte, end-start)
			if _, err := sec.ReadAt(buf, int64(off)); err == nil {
				img.table, img.tableAddr = buf, start
			}
		}
	}
	for _, name := range []string{"go:func.*", "go.func.*"} {
		if a, _, ok := sym(name); ok {
			img.gofunc = a
			break
		}
	}
	img.read = func(addr uint64, n int) ([]byte, error) {
		if addr < base {
			return nil, fmt.Errorf("gosymbol: address %#x below the image base", addr)
		}
		rva := addr - base
		for _, s := range f.Sections {
			size := uint64(max(s.VirtualSize, s.Size))
			if rva < uint64(s.VirtualAddress) || rva-uint64(s.VirtualAddress) >= size {
				continue
			}
			off := rva - uint64(s.VirtualAddress)
			if uint64(n) > uint64(s.Size)-min(off, uint64(s.Size)) {
				n = int(uint64(s.Size) - min(off, uint64(s.Size)))
			}
			buf := make([]byte, n)
			if _, err := s.ReadAt(buf, int64(off)); err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return buf, nil
		}
		return nil, fmt.Errorf("gosymbol: address %#x is in no section", addr)
	}
	for _, s := range f.Sections {
		if s.Characteristics&pe.IMAGE_SCN_CNT_CODE == 0 {
			sec := section{r: s, size: int64(min(s.Size, s.VirtualSize)), addr: base + uint64(s.VirtualAddress)}
			if s.VirtualSize == 0 {
				sec.size = int64(s.Size)
			}
			img.scan = append(img.scan, sec)
			if s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0 {
				img.data = append(img.data, sec)
			}
		}
	}
	return img, nil
}

// Header magics of the pclntab formats this package reads.
const (
	magic118 = 0xfffffff0 // Go 1.18, 1.19
	magic120 = 0xfffffff1 // Go 1.20 and later
)

// findTable searches data sections for a pclntab header, for binaries whose
// section or symbols do not name it.
func findTable(img *image) ([]byte, error) {
	var scanned int64
	for _, s := range img.scan {
		size := s.size
		if size <= 0 || scanned+size > maxScan {
			continue
		}
		scanned += size
		buf := make([]byte, size)
		if _, err := s.r.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
			continue
		}
		for off := 0; off+16 <= len(buf); off += 4 {
			m := img.order.Uint32(buf[off:])
			if m != magic118 && m != magic120 {
				continue
			}
			if t := buf[off:]; plausibleHeader(img.order, t) {
				if _, err := parseTable(img.order, t); err == nil {
					img.tableAddr = s.addr + uint64(off)
					return t, nil
				}
			}
		}
	}
	return nil, ErrNotGo
}

func plausibleHeader(order binary.ByteOrder, t []byte) bool {
	if len(t) < 8 || t[4] != 0 || t[5] != 0 {
		return false
	}
	minLC, ptr := t[6], t[7]
	return (minLC == 1 || minLC == 2 || minLC == 4) && (ptr == 4 || ptr == 8)
}

// table is a parsed pclntab.
type table struct {
	order   binary.ByteOrder
	go120   bool
	ptrSize int
	minLC   uint32
	nfunc   int
	// hdr are the header words: nfunc, nfiles, textStart, funcnameOffset,
	// cuOffset, filetabOffset, pctabOffset, pclnOffset.
	hdr       [8]uint64
	funcnames []byte
	pctab     []byte
	pcln      []byte // from the function table on
}

func parseTable(order binary.ByteOrder, t []byte) (*table, error) {
	bad := func(what string) error { return fmt.Errorf("gosymbol: function table: %s", what) }
	if !plausibleHeader(order, t) {
		return nil, bad("header")
	}
	m := order.Uint32(t)
	if m != magic118 && m != magic120 {
		return nil, bad("unsupported format")
	}
	tb := &table{order: order, go120: m == magic120, minLC: uint32(t[6]), ptrSize: int(t[7])}
	word := func(i int) (uint64, bool) {
		off := 8 + i*tb.ptrSize
		if off+tb.ptrSize > len(t) {
			return 0, false
		}
		if tb.ptrSize == 4 {
			return uint64(order.Uint32(t[off:])), true
		}
		return order.Uint64(t[off:]), true
	}
	// nfunc, nfiles, textStart, funcnameOffset, cuOffset, filetabOffset,
	// pctabOffset, pclnOffset.
	var w [8]uint64
	for i := range w {
		v, ok := word(i)
		if !ok {
			return nil, bad("header")
		}
		w[i] = v
	}
	if w[0] == 0 || w[0] > maxFuncs {
		return nil, bad("function count")
	}
	tb.nfunc = int(w[0])
	tb.hdr = w
	sub := func(off uint64) ([]byte, bool) {
		if off >= uint64(len(t)) {
			return nil, false
		}
		return t[off:], true
	}
	var ok bool
	if tb.funcnames, ok = sub(w[3]); !ok {
		return nil, bad("name table")
	}
	if tb.pctab, ok = sub(w[6]); !ok {
		return nil, bad("pc table")
	}
	if tb.pcln, ok = sub(w[7]); !ok {
		return nil, bad("function index")
	}
	if len(tb.pcln) < (2*tb.nfunc+1)*4 {
		return nil, bad("function index")
	}
	// Entries are in address order.
	var prev uint32
	for i := 0; i < tb.nfunc; i++ {
		e := order.Uint32(tb.pcln[8*i:])
		if i > 0 && e < prev {
			return nil, bad("function index order")
		}
		prev = e
	}
	return tb, nil
}

// name reads a NUL-terminated name from the name table.
func (tb *table) name(off int64) (string, bool) {
	if off < 0 || off >= int64(len(tb.funcnames)) {
		return "", false
	}
	rest := tb.funcnames[off:]
	end := bytes.IndexByte(rest, 0)
	if end <= 0 || end > 4096 || !utf8.Valid(rest[:end]) {
		return "", false
	}
	return string(rest[:end]), true
}

// Indexes of the runtime's per-function tables (internal/abi).
const (
	pcdataInlTreeIndex = 2
	funcdataInlTree    = 3
)

// fn is the part of a runtime _func this package reads.
type fn struct {
	nameOff      int32
	inlTreeIndex uint32 // pctab offset, 0 when none
	inlTree      uint32 // offset from go:func.*, ^0 when none
}

func (tb *table) fn(i int) (fn, bool) {
	o := tb.order
	funcOff := o.Uint32(tb.pcln[8*i+4:])
	if uint64(funcOff) >= uint64(len(tb.pcln)) {
		return fn{}, false
	}
	f := tb.pcln[funcOff:]
	// entryOff, nameOff, args, deferreturn, pcsp, pcfile, pcln, npcdata,
	// cuOffset, [startLine (1.20+)], funcID, flag, _, nfuncdata.
	fixed := 40
	if tb.go120 {
		fixed = 44
	}
	if len(f) < fixed {
		return fn{}, false
	}
	out := fn{nameOff: int32(o.Uint32(f[4:])), inlTree: ^uint32(0)}
	npcdata := int(o.Uint32(f[28:]))
	nfuncdata := int(f[fixed-1])
	if npcdata > 64 || len(f) < fixed+4*(npcdata+nfuncdata) {
		return fn{}, false
	}
	if npcdata > pcdataInlTreeIndex {
		out.inlTreeIndex = o.Uint32(f[fixed+4*pcdataInlTreeIndex:])
	}
	if nfuncdata > funcdataInlTree {
		out.inlTree = o.Uint32(f[fixed+4*npcdata+4*funcdataInlTree:])
	}
	return out, true
}

// inlineIndexes decodes a pc-value table and returns the distinct values
// that are not negative.
func (tb *table) inlineIndexes(off uint32) ([]int32, bool) {
	if uint64(off) >= uint64(len(tb.pctab)) {
		return nil, false
	}
	p := tb.pctab[off:]
	val := int32(-1)
	seen := map[int32]bool{}
	var out []int32
	for first := true; ; first = false {
		uv, n := binary.Uvarint(p)
		if n <= 0 || uv > 0xffffffff {
			return nil, false
		}
		if uv == 0 && !first {
			return out, true
		}
		p = p[n:]
		d := uint32(uv)
		if d&1 != 0 {
			d = ^(d >> 1)
		} else {
			d >>= 1
		}
		val += int32(d)
		if _, n = binary.Uvarint(p); n <= 0 {
			return nil, false
		}
		p = p[n:]
		if val >= 0 && !seen[val] {
			if len(seen) > 1<<16 {
				return nil, false
			}
			seen[val] = true
			out = append(out, val)
		}
	}
}

func parse(img *image, raw []byte) (*Binary, error) {
	tb, err := parseTable(img.order, raw)
	if err != nil {
		return nil, err
	}
	if img.gofunc == 0 {
		img.gofunc = findGofunc(img, tb)
	}
	b := &Binary{funcs: make(map[string]bool, tb.nfunc), inlineKnown: img.gofunc != 0}
	add := func(name string) {
		n := Normalize(name)
		b.funcs[n] = true
		if base := closureBase(n); base != n {
			b.funcs[base] = true
		}
	}
	// runtime.inlinedCall: its size and where the name offset is.
	// Go 1.20+: funcID, pad, nameOff, parentPc, startLine.
	// Go 1.18, 1.19: parent, funcID, pad, file, line, func_, parentPc.
	entry, nameAt := 16, 4
	if !tb.go120 {
		entry, nameAt = 20, 12
	}
	var inlineRead int
	for i := 0; i < tb.nfunc; i++ {
		f, ok := tb.fn(i)
		if !ok {
			return nil, errors.New("gosymbol: function table: function record")
		}
		name, ok := tb.name(int64(f.nameOff))
		if !ok {
			return nil, errors.New("gosymbol: function table: function name")
		}
		add(name)
		if !b.inlineKnown || f.inlTree == ^uint32(0) || f.inlTreeIndex == 0 {
			continue
		}
		idx, ok := tb.inlineIndexes(f.inlTreeIndex)
		if !ok {
			b.inlineKnown = false
			continue
		}
		var maxIdx int32
		for _, x := range idx {
			maxIdx = max(maxIdx, x)
		}
		n := int(maxIdx+1) * entry
		inlineRead += n
		if inlineRead > maxInlineRead {
			b.inlineKnown = false
			continue
		}
		tree, err := img.read(img.gofunc+uint64(f.inlTree), n)
		if err != nil || len(tree) < n {
			b.inlineKnown = false
			continue
		}
		// Every entry up to the largest index: an inlined function whose
		// body is only another inlined call has no pc of its own, and the
		// compiler numbers a parent before its children.
		for x := 0; x <= int(maxIdx); x++ {
			nameOff := int32(img.order.Uint32(tree[x*entry+nameAt:]))
			inl, ok := tb.name(int64(nameOff))
			if !ok {
				b.inlineKnown = false
				break
			}
			add(inl)
		}
	}
	return b, nil
}
