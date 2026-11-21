// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
)

// rpm header tags (rpmtag.h).
const (
	tagName            = 1000
	tagVersion         = 1001
	tagRelease         = 1002
	tagEpoch           = 1003
	tagVendor          = 1011
	tagPackager        = 1015
	tagArch            = 1022
	tagOldFilenames    = 1027
	tagFileModes       = 1030
	tagSourceRPM       = 1044
	tagDirIndexes      = 1116
	tagBasenames       = 1117
	tagDirNames        = 1118
	tagModularityLabel = 5096
)

// rpm header data types.
const (
	typeChar        = 1
	typeInt8        = 2
	typeInt16       = 3
	typeInt32       = 4
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
)

const (
	// maxHeaderTags and maxHeaderData are rpm's own limits
	// (HEADER_TAGS_MAX, HEADER_DATA_MAX).
	maxHeaderTags = 0xffff
	maxHeaderData = 0x0fffffff
	// maxBlob bounds one stored header.
	maxBlob = 32 << 20
)

var errHeader = errors.New("malformed rpm header")

type hdrEntry struct {
	typ    uint32
	offset uint32
	count  uint32
}

// rpmHeader is a parsed header blob as stored in the rpm database: a count of
// index entries, a data length, the index and the data store. Only the
// requested tags are kept.
type rpmHeader struct {
	data    []byte
	entries map[int32]hdrEntry
}

var pkgTags = []int32{tagName, tagVersion, tagRelease, tagEpoch, tagVendor, tagPackager, tagArch, tagSourceRPM, tagModularityLabel}

var fileTags = []int32{tagName, tagOldFilenames, tagFileModes, tagDirIndexes, tagBasenames, tagDirNames}

func parseRPMHeader(blob []byte, tags []int32) (*rpmHeader, error) {
	if len(blob) < 8 {
		return nil, errHeader
	}
	il := binary.BigEndian.Uint32(blob[0:4])
	dl := binary.BigEndian.Uint32(blob[4:8])
	if il == 0 || il > maxHeaderTags || dl > maxHeaderData {
		return nil, errHeader
	}
	dataStart := 8 + uint64(il)*16
	if dataStart+uint64(dl) > uint64(len(blob)) {
		return nil, fmt.Errorf("%w: truncated", errHeader)
	}
	h := &rpmHeader{
		data:    blob[dataStart : dataStart+uint64(dl)],
		entries: make(map[int32]hdrEntry, len(tags)),
	}
	for i := uint64(0); i < uint64(il); i++ {
		e := blob[8+i*16 : 8+i*16+16]
		tag := int32(binary.BigEndian.Uint32(e[0:4]))
		if !slices.Contains(tags, tag) {
			continue
		}
		if _, dup := h.entries[tag]; dup {
			continue
		}
		h.entries[tag] = hdrEntry{
			typ:    binary.BigEndian.Uint32(e[4:8]),
			offset: binary.BigEndian.Uint32(e[8:12]),
			count:  binary.BigEndian.Uint32(e[12:16]),
		}
	}
	return h, nil
}

// strs returns the strings of a string-typed tag.
func (h *rpmHeader) strs(tag int32) ([]string, error) {
	e, ok := h.entries[tag]
	if !ok {
		return nil, nil
	}
	switch e.typ {
	case typeString:
		if e.count != 1 {
			return nil, errHeader
		}
	case typeStringArray, typeI18NString:
	default:
		return nil, errHeader
	}
	if uint64(e.offset) >= uint64(len(h.data)) || uint64(e.count) > uint64(len(h.data)) {
		return nil, errHeader
	}
	d := h.data[e.offset:]
	out := make([]string, 0, min(e.count, 4096))
	for range e.count {
		i := bytes.IndexByte(d, 0)
		if i < 0 {
			return nil, errHeader
		}
		out = append(out, string(d[:i]))
		d = d[i+1:]
	}
	return out, nil
}

// str returns the first string of a string-typed tag.
func (h *rpmHeader) str(tag int32) (string, error) {
	s, err := h.strs(tag)
	if err != nil || len(s) == 0 {
		return "", err
	}
	return s[0], nil
}

func (h *rpmHeader) ints(tag int32) ([]uint32, error) {
	e, ok := h.entries[tag]
	if !ok {
		return nil, nil
	}
	var size uint64
	switch e.typ {
	case typeInt32:
		size = 4
	case typeInt16:
		size = 2
	case typeChar, typeInt8:
		size = 1
	default:
		return nil, errHeader
	}
	end := uint64(e.offset) + uint64(e.count)*size
	if end > uint64(len(h.data)) {
		return nil, errHeader
	}
	d := h.data[e.offset:end]
	out := make([]uint32, e.count)
	for i := range out {
		switch size {
		case 4:
			out[i] = binary.BigEndian.Uint32(d[i*4:])
		case 2:
			out[i] = uint32(binary.BigEndian.Uint16(d[i*2:]))
		default:
			out[i] = uint32(d[i])
		}
	}
	return out, nil
}

// rpmPackage converts a header. ok is false for entries that are not
// packages (gpg-pubkey).
func rpmPackage(h *rpmHeader) (p report.Package, ok bool, err error) {
	var first error
	get := func(tag int32) string {
		s, err := h.str(tag)
		if err != nil && first == nil {
			first = err
		}
		return cleanString(s)
	}
	name := get(tagName)
	version := get(tagVersion)
	release := get(tagRelease)
	arch := get(tagArch)
	srpm := get(tagSourceRPM)
	vendor := get(tagVendor)
	packager := get(tagPackager)
	label := get(tagModularityLabel)
	epochs, err := h.ints(tagEpoch)
	if err != nil && first == nil {
		first = err
	}
	if first != nil {
		return p, false, first
	}
	if name == "" || version == "" {
		return p, false, fmt.Errorf("%w: no name or version", errHeader)
	}
	if name == "gpg-pubkey" {
		return p, false, nil
	}
	evr := version
	if release != "" {
		evr += "-" + release
	}
	epoch := ""
	if len(epochs) > 0 && epochs[0] != 0 {
		epoch = strconv.FormatUint(uint64(epochs[0]), 10) + ":"
	}
	p = report.Package{
		Type:            report.PackageRPM,
		Name:            name,
		Version:         epoch + evr,
		Arch:            arch,
		Vendor:          vendor,
		Maintainer:      packager,
		ModularityLabel: label,
	}
	if sn, sv, ok := parseSourceRPM(srpm); ok {
		p.SourceName = sn
		p.SourceVersion = epoch + sv
	} else {
		p.SourceName = name
		p.SourceVersion = p.Version
	}
	return p, true, nil
}

// parseSourceRPM splits "name-version-release.src.rpm" into the name and
// "version-release".
func parseSourceRPM(s string) (name, vr string, ok bool) {
	switch {
	case strings.HasSuffix(s, ".src.rpm"):
		s = strings.TrimSuffix(s, ".src.rpm")
	case strings.HasSuffix(s, ".nosrc.rpm"):
		s = strings.TrimSuffix(s, ".nosrc.rpm")
	default:
		return "", "", false
	}
	r := strings.LastIndexByte(s, '-')
	if r <= 0 {
		return "", "", false
	}
	v := strings.LastIndexByte(s[:r], '-')
	if v <= 0 {
		return "", "", false
	}
	return s[:v], s[v+1:], true
}

// rpmFiles returns the package name and the absolute paths of the files that
// are not directories.
func rpmFiles(h *rpmHeader) (name string, files []string, err error) {
	name, err = h.str(tagName)
	if err != nil || name == "" || name == "gpg-pubkey" {
		return "", nil, err
	}
	modes, err := h.ints(tagFileModes)
	if err != nil {
		return name, nil, err
	}
	isDir := func(i int) bool {
		return i < len(modes) && modes[i]&0o170000 == 0o040000
	}
	base, err := h.strs(tagBasenames)
	if err != nil {
		return name, nil, err
	}
	if len(base) == 0 {
		old, err := h.strs(tagOldFilenames)
		if err != nil {
			return name, nil, err
		}
		for i, f := range old {
			if !isDir(i) {
				files = append(files, f)
			}
		}
		return name, files, nil
	}
	dirs, err := h.strs(tagDirNames)
	if err != nil {
		return name, nil, err
	}
	idx, err := h.ints(tagDirIndexes)
	if err != nil {
		return name, nil, err
	}
	if len(idx) != len(base) {
		return name, nil, fmt.Errorf("%w: file list sizes differ", errHeader)
	}
	files = make([]string, 0, len(base))
	for i, b := range base {
		if isDir(i) {
			continue
		}
		if int(idx[i]) >= len(dirs) {
			return name, files, fmt.Errorf("%w: directory index out of range", errHeader)
		}
		files = append(files, dirs[idx[i]]+b)
	}
	return name, files, nil
}
