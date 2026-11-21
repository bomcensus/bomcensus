// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// rpm "ndb" database (Packages.db, rpm lib/backend/ndb/rpmpkg.c): a header,
// slot pages pointing at blobs, and the blobs in 16-byte blocks. All numbers
// are little endian.

const (
	ndbHeaderMagic = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	ndbSlotMagic   = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
	ndbBlobMagic   = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24

	ndbPageSize      = 4096
	ndbSlotSize      = 16
	ndbBlockSize     = 16
	ndbBlobHeadSize  = 16
	ndbMaxSlotPages  = 2048
	ndbHeaderSlots   = 2 // the file header occupies the first two slots
	ndbSlotsPerPage  = ndbPageSize / ndbSlotSize
	ndbHeaderVersion = 0
)

var errNotNDB = errors.New("not an rpm ndb database")

type ndbFile struct {
	r     io.ReaderAt
	size  int64
	slots []byte
	// short is set when the file ends inside the slot area.
	short bool
}

func openNDB(r io.ReaderAt, size int64) (*ndbFile, error) {
	hdr := make([]byte, 32)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", errNotNDB, err)
	}
	if binary.LittleEndian.Uint32(hdr[0:4]) != ndbHeaderMagic || binary.LittleEndian.Uint32(hdr[4:8]) != ndbHeaderVersion {
		return nil, errNotNDB
	}
	npages := binary.LittleEndian.Uint32(hdr[12:16])
	if npages == 0 || npages > ndbMaxSlotPages {
		return nil, fmt.Errorf("%w: %d slot pages", errNotNDB, npages)
	}
	n := &ndbFile{r: r, size: size}
	area := int64(npages) * ndbPageSize
	if area > size {
		area = size - size%ndbSlotSize
		n.short = true
	}
	n.slots = make([]byte, area)
	if _, err := r.ReadAt(n.slots, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return n, nil
}

func (n *ndbFile) each(ctx context.Context, fn func([]byte) bool) (skipped int, err error) {
	head := make([]byte, ndbBlobHeadSize)
	for i := ndbHeaderSlots; (i+1)*ndbSlotSize <= len(n.slots); i++ {
		if i%ndbSlotsPerPage == 0 {
			if err := ctx.Err(); err != nil {
				return skipped, err
			}
		}
		s := n.slots[i*ndbSlotSize : (i+1)*ndbSlotSize]
		if binary.LittleEndian.Uint32(s[0:4]) != ndbSlotMagic {
			skipped++
			continue
		}
		idx := binary.LittleEndian.Uint32(s[4:8])
		if idx == 0 {
			continue // free slot
		}
		blk := int64(binary.LittleEndian.Uint32(s[8:12]))
		cnt := int64(binary.LittleEndian.Uint32(s[12:16]))
		off := blk * ndbBlockSize
		if off+ndbBlobHeadSize > n.size {
			skipped++
			continue
		}
		if _, err := n.r.ReadAt(head, off); err != nil {
			skipped++
			continue
		}
		blen := int64(binary.LittleEndian.Uint32(head[12:16]))
		if binary.LittleEndian.Uint32(head[0:4]) != ndbBlobMagic ||
			binary.LittleEndian.Uint32(head[4:8]) != idx ||
			blen > maxBlob ||
			ndbBlobHeadSize+blen > cnt*ndbBlockSize ||
			off+ndbBlobHeadSize+blen > n.size {
			skipped++
			continue
		}
		blob := make([]byte, blen)
		if _, err := n.r.ReadAt(blob, off+ndbBlobHeadSize); err != nil {
			skipped++
			continue
		}
		if !fn(blob) {
			return skipped, nil
		}
	}
	if n.short {
		return skipped, errors.New("file ends inside the slot area")
	}
	return skipped, nil
}
