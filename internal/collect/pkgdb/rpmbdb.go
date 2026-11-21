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

// Berkeley DB hash database, as used by rpm up to 4.15 ("Packages"). Only the
// parts needed to enumerate the stored values are implemented: the metadata
// page, hash pages and overflow page chains.

const (
	bdbHashMagic = 0x061561

	bdbPageHeaderSize = 26

	bdbPageHashUnsorted = 2
	bdbPageOverflow     = 7
	bdbPageHashMeta     = 8
	bdbPageHash         = 13

	bdbItemKeyData = 1
	bdbItemOffPage = 3
	bdbOffPageSize = 12
)

var errNotBDB = errors.New("not a Berkeley DB hash database")

type bdbFile struct {
	r        io.ReaderAt
	order    binary.ByteOrder
	pageSize uint32
	lastPage uint32
	// pages is the number of pages actually present in the file.
	pages uint32
}

func openBDB(r io.ReaderAt, size int64) (*bdbFile, error) {
	meta := make([]byte, 72)
	if _, err := r.ReadAt(meta, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", errNotBDB, err)
	}
	b := &bdbFile{r: r}
	switch {
	case binary.LittleEndian.Uint32(meta[12:16]) == bdbHashMagic:
		b.order = binary.LittleEndian
	case binary.BigEndian.Uint32(meta[12:16]) == bdbHashMagic:
		b.order = binary.BigEndian
	default:
		return nil, errNotBDB
	}
	if meta[25] != bdbPageHashMeta {
		return nil, errNotBDB
	}
	b.pageSize = b.order.Uint32(meta[20:24])
	switch b.pageSize {
	case 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536:
	default:
		return nil, fmt.Errorf("%w: page size %d", errNotBDB, b.pageSize)
	}
	b.lastPage = b.order.Uint32(meta[32:36])
	inFile := size / int64(b.pageSize)
	b.pages = b.lastPage + 1
	if int64(b.pages) > inFile || b.lastPage == ^uint32(0) {
		b.pages = uint32(min(inFile, int64(^uint32(0))))
	}
	return b, nil
}

func (b *bdbFile) readPage(pg uint32, buf []byte) error {
	if pg >= b.pages {
		return fmt.Errorf("page %d beyond end of file", pg)
	}
	_, err := b.r.ReadAt(buf, int64(pg)*int64(b.pageSize))
	return err
}

// each calls fn for every stored value that is not tiny. It keeps going
// after damaged pages and returns how many it skipped. err is set when the
// file is shorter than its metadata says or ctx was cancelled.
func (b *bdbFile) each(ctx context.Context, fn func([]byte) bool) (skipped int, err error) {
	page := make([]byte, b.pageSize)
	ovf := make([]byte, b.pageSize)
	for pg := uint32(1); pg < b.pages; pg++ {
		if pg%256 == 0 {
			if err := ctx.Err(); err != nil {
				return skipped, err
			}
		}
		if err := b.readPage(pg, page); err != nil {
			return skipped, err
		}
		typ := page[25]
		if typ != bdbPageHash && typ != bdbPageHashUnsorted {
			continue
		}
		n := uint32(b.order.Uint16(page[20:22]))
		if n%2 != 0 || bdbPageHeaderSize+2*n > b.pageSize {
			skipped++
			continue
		}
		off := func(i uint32) uint32 {
			return uint32(b.order.Uint16(page[bdbPageHeaderSize+2*i:]))
		}
		for i := uint32(1); i < n; i += 2 {
			start := off(i)
			end := off(i - 1) // items are stored downwards: the key sits above its value
			if start >= b.pageSize || end > b.pageSize || end <= start {
				skipped++
				continue
			}
			item := page[start:end]
			var val []byte
			switch item[0] {
			case bdbItemKeyData:
				val = append([]byte(nil), item[1:]...)
			case bdbItemOffPage:
				if len(item) < bdbOffPageSize {
					skipped++
					continue
				}
				v, err := b.overflow(b.order.Uint32(item[4:8]), b.order.Uint32(item[8:12]), ovf)
				if err != nil {
					skipped++
					continue
				}
				val = v
			default:
				skipped++
				continue
			}
			// The record with key 0 holds a counter, not a header.
			if len(val) < 16 {
				continue
			}
			if !fn(val) {
				return skipped, nil
			}
		}
	}
	if b.pages < b.lastPage+1 {
		return skipped, fmt.Errorf("file is shorter than its metadata (%d of %d pages)", b.pages, b.lastPage+1)
	}
	return skipped, nil
}

// overflow follows a chain of overflow pages and returns the item.
func (b *bdbFile) overflow(pg, total uint32, buf []byte) ([]byte, error) {
	if total == 0 || total > maxBlob {
		return nil, fmt.Errorf("overflow item size %d", total)
	}
	out := make([]byte, 0, total)
	for hops := uint32(0); pg != 0; hops++ {
		if hops > b.pages || uint32(len(out)) >= total {
			return nil, errors.New("overflow chain too long")
		}
		if err := b.readPage(pg, buf); err != nil {
			return nil, err
		}
		if buf[25] != bdbPageOverflow {
			return nil, fmt.Errorf("page %d is not an overflow page", pg)
		}
		n := uint32(b.order.Uint16(buf[22:24]))
		if bdbPageHeaderSize+n > b.pageSize {
			return nil, fmt.Errorf("overflow page %d length %d", pg, n)
		}
		if uint32(len(out))+n > total {
			n = total - uint32(len(out))
		}
		out = append(out, buf[bdbPageHeaderSize:bdbPageHeaderSize+n]...)
		pg = b.order.Uint32(buf[16:20])
	}
	if uint32(len(out)) != total {
		return nil, fmt.Errorf("overflow item has %d of %d bytes", len(out), total)
	}
	return out, nil
}
