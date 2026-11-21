// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkgdb

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	// maxLine bounds one line of a text database. Longer lines are cut and
	// the rest is discarded.
	maxLine = 1 << 20
	// maxField bounds a value copied into the report.
	maxField = 1024
)

// lineReader reads newline-terminated lines with a length bound, so a file
// without newlines cannot make it buffer without limit.
type lineReader struct {
	r *bufio.Reader
	// long is set once a line was cut at maxLine.
	long bool
	// unterminated is set when the input did not end with a newline.
	unterminated bool
	err          error
	buf          []byte
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 64<<10)}
}

// next returns the next line without its line ending. The slice is only
// valid until the following call. ok is false at the end of input or on a
// read error (see err).
func (lr *lineReader) next() (line []byte, ok bool) {
	lr.buf = lr.buf[:0]
	read := false
	for {
		frag, err := lr.r.ReadSlice('\n')
		if len(frag) > 0 {
			read = true
		}
		if room := maxLine - len(lr.buf); room > 0 {
			if len(frag) > room {
				lr.buf = append(lr.buf, frag[:room]...)
				lr.long = true
			} else {
				lr.buf = append(lr.buf, frag...)
			}
		} else if len(frag) > 0 {
			lr.long = true
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				lr.err = err
				return nil, false
			}
			if !read {
				return nil, false
			}
			lr.unterminated = true
		}
		break
	}
	line = bytes.TrimSuffix(lr.buf, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	return line, true
}

// clean bounds a value for the report and makes it valid UTF-8.
func clean(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > maxField {
		b = b[:maxField]
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

func cleanString(s string) string {
	return clean([]byte(s))
}
