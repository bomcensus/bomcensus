// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// MaxDecodedSize bounds the decompressed size of a report.
const MaxDecodedSize = 512 << 20

// Encode writes r as zstd-compressed JSON.
func Encode(w io.Writer, r *Report) error {
	zw, err := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return fmt.Errorf("report: new zstd writer: %w", err)
	}
	if err := json.NewEncoder(zw).Encode(r); err != nil {
		zw.Close()
		return fmt.Errorf("report: encode: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("report: finish zstd stream: %w", err)
	}
	return nil
}

// Decode reads a report written by Encode. It rejects reports that are larger
// than MaxDecodedSize after decompression or that use a newer schema.
func Decode(rd io.Reader) (*Report, error) {
	zr, err := zstd.NewReader(rd, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxDecodedSize))
	if err != nil {
		return nil, fmt.Errorf("report: new zstd reader: %w", err)
	}
	defer zr.Close()

	limited := &io.LimitedReader{R: zr, N: MaxDecodedSize + 1}
	var r Report
	if err := json.NewDecoder(limited).Decode(&r); err != nil {
		return nil, fmt.Errorf("report: decode: %w", err)
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("report: larger than %d bytes after decompression", MaxDecodedSize)
	}
	if r.SchemaVersion < 1 || r.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("report: unsupported schema version %d", r.SchemaVersion)
	}
	return &r, nil
}

// Digest returns the hex SHA-256 of the JSON encoding of body. Callers pass
// the section's items (not its SectionMeta), so that the timestamp of a run
// does not change the digest. Slices must be in a stable order.
func Digest(body any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return "", fmt.Errorf("report: digest: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}
