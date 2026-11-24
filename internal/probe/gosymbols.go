// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/collect/gosymbol"
	"github.com/bomcensus/bomcensus/internal/report"
)

// fileOpener opens a path of a GoSymbolFile. A nil opener with a non-empty
// reason means that every file of that container is not checked.
type fileOpener func(path string) (*os.File, error)

// answerGoSymbols looks up the names of q in the files it names. openerFor
// returns the opener for a container id ("" for the subject itself) or the
// reason its files cannot be read. Every requested name gets an answer;
// anything that keeps a file from being verified makes all its names
// not checked.
func answerGoSymbols(ctx context.Context, q *report.GoSymbolQuery, openerFor func(container string) (fileOpener, string)) *report.GoSymbolsSection {
	start := time.Now()
	sec := &report.GoSymbolsSection{SectionMeta: report.SectionMeta{Coverage: report.CoverageFull, CollectedAt: start.UTC()}}
	type opener struct {
		open   fileOpener
		reason string
	}
	openers := map[string]opener{}
	for _, f := range q.Files {
		ans := report.GoSymbolAnswer{Container: f.Container, Path: f.Path, SHA256: f.SHA256, Results: map[string]string{}}
		o, ok := openers[f.Container]
		if !ok {
			o.open, o.reason = openerFor(f.Container)
			openers[f.Container] = o
		}
		var reason string
		switch {
		case ctx.Err() != nil:
			reason = "runtime limit reached"
		case o.open == nil:
			reason = o.reason
		default:
			reason = lookupGoSymbols(o.open, f, ans.Results)
		}
		for _, n := range f.Names {
			if _, ok := ans.Results[n]; !ok {
				ans.Results[n] = report.GoSymbolNotChecked
			}
		}
		ans.Reason = reason
		if reason != "" {
			sec.Coverage = report.CoveragePartial
		}
		sec.Files = append(sec.Files, ans)
	}
	sec.DurationMs = time.Since(start).Milliseconds()
	return sec
}

// lookupGoSymbols fills results for one file and returns why names were
// not checked, if any were.
func lookupGoSymbols(open fileOpener, f report.GoSymbolFile, results map[string]string) string {
	fh, err := open(f.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "file no longer exists"
		}
		return fmt.Sprintf("cannot open file: %v", err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return fmt.Sprintf("cannot stat file: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return "not a regular file"
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(fh, 0, fi.Size())); err != nil {
		return fmt.Sprintf("cannot read file: %v", err)
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(f.SHA256) {
		return "file changed since it was reported"
	}
	if _, err := buildinfo.Read(fh); err != nil {
		return "not a Go binary"
	}
	bin, err := gosymbol.Open(fh)
	if err != nil {
		return fmt.Sprintf("function table not readable: %v", err)
	}
	for _, n := range f.Names {
		results[n] = string(bin.Lookup(n))
	}
	if !bin.InlineKnown() {
		return "inlined functions not readable (stripped binary); missing names not checked"
	}
	return ""
}
