// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package winsvc

import (
	"log/slog"
	"strings"
	"testing"
)

type event struct {
	level Level
	msg   string
}

func TestLineWriter(t *testing.T) {
	var got []event
	w := &lineWriter{emit: func(l Level, m string) { got = append(got, event{l, m}) }}
	log := slog.New(slog.NewTextHandler(w, nil))
	log.Info("started", "version", "1.0.0")
	log.Warn("slow")
	log.Error("failed", "error", "boom")
	w.Write([]byte("partial "))
	w.Write([]byte("line\r\n\nlast without newline"))
	if len(got) != 4 {
		t.Fatalf("events %+v", got)
	}
	want := []Level{LevelInfo, LevelWarning, LevelError, LevelInfo}
	for i, e := range got {
		if e.level != want[i] || strings.HasSuffix(e.msg, "\n") {
			t.Errorf("event %d: %+v", i, e)
		}
	}
	if got[3].msg != "partial line" {
		t.Fatalf("joined line %q", got[3].msg)
	}
	w.Close()
	if len(got) != 5 || got[4].msg != "last without newline" {
		t.Fatalf("after close %+v", got)
	}
	long := strings.Repeat("x", maxLine+10)
	w.Write([]byte(long))
	if len(got) != 6 || len(got[5].msg) != maxLine {
		t.Fatalf("long line split: %d events", len(got))
	}
}

func TestStubs(t *testing.T) {
	if IsService() {
		t.Fatal("a test binary runs as a service")
	}
}
