// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/agent/core"
	"github.com/bomcensus/bomcensus/internal/agent/state"
)

func TestEnrollIfNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &state.Enrollment{
		Kind:        string(core.KindScanner),
		ServerURL:   "https://server.invalid:8443",
		ServerName:  "server.invalid",
		ConnectMode: core.ModeConnect,
		TLSMode:     "pinned",
		AgentID:     "01a1fc83-4a09-77b9-a499-ef0449ae1388",
		Status:      state.StatusApproved,
		EnrolledAt:  time.Now(),
	}
	e.SetPin([32]byte{1})
	if err := st.SaveEnrollment(e); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	if code := run([]string{"enroll", "--state-dir", dir}, io.Discard, &stderr); code != 1 {
		t.Fatalf("enroll without --if-not-enrolled: exit %d, want 1 (%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), core.ErrAlreadyEnrolled.Error()) {
		t.Errorf("enroll without --if-not-enrolled: stderr %q lacks %q", stderr.String(), core.ErrAlreadyEnrolled)
	}

	stderr.Reset()
	if code := run([]string{"enroll", "--if-not-enrolled", "--state-dir", dir}, io.Discard, &stderr); code != 0 {
		t.Fatalf("enroll --if-not-enrolled: exit %d, want 0 (%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "already enrolled; nothing to do") {
		t.Errorf("enroll --if-not-enrolled: stderr %q lacks the log line", stderr.String())
	}
}
