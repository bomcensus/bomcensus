// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

func TestPURLLike(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1":        `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`,
		"pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12": `pkg:deb/debian/openssl@3.0.11-1`,
		"pkg:maven/org.apache.logging.log4j/log4j-core@*":             `pkg:maven/org.apache.logging.log4j/log4j-core@%`,
		"pkg:npm/%40scope/a_b@1.0":                                    `pkg:npm/\%40scope/a\_b@1.0`,
		"pkg:maven/a/*/b":                                             "",
		"log4j-core":                                                  "",
		"pkg:":                                                        "",
	} {
		got, err := PURLLike(in)
		if want == "" {
			if !errors.Is(err, ErrInvalidPattern) {
				t.Errorf("%q: %q, %v", in, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	if got := PURLScope("pkg:deb/debian/openssl@3.0.11-1?arch=amd64"); got != "pkg:deb/debian/openssl@3.0.11-1" {
		t.Errorf("scope %q", got)
	}
}

type fakeTriage struct {
	at     time.Time
	events []store.TriageEvent
}

func (f *fakeTriage) ExpireTriageRules(_ context.Context, at time.Time) ([]store.TriageEvent, error) {
	f.at = at
	return f.events, nil
}

func TestExpirer(t *testing.T) {
	ft := &fakeTriage{events: []store.TriageEvent{{Kind: store.TriageEventExpired, Rule: store.TriageRule{ID: "r", VulnID: "CVE-1"}, Findings: 2}}}
	e := NewExpirer(ft, nil)
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	if err := e.Run(context.Background()); err != nil || !ft.at.Equal(now) {
		t.Fatalf("run: %v at %s", err, ft.at)
	}
}
