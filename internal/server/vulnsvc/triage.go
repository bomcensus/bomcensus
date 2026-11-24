// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/job"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// DefaultExpireInterval is how often ended deferrals are recorded.
const DefaultExpireInterval = 15 * time.Minute

// ErrInvalidPattern is returned for a purl scope that is not a purl.
var ErrInvalidPattern = errors.New("vulnsvc: purl pattern must start with pkg: and may end with *")

// PURLLike turns a purl scope into the LIKE pattern matched against
// component purls without qualifiers: qualifiers and subpath are dropped,
// LIKE metacharacters escaped, and a trailing * matches any rest.
func PURLLike(pattern string) (string, error) {
	p := strings.TrimSpace(pattern)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	prefix := strings.HasSuffix(p, "*")
	p = strings.TrimSuffix(p, "*")
	if !strings.HasPrefix(p, "pkg:") || len(p) <= len("pkg:") || strings.Contains(p, "*") {
		return "", ErrInvalidPattern
	}
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(p)
	if prefix {
		r += "%"
	}
	return r, nil
}

// PURLScope is the default purl scope of a component: its purl without
// qualifiers or subpath.
func PURLScope(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}

// TriageStore is what the expirer uses.
type TriageStore interface {
	ExpireTriageRules(ctx context.Context, at time.Time) ([]store.TriageEvent, error)
}

// Expirer records triage rules whose deferral ended. The findings they
// deferred are shown again as soon as the expiry passes; the job makes the
// ending an event (triage_events) that API clients and notifications can
// follow, and marks the rule expired.
type Expirer struct {
	st  TriageStore
	log *slog.Logger
	now func() time.Time
}

// NewExpirer returns an Expirer.
func NewExpirer(st TriageStore, log *slog.Logger) *Expirer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Expirer{st: st, log: log, now: time.Now}
}

// Register registers the expire job and its periodic run with q.
func (e *Expirer) Register(q job.Queue, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultExpireInterval
	}
	if err := q.Register(job.KindTriageExpire, func(ctx context.Context, _ job.Job) error { return e.Run(ctx) }); err != nil {
		return err
	}
	return q.Periodic(job.KindTriageExpire, interval, nil, job.UniqueKey(job.KindTriageExpire))
}

// Run records the rules whose expiry passed.
func (e *Expirer) Run(ctx context.Context) error {
	events, err := e.st.ExpireTriageRules(ctx, e.now())
	if err != nil {
		return fmt.Errorf("vulnsvc: expire triage rules: %w", err)
	}
	for _, ev := range events {
		e.log.Info("triage deferral ended", "rule", ev.Rule.ID, "vulnerability", ev.Rule.VulnID,
			"scope", ev.Rule.ScopeKind+":"+ev.Rule.ScopeValue, "expired", ev.Rule.ExpiresAt, "findings", ev.Findings)
	}
	return nil
}
