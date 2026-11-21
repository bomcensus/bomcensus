// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package manageapi implements the management operations of the console API:
// agents, listen targets, Register Keys, releases and update settings, scan
// targets, credentials and TLS settings. Handlers are thin mappings onto the
// store and the services; errors are returned as *apierr.Error or store
// errors for the router to render.
package manageapi

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
	"github.com/bomcensus/bomcensus/internal/server/secret"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/server/updatesvc"
)

// OnlineWindow is how recently an approved agent must have been seen to be
// shown online.
const OnlineWindow = 3 * time.Minute

// ScanRunner starts an on-demand scan of a scan target. The scan scheduler
// implements it. An error wrapping store.ErrInvalidState or
// store.ErrConflict (for example a scan already running) is shown as 409.
type ScanRunner interface {
	RequestRun(ctx context.Context, targetID string) error
}

// ClusterCredentialUse tells how many Kubernetes clusters use each
// credential. Clusters belong to the inventory side of the store, so this is
// kept behind an interface; StoreClusters is the default implementation.
type ClusterCredentialUse interface {
	CredentialClusterCounts(ctx context.Context) (map[string]int, error)
}

// StoreClusters implements ClusterCredentialUse over store.K8sClusters.
type StoreClusters struct{ Clusters store.K8sClusters }

// CredentialClusterCounts implements ClusterCredentialUse.
func (c StoreClusters) CredentialClusterCounts(ctx context.Context) (map[string]int, error) {
	rows, err := collectAll(func(p store.Page) ([]store.K8sClusterRow, int, error) {
		return c.Clusters.ListClusters(ctx, store.ClusterFilter{}, p)
	})
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, r := range rows {
		if r.CredentialID != "" {
			out[r.CredentialID]++
		}
	}
	return out, nil
}

// UnsyncedAgents returns the counter pkisvc.Config.UnsyncedAgents expects:
// approved agents whose trust bundle version is below the current one.
func UnsyncedAgents(agents store.Agents) func(ctx context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		c, err := agents.CountAgents(ctx, time.Time{})
		if err != nil {
			return 0, err
		}
		return c.TrustBundleBehind, nil
	}
}

// Config holds the dependencies of Handlers.
type Config struct {
	Store   store.Store
	PKI     *pkisvc.Service
	Updates *updatesvc.Service
	Secrets *secret.Box
	// ScanRunner is optional; runScanTarget answers 503 without it.
	ScanRunner ScanRunner
	// Clusters is optional; StoreClusters{Store} by default.
	Clusters ClusterCredentialUse
	// PrincipalID returns the ID of the authenticated principal of the
	// request, stored as created_by.
	PrincipalID func(ctx context.Context) string
	Logger      *slog.Logger
	Now         func() time.Time
}

// Handlers implements the management operations of
// adminapi.StrictServerInterface.
type Handlers struct {
	st       store.Store
	pki      *pkisvc.Service
	updates  *updatesvc.Service
	secrets  *secret.Box
	runner   ScanRunner
	clusters ClusterCredentialUse
	who      func(ctx context.Context) string
	log      *slog.Logger
	now      func() time.Time
}

// New returns Handlers. Store, PKI, Updates and Secrets are required.
func New(cfg Config) (*Handlers, error) {
	if cfg.Store == nil || cfg.PKI == nil || cfg.Updates == nil || cfg.Secrets == nil {
		return nil, errors.New("manageapi: store, PKI, updates and secrets are required")
	}
	if cfg.Clusters == nil {
		cfg.Clusters = StoreClusters{Clusters: cfg.Store}
	}
	if cfg.PrincipalID == nil {
		cfg.PrincipalID = func(context.Context) string { return "" }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handlers{
		st: cfg.Store, pki: cfg.PKI, updates: cfg.Updates, secrets: cfg.Secrets, runner: cfg.ScanRunner,
		clusters: cfg.Clusters, who: cfg.PrincipalID, log: cfg.Logger, now: cfg.Now,
	}, nil
}

// Error codes in addition to those of apierr.
const (
	CodeAnchorMismatch     = "anchor_mismatch"
	CodeAgentsNotSynced    = "agents_not_synced"
	CodeAnchorPending      = "anchor_pending"
	CodeNoPendingAnchor    = "no_pending_anchor"
	CodeAnchorNotStaged    = "anchor_certificate_missing"
	CodeWebTLSOff          = "web_tls_off"
	CodeVerificationFailed = "release_verification_failed"
	CodeReleaseExists      = "release_exists"
)

// detail strips the package prefixes from a service error message.
func detail(err error) string {
	msg := err.Error()
	for _, p := range []string{"pkisvc: invalid input: ", "updatesvc: release verification failed: ", "updatesvc: invalid settings: ", "pkisvc: ", "updatesvc: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	return msg
}

// mapErr turns service errors into API errors. Store errors and anything
// else pass through to apierr.From.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var tooLarge *http.MaxBytesError
	var ae *apierr.Error
	if errors.As(err, &tooLarge) || errors.As(err, &ae) {
		return err
	}
	conflict := func(code string) error {
		return apierr.New(http.StatusConflict, code, detail(err)).Wrap(err)
	}
	switch {
	case errors.Is(err, pkisvc.ErrInvalid), errors.Is(err, updatesvc.ErrInvalid):
		return apierr.Invalid("%s", detail(err)).Wrap(err)
	case errors.Is(err, updatesvc.ErrVerification):
		return apierr.New(http.StatusBadRequest, CodeVerificationFailed, detail(err)).Wrap(err)
	case errors.Is(err, updatesvc.ErrExists):
		return conflict(CodeReleaseExists)
	case errors.Is(err, pkisvc.ErrAnchorMismatch):
		return conflict(CodeAnchorMismatch)
	case errors.Is(err, pkisvc.ErrAgentsNotSynced):
		return conflict(CodeAgentsNotSynced)
	case errors.Is(err, pkisvc.ErrAnchorPending):
		return conflict(CodeAnchorPending)
	case errors.Is(err, pkisvc.ErrNoPendingAnchor):
		return conflict(CodeNoPendingAnchor)
	case errors.Is(err, pkisvc.ErrNotStaged):
		return conflict(CodeAnchorNotStaged)
	case errors.Is(err, pkisvc.ErrWebTLSOff):
		return conflict(CodeWebTLSOff)
	case errors.Is(err, pkisvc.ErrNotReady):
		return apierr.Unavailable("certificates are not loaded yet").Wrap(err)
	}
	return err
}

// ── list helpers ────────────────────────────────────────────────────────

// maxCollect bounds the records loaded for filtering or sorting in memory.
const maxCollect = 100_000

// collectAll loads every page of a store list.
func collectAll[T any](fetch func(store.Page) ([]T, int, error)) ([]T, error) {
	var out []T
	for {
		items, total, err := fetch(store.Page{Limit: 1000, Offset: len(out)})
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if len(items) == 0 || len(out) >= total || len(out) >= maxCollect {
			return out, nil
		}
	}
}

func pageOf(limit, offset *int) store.Page {
	var p store.Page
	if limit != nil {
		p.Limit = *limit
	}
	if offset != nil {
		p.Offset = *offset
	}
	return p.Normalize()
}

func paginate[T any](items []T, p store.Page) []T {
	if p.Offset >= len(items) {
		return []T{}
	}
	end := min(p.Offset+p.Limit, len(items))
	return items[p.Offset:end]
}

// parseSort splits "-field" into field and descending.
func parseSort[S ~string](s *S, def string) (string, bool) {
	v := def
	if s != nil && *s != "" {
		v = string(*s)
	}
	if f, ok := strings.CutPrefix(v, "-"); ok {
		return f, true
	}
	return v, false
}

// sortBy sorts stably by key comparison cmpFn, reversed when desc.
func sortBy[T any](items []T, desc bool, cmpFn func(a, b T) int) {
	slices.SortStableFunc(items, func(a, b T) int {
		if desc {
			return cmpFn(b, a)
		}
		return cmpFn(a, b)
	})
}

func cmpTime(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return a.Compare(*b)
}

func cmpFold(a, b string) int { return cmp.Compare(strings.ToLower(a), strings.ToLower(b)) }

// matches reports whether q is empty or a case-insensitive substring of
// one of the fields.
func matches(q *string, fields ...string) bool {
	if q == nil || *q == "" {
		return true
	}
	needle := strings.ToLower(*q)
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

func isConflict(err error) bool { return errors.Is(err, store.ErrConflict) }
