// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package detectorsvc keeps the known-software detector table the server
// hands to agents and scanners: the table an administrator saved, else the
// default table (a file, normally the Helm chart's ConfigMap, else the table
// built into the server). Every edit is kept.
package detectorsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bomcensus/bomcensus/internal/detectors"
	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// DefaultTTL is how long the table in effect is cached. A table saved on
// another server replica reaches agents polling this one within it.
const DefaultTTL = 30 * time.Second

// ErrInvalid is returned (wrapped) by Save for a table with errors.
var ErrInvalid = errors.New("detectorsvc: invalid table")

// Table is a parsed detector table.
type Table struct {
	// YAML is the table as written.
	YAML string
	// Table is the parsed table, JSON its canonical form and Digest the
	// digest of both.
	Table  *report.DetectorTable
	JSON   []byte
	Digest string
}

// Effective is the table in effect.
type Effective struct {
	Table
	// Custom is set for a table saved by an administrator; Revision,
	// UpdatedAt and UpdatedBy describe that edit (or the reset to the
	// default).
	Custom    bool
	Revision  int64
	UpdatedAt time.Time
	UpdatedBy string
}

// Config configures a Service.
type Config struct {
	Store store.DetectorTables
	// DefaultFile is the default table; empty uses the table built into
	// the server. A file that is missing or has errors fails New.
	DefaultFile string
	// TTL defaults to DefaultTTL.
	TTL    time.Duration
	Logger *slog.Logger
	Now    func() time.Time
}

// Service provides the table in effect.
type Service struct {
	st         store.DetectorTables
	def        Table
	defSource  string
	ttl        time.Duration
	log        *slog.Logger
	now        func() time.Time
	mu         sync.Mutex
	cached     *Effective
	cachedTill time.Time
}

// New loads the default table.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("detectorsvc: store is required")
	}
	s := &Service{st: cfg.Store, ttl: cfg.TTL, log: cfg.Logger, now: cfg.Now}
	if s.ttl <= 0 {
		s.ttl = DefaultTTL
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	text, source := detectors.BuiltinYAML(), "built-in"
	if cfg.DefaultFile != "" {
		b, err := os.ReadFile(cfg.DefaultFile)
		if err != nil {
			return nil, fmt.Errorf("detectorsvc: default table: %w", err)
		}
		text, source = b, cfg.DefaultFile
	}
	def, probs := Parse(text)
	if err := problemsError(probs); err != nil {
		return nil, fmt.Errorf("detectorsvc: default table %s: %w", source, err)
	}
	s.def, s.defSource = def, source
	return s, nil
}

// Parse checks a YAML table (detectors.Check) and returns it with its
// problems. The table is usable when no problem is an error.
func Parse(text []byte) (Table, []detectors.Problem) {
	t, probs := detectors.Check(text)
	if t == nil || problemsError(probs) != nil {
		return Table{}, probs
	}
	raw, err := detectors.Encode(t)
	if err != nil {
		return Table{}, []detectors.Problem{{Index: -1, Message: err.Error()}}
	}
	d, err := detectors.Digest(t)
	if err != nil {
		return Table{}, []detectors.Problem{{Index: -1, Message: err.Error()}}
	}
	return Table{YAML: string(text), Table: t, JSON: raw, Digest: d}, probs
}

func problemsError(probs []detectors.Problem) error {
	var msgs []string
	for _, p := range probs {
		if p.Warning {
			continue
		}
		if p.Index >= 0 {
			msgs = append(msgs, fmt.Sprintf("detector %d (%s): %s", p.Index+1, p.ID, p.Message))
		} else {
			msgs = append(msgs, p.Message)
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(msgs, "; "))
}

// Default returns the default table and where it comes from (a file name
// or "built-in").
func (s *Service) Default() (Table, string) { return s.def, s.defSource }

// Effective returns the table in effect, cached for the TTL.
func (s *Service) Effective(ctx context.Context) (Effective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && s.now().Before(s.cachedTill) {
		return *s.cached, nil
	}
	e, err := s.load(ctx)
	if err != nil {
		return Effective{}, err
	}
	s.cached, s.cachedTill = &e, s.now().Add(s.ttl)
	return e, nil
}

func (s *Service) load(ctx context.Context) (Effective, error) {
	rev, err := s.st.LatestDetectorTable(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Effective{Table: s.def}, nil
	case err != nil:
		return Effective{}, err
	}
	e := Effective{Table: s.def, Revision: rev.ID, UpdatedAt: rev.CreatedAt, UpdatedBy: rev.CreatedBy}
	if rev.Reset {
		return e, nil
	}
	t, probs := Parse([]byte(rev.YAML))
	if err := problemsError(probs); err != nil {
		// Saved by a server whose checks differed (another version):
		// the default is safer than nothing.
		s.log.WarnContext(ctx, "saved detector table is not usable; using the default table", "revision", rev.ID, "error", err)
		return e, nil
	}
	e.Table, e.Custom = t, true
	return e, nil
}

// Save checks and stores an administrator's table. A table with errors is
// not stored: the problems are returned with an error wrapping ErrInvalid.
// Warnings are returned with the saved table.
func (s *Service) Save(ctx context.Context, text []byte, by string) (Effective, []detectors.Problem, error) {
	t, probs := Parse(text)
	if err := problemsError(probs); err != nil {
		return Effective{}, probs, err
	}
	if _, err := s.st.AddDetectorTable(ctx, store.DetectorTableRevision{YAML: t.YAML, Digest: t.Digest,
		CreatedAt: s.now(), CreatedBy: by}); err != nil {
		return Effective{}, probs, err
	}
	e, err := s.refresh(ctx)
	return e, probs, err
}

// Reset returns to the default table; the earlier edits are kept.
func (s *Service) Reset(ctx context.Context, by string) (Effective, error) {
	if _, err := s.st.AddDetectorTable(ctx, store.DetectorTableRevision{Reset: true, CreatedAt: s.now(), CreatedBy: by}); err != nil {
		return Effective{}, err
	}
	return s.refresh(ctx)
}

func (s *Service) refresh(ctx context.Context) (Effective, error) {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
	return s.Effective(ctx)
}

// Current implements the source of agentapi: the digest and canonical
// JSON of the table in effect.
func (s *Service) Current(ctx context.Context) (string, []byte, error) {
	e, err := s.Effective(ctx)
	if err != nil {
		return "", nil, err
	}
	return e.Digest, e.JSON, nil
}

// ForProbe returns the table in effect for a probe request, nil when it
// cannot be read (the probe then uses its built-in table).
func (s *Service) ForProbe() *report.DetectorTable {
	e, err := s.Effective(context.Background())
	if err != nil {
		s.log.Warn("detector table not available; probes use their built-in table", "error", err)
		return nil
	}
	return e.Table.Table
}

// History returns the edits, newest first.
func (s *Service) History(ctx context.Context, limit int) ([]store.DetectorTableRevision, error) {
	return s.st.ListDetectorTables(ctx, limit)
}

// Revision returns one edit with its YAML.
func (s *Service) Revision(ctx context.Context, id int64) (store.DetectorTableRevision, error) {
	return s.st.GetDetectorTable(ctx, id)
}

// Usage counts the agents and scanners by the table they reported.
func (s *Service) Usage(ctx context.Context) ([]store.DetectorTableUsage, error) {
	return s.st.DetectorTableUsage(ctx)
}
