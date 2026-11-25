// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package integritysvc holds the server side of package file integrity
// passes: the policy setting, which collectors run passes, and when the
// passes of SSH targets are due.
package integritysvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// SettingPolicy is the settings key of the integrity policy.
const SettingPolicy = "integrity_policy"

// Policy is the integrity policy document.
type Policy struct {
	// Agents and SSH are the defaults of agents and scan targets whose
	// integrity mode is inherit.
	Agents bool `json:"agents"`
	SSH    bool `json:"ssh"`
	// WindowStart and WindowEnd are local times "HH:MM" of the inspected
	// host; the window may cross midnight, equal values mean all day.
	WindowStart    string   `json:"window_start"`
	WindowEnd      string   `json:"window_end"`
	IntervalDays   int      `json:"interval_days"`
	MaxReadMBps    int      `json:"max_read_mbps"`
	FullRehashDays int      `json:"full_rehash_days"`
	ExcludePaths   []string `json:"exclude_paths"`
}

// DefaultPolicy is used until an administrator saves one: passes on, every
// night between 02:00 and 05:00.
func DefaultPolicy() Policy {
	return Policy{Agents: true, SSH: true, WindowStart: "02:00", WindowEnd: "05:00", IntervalDays: 1,
		MaxReadMBps: 20, FullRehashDays: 7, ExcludePaths: []string{}}
}

var hhmm = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// Validate checks the policy's values.
func (p Policy) Validate() error {
	switch {
	case !hhmm.MatchString(p.WindowStart) || !hhmm.MatchString(p.WindowEnd):
		return errors.New("the window must be given as HH:MM")
	case p.IntervalDays < 1 || p.IntervalDays > 30:
		return errors.New("the interval must be 1 to 30 days")
	case p.MaxReadMBps < 1 || p.MaxReadMBps > report.MaxIntegrityReadMBps:
		return fmt.Errorf("the read rate must be 1 to %d MB/s", report.MaxIntegrityReadMBps)
	case p.FullRehashDays < 1 || p.FullRehashDays > 365:
		return errors.New("the full rehash interval must be 1 to 365 days")
	case len(p.ExcludePaths) > report.MaxIntegrityExcludes:
		return fmt.Errorf("at most %d exclude paths", report.MaxIntegrityExcludes)
	}
	for _, e := range p.ExcludePaths {
		if !strings.HasPrefix(e, "/") || len(e) > report.MaxIntegrityExcludeLen {
			return fmt.Errorf("exclude path %q must be absolute and at most %d bytes", e, report.MaxIntegrityExcludeLen)
		}
	}
	return nil
}

// Normalize trims the exclude paths and drops empty and duplicate ones.
func (p Policy) Normalize() Policy {
	var out []string
	for _, e := range p.ExcludePaths {
		e = strings.TrimSpace(e)
		if e != "" && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	if out == nil {
		out = []string{}
	}
	p.ExcludePaths = out
	return p
}

// Settings is what Load and Save need from the store.
type Settings interface {
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
	PutSetting(ctx context.Context, key string, value json.RawMessage) error
}

// Load returns the stored policy, the default when none is stored. A
// stored document that cannot be read is an error, so that a damaged
// setting is noticed instead of silently replaced.
func Load(ctx context.Context, st Settings) (Policy, error) {
	raw, err := st.GetSetting(ctx, SettingPolicy)
	if errors.Is(err, store.ErrNotFound) {
		return DefaultPolicy(), nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("integrity policy: %w", err)
	}
	p := DefaultPolicy()
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, fmt.Errorf("integrity policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, fmt.Errorf("integrity policy: %w", err)
	}
	return p.Normalize(), nil
}

// Save validates and stores p.
func Save(ctx context.Context, st Settings, p Policy) (Policy, error) {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return Policy{}, fmt.Errorf("%w: %v", store.ErrInvalid, err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return Policy{}, err
	}
	if err := st.PutSetting(ctx, SettingPolicy, raw); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Enabled resolves a collector's integrity mode against the default of its
// kind.
func Enabled(mode string, kindDefault bool) bool {
	switch mode {
	case store.IntegrityOn:
		return true
	case store.IntegrityOff:
		return false
	}
	return kindDefault
}
