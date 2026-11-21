// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package updater

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"time"

	"github.com/bomcensus/bomcensus/internal/sign"
)

// StateSchemaVersion is the schema_version written to state.json.
const StateSchemaVersion = 1

// Sources of an installed version.
const (
	// SourceBundle marks a version installed from a verified release bundle.
	SourceBundle = "bundle"
	// SourceAdopted marks the version found in place when no state.json
	// existed yet, whose executables passed code signature verification.
	SourceAdopted = "adopted"
)

// maxFailed bounds the remembered failed versions.
const maxFailed = 16

// State is the content of <install>/state.json.
type State struct {
	SchemaVersion int `json:"schema_version"`
	// Current is the version the current link points to ("" before the
	// first install).
	Current string `json:"current"`
	// Previous is the version a rollback switches to ("" when none).
	Previous string `json:"previous"`
	// Pending is set while Current has not been confirmed.
	Pending *Pending `json:"pending"`
	// Installed lists the version directories this updater verified, with
	// the SHA-256 of every file at install time.
	Installed map[string]Installed `json:"installed,omitempty"`
	// Failed lists versions that were rolled back. They are not installed
	// again.
	Failed []Failed `json:"failed,omitempty"`
}

// Pending describes a version on trial.
type Pending struct {
	Version  string    `json:"version"`
	Since    time.Time `json:"since"`
	Attempts int       `json:"attempts"`
}

// Installed describes one version directory.
type Installed struct {
	Source         string            `json:"source"`
	InstalledAt    time.Time         `json:"installed_at"`
	ManifestSHA256 string            `json:"manifest_sha256,omitempty"`
	Files          map[string]string `json:"files"` // name -> lowercase hex SHA-256
}

// Failed is a version that was rolled back.
type Failed struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
	Reason  string    `json:"reason"`
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *State) clone() *State {
	c := *s
	if s.Pending != nil {
		p := *s.Pending
		c.Pending = &p
	}
	c.Installed = maps.Clone(s.Installed)
	c.Failed = slices.Clone(s.Failed)
	return &c
}

func (s *State) isFailed(v string) bool {
	for _, f := range s.Failed {
		if c, err := sign.CompareVersions(f.Version, v); err == nil && c == 0 {
			return true
		}
	}
	return false
}

func (s *State) validate() error {
	if s.SchemaVersion != StateSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", s.SchemaVersion)
	}
	for _, v := range []string{s.Current, s.Previous} {
		if v != "" && !sign.ValidVersion(v) {
			return fmt.Errorf("invalid version %q", v)
		}
	}
	if s.Pending != nil && !sign.ValidVersion(s.Pending.Version) {
		return fmt.Errorf("invalid pending version %q", s.Pending.Version)
	}
	for v, in := range s.Installed {
		if !sign.ValidVersion(v) {
			return fmt.Errorf("invalid installed version %q", v)
		}
		if len(in.Files) == 0 {
			return fmt.Errorf("installed version %s has no files", v)
		}
		for name, sum := range in.Files {
			if !sign.ValidFileName(name) || !sha256Re.MatchString(sum) {
				return fmt.Errorf("installed version %s: invalid file entry %q", v, name)
			}
		}
	}
	for _, f := range s.Failed {
		if !sign.ValidVersion(f.Version) {
			return fmt.Errorf("invalid failed version %q", f.Version)
		}
	}
	return nil
}

func decodeState(b []byte) (*State, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var s State
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode %s: %w", stateName, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s: trailing data", stateName)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", stateName, err)
	}
	return &s, nil
}

func encodeState(s *State) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", stateName, err)
	}
	return append(b, '\n'), nil
}
