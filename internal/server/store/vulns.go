// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// Match status of a component.
const (
	MatchChecked     = "checked"
	MatchUnsupported = "unsupported"
	MatchInvalid     = "invalid"
)

// MatchEpoch is the data a match was made against: a server, its data
// revision and its rules digest. A component matched against an older epoch
// is matched again.
type MatchEpoch struct {
	ServerID string
	Revision int64
	Rules    string
}

// CVSSScore is one CVSS score of a vulnerability.
type CVSSScore struct {
	Source   string  `json:"source,omitempty"`
	Type     string  `json:"type,omitempty"` // Primary (NVD) or Secondary (CNA)
	Version  string  `json:"version"`
	Vector   string  `json:"vector"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity,omitempty"`
}

// KEVEntry is the CISA Known Exploited Vulnerabilities entry.
type KEVEntry struct {
	DateAdded      string `json:"date_added"`
	DueDate        string `json:"due_date,omitempty"`
	Name           string `json:"name,omitempty"`
	RequiredAction string `json:"required_action,omitempty"`
	RansomwareUse  string `json:"ransomware_use,omitempty"`
}

// VulnMeta describes a vulnerability.
type VulnMeta struct {
	ID          string
	Aliases     []string
	Summary     string
	Description string
	CVSS        []CVSSScore
	// MaxScore is the highest CVSS base score; nil without one.
	MaxScore *float64
	// Severity is the rating of MaxScore (critical, high, medium, low,
	// none), empty without a score.
	Severity       string
	CWEs           []string
	References     []string
	KEV            *KEVEntry
	EPSS           *float64
	EPSSPercentile *float64
	Published      *time.Time
	Modified       *time.Time
}

// VulnAdvisory is an advisory behind a match.
type VulnAdvisory struct {
	Source   string `json:"source"`
	ID       string `json:"id"`
	Severity string `json:"severity,omitempty"`
}

// SeverityNegligible is the rating of a match the distribution considers
// negligible (Debian "unimportant"). Only matches carry it, never CVSS.
const SeverityNegligible = "negligible"

// ComponentVuln is one vulnerability matched to a component.
type ComponentVuln struct {
	VulnID       string
	Method       string // package or cpe
	Ecosystem    string
	FixState     string
	FixedVersion string
	CPEMatch     string
	RangeSource  string
	// BuildUnknown: every matching range is bounded by a vendor build and
	// the component has none, so the match is conservative.
	BuildUnknown bool
	Platforms    []string
	Advisories   []VulnAdvisory
	// Symbols are the vulnerable Go functions, empty when not known.
	Symbols []GoImport
	// Severity is the distribution's rating of a package match (critical,
	// high, medium, low, negligible), empty when its advisories have none.
	Severity string
}

// MatchSeverity is the rating a match is ranked by: the distribution's
// rating when it has one, which knows how the package is built, otherwise
// the CVSS rating of the vulnerability.
func MatchSeverity(v ComponentVuln, m VulnMeta) string {
	if v.Severity != "" {
		return v.Severity
	}
	return m.Severity
}

// ComponentMatch is the outcome of matching one component.
type ComponentMatch struct {
	ComponentID string
	OSKey       string
	Status      string
	Reason      string
	Vulns       []ComponentVuln
	// Notices are the ids of the notices whose software matches the
	// component (details in MatchBatch.Notices).
	Notices []string
}

// MatchBatch is what one match request produced.
type MatchBatch struct {
	Epoch      MatchEpoch
	At         time.Time
	Components []ComponentMatch
	Vulns      []VulnMeta
	// Notices describes the notices the components reference.
	Notices []Notice
}

// MatchCounts counts the live components by match state for an epoch.
type MatchCounts struct {
	Checked     int
	Unsupported int
	Invalid     int
	// Pending are live components not matched against the epoch yet.
	Pending int
	// Vulnerable are checked components with at least one vulnerability.
	Vulnerable int
}

// ComponentVulnRow is a vulnerability of a component with its details.
type ComponentVulnRow struct {
	ComponentVuln
	Meta VulnMeta
}

// Vulns stores match results. A component is live while an asset has it
// installed or an image contains it; only live components are matched.
type Vulns interface {
	// PendingMatches returns up to limit live components not matched
	// against e (a match against the same server with a revision at least
	// e.Revision and the same rules counts), ordered by distro.
	PendingMatches(ctx context.Context, e MatchEpoch, limit int) ([]Component, error)
	// SaveMatches stores a batch in one transaction: the vulnerability and
	// notice details, and for each component its match state,
	// vulnerabilities and notices (replacing the previous ones; a notice
	// link that stays keeps the time it was first made).
	SaveMatches(ctx context.Context, b MatchBatch) error
	// ResetMatches forgets the match states of the server's matches so that
	// every component is matched again. Vulnerabilities stay until then.
	ResetMatches(ctx context.Context, serverID string) error
	// CountMatches counts live components by match state for e.
	CountMatches(ctx context.Context, e MatchEpoch) (MatchCounts, error)
	VulnQuery
}

// VulnQuery reads match results and findings for the console.
type VulnQuery interface {
	VulnViews
	// GetComponentMatch returns ErrNotFound when the component was never
	// matched.
	GetComponentMatch(ctx context.Context, componentID string) (ComponentMatch, MatchEpoch, time.Time, error)
	// ListComponentVulns returns the vulnerabilities of a component: known
	// exploited first, then by score.
	ListComponentVulns(ctx context.Context, componentID string) ([]ComponentVulnRow, error)
}
