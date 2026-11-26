// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// NoticeSoftware is a product a notice names.
type NoticeSoftware struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	// CPEVendor and CPEProduct are the normalized CPE fields the feed
	// matches components by.
	CPEVendor  string `json:"cpe_vendor"`
	CPEProduct string `json:"cpe_product"`
	// Affected and Fixed are version texts as printed; informational only.
	Affected string `json:"affected"`
	Fixed    string `json:"fixed"`
}

// Notice is a security notice (KISA, a vendor) as the feed server last
// returned it. A notice is not a finding: it is shown with the assets whose
// software it names, and the administrator decides whether it applies.
type Notice struct {
	ID     string // source-prefixed, "kisa-6219"
	Source string // kisa, tmaxsoft, ...
	Title  string
	URL    string
	// Published is when the source published it; nil when not known.
	Published *time.Time
	// Summary is a short English summary, possibly empty.
	Summary string
	// CVEIDs are printed in the notice; RelatedCVEIDs are linked by the
	// feed (same software, published close to the notice).
	CVEIDs        []string
	RelatedCVEIDs []string
	AdvisoryIDs   []string
	Software      []NoticeSoftware
	// Modified is when the feed last changed the notice or its
	// classification; nil when not known.
	Modified *time.Time
}

// NoticeFilter selects notices for the console. Only notices that match
// an installed component of a current asset in the scope are listed.
type NoticeFilter struct {
	// ID keeps one notice.
	ID string
	// AssetID counts only the matches of one asset.
	AssetID string
	Source  string
	// Q matches the id, title, summary, the CVE and advisory ids and the
	// software names.
	Q string
	// IncludeRead keeps notices that are read.
	IncludeRead bool
	// Sort is "" (unread first, then the newest), published, title,
	// source, assets or last_matched, prefixed with "-" for descending.
	Sort string
}

// NoticeRow is a notice with what matches it in the scope.
type NoticeRow struct {
	Notice
	// Assets counts the current assets with a matching component.
	Assets int
	// NewAssets counts those of them that are not covered by a read mark:
	// the notice was never marked read in the asset's scope, or the asset
	// started matching after that. The notice is unread when it is not 0.
	NewAssets int
	// FirstMatched and LastMatched are the earliest and latest time an
	// asset started matching.
	FirstMatched time.Time
	LastMatched  time.Time
	// ReadAt and ReadBy are the latest read mark of the scopes of the
	// matching assets; nil and empty without one.
	ReadAt *time.Time
	ReadBy string
}

// Unread reports whether an asset matches the notice that no read mark
// covers.
func (r NoticeRow) Unread() bool { return r.NewAssets > 0 }

// NoticeMatchFilter selects the matches of a notice, or of an asset; at
// least one is set.
type NoticeMatchFilter struct {
	NoticeID string
	AssetID  string
}

// NoticeMatch is a component installed on an asset that a notice names.
type NoticeMatch struct {
	NoticeID  string
	AssetID   string
	AssetName string
	AssetKind AssetKind
	// Container is empty for the asset itself.
	Container string
	Component Component
	Locations []string
	// FirstSeen is when this component started matching the notice here:
	// the later of its installation and the notice link.
	FirstSeen time.Time
	// New is true when the asset is not covered by a read mark (see
	// NoticeRow.NewAssets).
	New bool
}

// NoticeCounts counts the notices visible in a scope.
type NoticeCounts struct {
	Total  int
	Unread int
}

// MaxNoticeIDs bounds the ids of one read or unread request.
const MaxNoticeIDs = 1000

// Notices reads notices and keeps their read state. The notices of a
// component come with its match (MatchBatch.Notices) and are replaced with
// each match.
//
// Read marks are kept per notice and scope id: marking a notice read marks
// it for the scope ids of the matching assets the request sees, so that one
// scope never hides a notice from another.
type Notices interface {
	// ListNotices lists the notices f selects: unread ones first, then the
	// newest.
	ListNotices(ctx context.Context, f NoticeFilter, p Page) ([]NoticeRow, int, error)
	// GetNotice returns ErrNotFound unless a current asset in the scope
	// matches the notice.
	GetNotice(ctx context.Context, id string) (NoticeRow, error)
	// ListNoticeMatches lists the matches f selects, by asset name.
	ListNoticeMatches(ctx context.Context, f NoticeMatchFilter) ([]NoticeMatch, error)
	// CountNotices counts the visible notices.
	CountNotices(ctx context.Context) (NoticeCounts, error)
	// MarkNoticesRead marks the visible notices among ids read for the
	// scope ids of their matching assets and returns how many it marked.
	MarkNoticesRead(ctx context.Context, ids []string, by string, at time.Time) (int, error)
	// MarkNoticesUnread removes the read marks of ids in the scope and
	// returns how many notices had one.
	MarkNoticesUnread(ctx context.Context, ids []string) (int, error)
}
