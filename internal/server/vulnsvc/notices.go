// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package vulnsvc

import (
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// notice is a security notice of a match response (Contract A of the feed
// API). Times are strings so that a malformed one drops the time, not the
// response.
type notice struct {
	ID            string           `json:"id"`
	Source        string           `json:"source"`
	Title         string           `json:"title"`
	URL           string           `json:"url"`
	Published     string           `json:"published"`
	Summary       string           `json:"summary"`
	CVEIDs        []string         `json:"cve_ids"`
	RelatedCVEIDs []string         `json:"related_cve_ids"`
	AdvisoryIDs   []string         `json:"advisory_ids"`
	Software      []noticeSoftware `json:"software"`
	Updated       string           `json:"updated"`
}

type noticeSoftware struct {
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	CPEVendor  string `json:"cpe_vendor"`
	CPEProduct string `json:"cpe_product"`
	Affected   string `json:"affected"`
	Fixed      string `json:"fixed"`
}

// Bounds of what is kept of a notice. Notices are shown in the console, so
// what the feed sends is bounded and cleaned: longer texts are cut, extra
// entries dropped.
const (
	maxNoticeTitle    = 1000
	maxNoticeSummary  = 8000
	maxNoticeURL      = 2048
	maxNoticeField    = 256
	maxNoticeIDs      = 500
	maxNoticeSoftware = 200
	// maxComponentNotices bounds the notices of one component.
	maxComponentNotices = 500
)

var (
	noticeIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	noticeSourcePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
)

// noticesByID converts the notices of a response. Notices without a valid
// id or source are dropped; the first of duplicate ids wins.
func noticesByID(in []notice) map[string]store.Notice {
	out := make(map[string]store.Notice, len(in))
	for _, n := range in {
		if !noticeIDPattern.MatchString(n.ID) || !noticeSourcePattern.MatchString(n.Source) {
			continue
		}
		if _, dup := out[n.ID]; dup {
			continue
		}
		m := store.Notice{ID: n.ID, Source: n.Source, Title: clean(n.Title, maxNoticeTitle), URL: webURL(n.URL),
			Published: parseTime(n.Published), Summary: clean(n.Summary, maxNoticeSummary),
			CVEIDs: cleanList(n.CVEIDs), RelatedCVEIDs: cleanList(n.RelatedCVEIDs), AdvisoryIDs: cleanList(n.AdvisoryIDs),
			Modified: parseTime(n.Updated)}
		for _, s := range n.Software {
			if len(m.Software) == maxNoticeSoftware {
				break
			}
			m.Software = append(m.Software, store.NoticeSoftware{Vendor: clean(s.Vendor, maxNoticeField),
				Product: clean(s.Product, maxNoticeField), CPEVendor: clean(s.CPEVendor, maxNoticeField),
				CPEProduct: clean(s.CPEProduct, maxNoticeField), Affected: clean(s.Affected, maxNoticeField),
				Fixed: clean(s.Fixed, maxNoticeField)})
		}
		out[n.ID] = m
	}
	return out
}

// noticeRefs returns the distinct ids of refs that known describes and
// adds them to used. A reference without details is dropped rather than
// failing the match: notices are informational and must not hold up the
// vulnerability results.
func noticeRefs(refs []string, known map[string]store.Notice, used map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range refs {
		if _, ok := known[id]; !ok || seen[id] {
			continue
		}
		if len(out) == maxComponentNotices {
			break
		}
		seen[id] = true
		used[id] = true
		out = append(out, id)
	}
	return out
}

// clean trims s, removes NUL (PostgreSQL text cannot hold it) and cuts it
// to limit runes.
func clean(s string, limit int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if utf8.RuneCountInString(s) > limit {
		r := []rune(s)
		s = strings.TrimSpace(string(r[:limit]))
	}
	return s
}

// cleanList keeps the distinct non-empty ids of in, each at most
// maxNoticeField long.
func cleanList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range in {
		v = clean(v, maxNoticeField)
		if v == "" || seen[v] {
			continue
		}
		if len(out) == maxNoticeIDs {
			break
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// webURL returns u when it is an absolute http or https URL, empty
// otherwise, so that the console links only to web pages.
func webURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" || len(u) > maxNoticeURL {
		return ""
	}
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return ""
	}
	return p.String()
}

// parseTime reads an RFC 3339 time or a date; nil when s is neither.
func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
