// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"context"
	"errors"
	"strings"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Notices are shown, never turned into findings: the administrator reads
// a notice with the assets whose software it names and decides.

const maxNoticeIDLen = 128

func noticeDTO(n store.NoticeRow) gen.Notice {
	d := gen.Notice{
		NoticeId: n.ID, Source: n.Source, Title: n.Title, Url: optStr(n.URL), Published: n.Published,
		Summary: optStr(n.Summary), CveIds: strs(n.CVEIDs), RelatedCveIds: strs(n.RelatedCVEIDs),
		AdvisoryIds: strs(n.AdvisoryIDs), Software: make([]gen.NoticeSoftware, 0, len(n.Software)), Updated: n.Modified,
		Assets: n.Assets, NewAssets: n.NewAssets, Unread: n.Unread(), FirstMatched: n.FirstMatched,
		LastMatched: n.LastMatched, ReadAt: n.ReadAt, ReadBy: optStr(n.ReadBy),
	}
	for _, s := range n.Software {
		d.Software = append(d.Software, gen.NoticeSoftware{Vendor: s.Vendor, Product: s.Product, CpeVendor: s.CPEVendor,
			CpeProduct: s.CPEProduct, Affected: optStr(s.Affected), Fixed: optStr(s.Fixed)})
	}
	return d
}

func noticeMatchDTO(m store.NoticeMatch) gen.NoticeMatch {
	return gen.NoticeMatch{
		AssetId: m.AssetID, AssetName: m.AssetName, AssetKind: gen.AssetKind(m.AssetKind), Container: optStr(m.Container),
		ComponentId: m.Component.ID, ComponentName: m.Component.Name, ComponentVersion: m.Component.Version,
		ComponentType: m.Component.Type, Cpe: optStr(m.Component.CPE), Purl: optStr(m.Component.PURL),
		Locations: strs(m.Locations), FirstSeen: m.FirstSeen, New: m.New,
	}
}

// ListNotices implements gen.StrictServerInterface.
func (h *Handlers) ListNotices(ctx context.Context, req gen.ListNoticesRequestObject) (gen.ListNoticesResponseObject, error) {
	prm := req.Params
	p, err := page(prm.Limit, prm.Offset)
	if err != nil {
		return nil, err
	}
	q, err := query(prm.Q)
	if err != nil {
		return nil, err
	}
	source := strings.TrimSpace(deref(prm.Source))
	if len(source) > 32 {
		return nil, apierr.Invalid("source must be at most 32 bytes")
	}
	f := store.NoticeFilter{Q: q, Source: source, IncludeRead: prm.IncludeRead != nil && *prm.IncludeRead}
	rows, total, err := h.cfg.Store.ListNotices(ctx, f, p)
	if err != nil {
		return nil, err
	}
	out := gen.ListNotices200JSONResponse{Items: make([]gen.Notice, 0, len(rows)), Total: total}
	for _, r := range rows {
		out.Items = append(out.Items, noticeDTO(r))
	}
	return out, nil
}

// GetNoticeSummary implements gen.StrictServerInterface.
func (h *Handlers) GetNoticeSummary(ctx context.Context, _ gen.GetNoticeSummaryRequestObject) (gen.GetNoticeSummaryResponseObject, error) {
	c, err := h.cfg.Store.CountNotices(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetNoticeSummary200JSONResponse{Total: c.Total, Unread: c.Unread}, nil
}

// GetNotice implements gen.StrictServerInterface.
func (h *Handlers) GetNotice(ctx context.Context, req gen.GetNoticeRequestObject) (gen.GetNoticeResponseObject, error) {
	if req.NoticeId == "" || len(req.NoticeId) > maxNoticeIDLen {
		return nil, apierr.NotFound("notice")
	}
	n, err := h.cfg.Store.GetNotice(ctx, req.NoticeId)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("notice")
	}
	if err != nil {
		return nil, err
	}
	ms, err := h.cfg.Store.ListNoticeMatches(ctx, store.NoticeMatchFilter{NoticeID: n.ID})
	if err != nil {
		return nil, err
	}
	out := gen.GetNotice200JSONResponse{Notice: noticeDTO(n), Matches: make([]gen.NoticeMatch, 0, len(ms))}
	for _, m := range ms {
		out.Matches = append(out.Matches, noticeMatchDTO(m))
	}
	return out, nil
}

// ListAssetNotices implements gen.StrictServerInterface.
func (h *Handlers) ListAssetNotices(ctx context.Context, req gen.ListAssetNoticesRequestObject) (gen.ListAssetNoticesResponseObject, error) {
	if _, err := h.cfg.Store.GetAsset(ctx, req.Id); errors.Is(err, store.ErrNotFound) {
		return nil, apierr.NotFound("asset")
	} else if err != nil {
		return nil, err
	}
	var rows []store.NoticeRow
	for p := (store.Page{Limit: maxLimit}); ; p.Offset += p.Limit {
		pg, total, err := h.cfg.Store.ListNotices(ctx, store.NoticeFilter{AssetID: req.Id, IncludeRead: true}, p)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pg...)
		if len(pg) == 0 || len(rows) >= total {
			break
		}
	}
	ms, err := h.cfg.Store.ListNoticeMatches(ctx, store.NoticeMatchFilter{AssetID: req.Id})
	if err != nil {
		return nil, err
	}
	byNotice := map[string][]gen.NoticeMatch{}
	for _, m := range ms {
		byNotice[m.NoticeID] = append(byNotice[m.NoticeID], noticeMatchDTO(m))
	}
	out := gen.ListAssetNotices200JSONResponse{Items: make([]gen.AssetNotice, 0, len(rows))}
	for _, r := range rows {
		m := byNotice[r.ID]
		if m == nil {
			m = []gen.NoticeMatch{}
		}
		out.Items = append(out.Items, gen.AssetNotice{Notice: noticeDTO(r), Matches: m})
	}
	return out, nil
}

// noticeIDs validates the ids of a read or unread request.
func noticeIDs(b *gen.NoticeIds) ([]string, error) {
	if b == nil || len(b.Ids) == 0 {
		return nil, apierr.Invalid("ids are required")
	}
	if len(b.Ids) > store.MaxNoticeIDs {
		return nil, apierr.Invalid("at most %d ids", store.MaxNoticeIDs)
	}
	seen := make(map[string]bool, len(b.Ids))
	out := make([]string, 0, len(b.Ids))
	for _, id := range b.Ids {
		if id == "" || len(id) > maxNoticeIDLen {
			return nil, apierr.Invalid("a notice id must be 1 to %d bytes", maxNoticeIDLen)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// MarkNoticesRead implements gen.StrictServerInterface.
func (h *Handlers) MarkNoticesRead(ctx context.Context, req gen.MarkNoticesReadRequestObject) (gen.MarkNoticesReadResponseObject, error) {
	ids, err := noticeIDs(req.Body)
	if err != nil {
		return nil, err
	}
	n, err := h.cfg.Store.MarkNoticesRead(ctx, ids, principal(ctx), h.cfg.Now())
	if err != nil {
		return nil, err
	}
	h.logChange(ctx, "notices marked read", "requested", len(ids), "marked", n)
	return gen.MarkNoticesRead200JSONResponse{Updated: n}, nil
}

// MarkNoticesUnread implements gen.StrictServerInterface.
func (h *Handlers) MarkNoticesUnread(ctx context.Context, req gen.MarkNoticesUnreadRequestObject) (gen.MarkNoticesUnreadResponseObject, error) {
	ids, err := noticeIDs(req.Body)
	if err != nil {
		return nil, err
	}
	n, err := h.cfg.Store.MarkNoticesUnread(ctx, ids)
	if err != nil {
		return nil, err
	}
	h.logChange(ctx, "notices marked unread", "requested", len(ids), "marked", n)
	return gen.MarkNoticesUnread200JSONResponse{Updated: n}, nil
}
