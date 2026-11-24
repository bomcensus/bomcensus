// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/feedsvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Error codes of the feed operations.
const (
	CodeFeedBuiltin    = "feed_server_builtin"
	CodeFeedActive     = "feed_server_active"
	CodeFeedDisabled   = "feed_server_disabled"
	CodeFeedKeyMissing = "feed_key_not_presented"
)

func (h *Handlers) feedService() (*feedsvc.Service, error) {
	if h.feed == nil {
		return nil, apierr.Unavailable("the feed connection is not configured")
	}
	return h.feed, nil
}

func feedServerDTO(s store.FeedServer) gen.FeedServer {
	out := gen.FeedServer{
		Id: s.ID, Name: s.Name, Url: s.URL, Builtin: s.Builtin, Active: s.Active, Enabled: s.Enabled,
		Telemetry: s.Telemetry, Status: gen.FeedServerStatus(s.Status),
		ServerKey: optString(s.ServerKey), KeyTrustedAt: s.KeyTrustedAt,
		PresentedKey: optString(s.PresentedKey), PresentedAt: s.PresentedAt,
		LastError: optString(s.LastError), LastErrorAt: s.LastErrorAt, LastOkAt: s.LastOKAt,
		Grade: optString(s.Grade), SessionExpiresAt: s.SessionExpiresAt,
		Revision: s.Revision, RulesDigest: s.RulesDigest, StatusCheckedAt: s.StatusCheckedAt,
		Sources: make([]gen.FeedSource, 0, len(s.Sources)), CreatedAt: s.CreatedAt,
	}
	for _, src := range s.Sources {
		out.Sources = append(out.Sources, gen.FeedSource{Name: src.Name, UpdatedAt: src.UpdatedAt, ChangedAt: src.ChangedAt, Healthy: src.Healthy})
	}
	return out
}

func feedName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 100 {
		return "", apierr.Invalid("name must be 1 to 100 characters")
	}
	return s, nil
}

func feedErr(err error) error {
	if errors.Is(err, feedsvc.ErrInvalid) {
		return apierr.Invalid("%s", strings.TrimPrefix(err.Error(), "feedsvc: invalid input: ")).Wrap(err)
	}
	return err
}

// GetFeedInstance implements getFeedInstance.
func (h *Handlers) GetFeedInstance(ctx context.Context, _ gen.GetFeedInstanceRequestObject) (gen.GetFeedInstanceResponseObject, error) {
	f, err := h.feedService()
	if err != nil {
		return nil, err
	}
	in, err := f.Instance(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetFeedInstance200JSONResponse{InstanceId: in.PublicKey, CreatedAt: in.CreatedAt}, nil
}

// ListFeedServers implements listFeedServers.
func (h *Handlers) ListFeedServers(ctx context.Context, _ gen.ListFeedServersRequestObject) (gen.ListFeedServersResponseObject, error) {
	list, err := h.st.ListFeedServers(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListFeedServers200JSONResponse{Items: make([]gen.FeedServer, 0, len(list)), Total: len(list)}
	for _, s := range list {
		out.Items = append(out.Items, feedServerDTO(s))
	}
	return out, nil
}

// CreateFeedServer implements createFeedServer.
func (h *Handlers) CreateFeedServer(ctx context.Context, req gen.CreateFeedServerRequestObject) (gen.CreateFeedServerResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	name, err := feedName(b.Name)
	if err != nil {
		return nil, err
	}
	u, err := feedsvc.NormalizeURL(b.Url)
	if err != nil {
		return nil, feedErr(err)
	}
	telemetry := true
	if b.Telemetry != nil {
		telemetry = *b.Telemetry
	}
	s, err := h.st.CreateFeedServer(ctx, store.FeedServerCreate{Name: name, URL: u, Telemetry: telemetry})
	if isConflict(err) {
		return nil, apierr.Conflict("a feed server with this URL exists").Wrap(err)
	}
	if err != nil {
		return nil, err
	}
	h.log.Info("feed server added", "server", s.URL, "telemetry", s.Telemetry, "by", h.who(ctx))
	return gen.CreateFeedServer201JSONResponse(feedServerDTO(s)), nil
}

// UpdateFeedServer implements updateFeedServer.
func (h *Handlers) UpdateFeedServer(ctx context.Context, req gen.UpdateFeedServerRequestObject) (gen.UpdateFeedServerResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	if b.Active != nil && !*b.Active {
		return nil, apierr.Invalid("active accepts only true; activate another server instead")
	}
	var u store.FeedServerUpdate
	if b.Name != nil {
		name, err := feedName(*b.Name)
		if err != nil {
			return nil, err
		}
		u.Name = &name
	}
	u.Enabled, u.Telemetry = b.Enabled, b.Telemetry

	cur, err := h.st.GetFeedServer(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	var out store.FeedServer
	err = h.st.WithTx(ctx, func(tx store.Store) error {
		var err error
		// Enable before activating, deactivate before disabling.
		if out, err = tx.UpdateFeedServer(ctx, req.Id, u); err != nil {
			return err
		}
		if b.Active != nil && !cur.Active {
			out, err = tx.ActivateFeedServer(ctx, req.Id)
		}
		return err
	})
	if errors.Is(err, store.ErrInvalidState) {
		if b.Enabled != nil && !*b.Enabled {
			return nil, apierr.New(http.StatusConflict, CodeFeedActive, "the active feed server cannot be disabled").Wrap(err)
		}
		return nil, apierr.New(http.StatusConflict, CodeFeedDisabled, "a disabled feed server cannot be activated").Wrap(err)
	}
	if err != nil {
		return nil, err
	}
	h.log.Info("feed server changed", "server", out.URL, "active", out.Active, "enabled", out.Enabled,
		"telemetry", out.Telemetry, "by", h.who(ctx))
	if h.feed != nil {
		h.feed.Kick()
	}
	return gen.UpdateFeedServer200JSONResponse(feedServerDTO(out)), nil
}

// DeleteFeedServer implements deleteFeedServer.
func (h *Handlers) DeleteFeedServer(ctx context.Context, req gen.DeleteFeedServerRequestObject) (gen.DeleteFeedServerResponseObject, error) {
	cur, err := h.st.GetFeedServer(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	switch {
	case cur.Builtin:
		return nil, apierr.New(http.StatusConflict, CodeFeedBuiltin, "the built-in feed server cannot be removed; disable it instead")
	case cur.Active:
		return nil, apierr.New(http.StatusConflict, CodeFeedActive, "the active feed server cannot be removed; activate another one first")
	}
	if err := h.st.DeleteFeedServer(ctx, req.Id); err != nil {
		return nil, err
	}
	h.log.Info("feed server removed", "server", cur.URL, "by", h.who(ctx))
	return gen.DeleteFeedServer204Response{}, nil
}

// TestFeedServer implements testFeedServer.
func (h *Handlers) TestFeedServer(ctx context.Context, req gen.TestFeedServerRequestObject) (gen.TestFeedServerResponseObject, error) {
	f, err := h.feedService()
	if err != nil {
		return nil, err
	}
	s, err := f.Test(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.TestFeedServer200JSONResponse(feedServerDTO(s)), nil
}

// TrustFeedServerKey implements trustFeedServerKey.
func (h *Handlers) TrustFeedServerKey(ctx context.Context, req gen.TrustFeedServerKeyRequestObject) (gen.TrustFeedServerKeyResponseObject, error) {
	f, err := h.feedService()
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	cur, err := h.st.GetFeedServer(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	s, err := f.TrustKey(ctx, req.Id, b.Key)
	if errors.Is(err, store.ErrInvalidState) {
		return nil, apierr.New(http.StatusConflict, CodeFeedKeyMissing, "the key is not the one the server presented").Wrap(err)
	}
	if err != nil {
		return nil, feedErr(err)
	}
	// An audit record: who replaced which key with which.
	h.log.Warn("feed server key replaced", "server", s.URL, "previous", cur.ServerKey, "trusted", s.ServerKey,
		"by", h.who(ctx), "at", h.now().UTC().Format(time.RFC3339))
	return gen.TrustFeedServerKey200JSONResponse(feedServerDTO(s)), nil
}
