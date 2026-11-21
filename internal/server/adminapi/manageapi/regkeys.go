// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/token"
)

// Limits on Register Key policies.
const (
	maxRegisterKeyCIDRs = 256
	maxDefaultTags      = 64
	maxTagLen           = 200
)

func registerKeyState(k store.RegisterKey, now time.Time) gen.RegisterKeyState {
	switch k.Usable(now) {
	case store.ErrRegisterKeyRevoked:
		return gen.RegisterKeyStateRevoked
	case store.ErrRegisterKeyExpired:
		return gen.RegisterKeyStateExpired
	case store.ErrRegisterKeyExhausted:
		return gen.RegisterKeyStateExhausted
	}
	return gen.RegisterKeyStateValid
}

func registerKeyDTO(k store.RegisterKey, now time.Time) gen.RegisterKey {
	cidrs := make([]string, 0, len(k.AllowedCIDRs))
	for _, p := range k.AllowedCIDRs {
		cidrs = append(cidrs, p.String())
	}
	tags := k.DefaultTags
	if tags == nil {
		tags = []string{}
	}
	return gen.RegisterKey{
		Id:              k.ID,
		Name:            k.Name,
		Target:          gen.AgentKind(k.Target),
		ExpiresAt:       k.ExpiresAt,
		AllowedCidrs:    cidrs,
		MaxUses:         k.MaxUses,
		UsedCount:       k.UsedCount,
		Approval:        gen.RegisterKeyApproval(k.Approval),
		AllowRelaxedTls: k.AllowRelaxedTLS,
		DefaultGroup:    k.DefaultGroup,
		DefaultTags:     tags,
		State:           registerKeyState(k, now),
		CreatedAt:       k.CreatedAt,
		RevokedAt:       k.RevokedAt,
	}
}

// ListRegisterKeys implements listRegisterKeys.
func (h *Handlers) ListRegisterKeys(ctx context.Context, req gen.ListRegisterKeysRequestObject) (gen.ListRegisterKeysResponseObject, error) {
	p := req.Params
	f := store.RegisterKeyFilter{Q: deref(p.Q), Target: store.AgentKind(deref(p.Target))}
	all, err := collectAll(func(pg store.Page) ([]store.RegisterKey, int, error) { return h.st.ListRegisterKeys(ctx, f, pg) })
	if err != nil {
		return nil, err
	}
	now := h.now()
	kept := all[:0]
	for _, k := range all {
		if p.State == nil || registerKeyState(k, now) == *p.State {
			kept = append(kept, k)
		}
	}
	field, desc := parseSort(p.Sort, "-createdAt")
	sortBy(kept, desc, func(x, y store.RegisterKey) int {
		var c int
		switch field {
		case "name":
			c = cmpFold(x.Name, y.Name)
		case "target":
			c = cmp.Compare(x.Target, y.Target)
		case "state":
			c = cmp.Compare(registerKeyState(x, now), registerKeyState(y, now))
		case "expiresAt":
			c = cmpTime(x.ExpiresAt, y.ExpiresAt)
		case "usedCount":
			c = cmp.Compare(x.UsedCount, y.UsedCount)
		case "approval":
			c = cmp.Compare(x.Approval, y.Approval)
		}
		return cmp.Or(c, x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	out := gen.ListRegisterKeys200JSONResponse{Items: []gen.RegisterKey{}, Total: len(kept)}
	for _, k := range paginate(kept, pageOf(p.Limit, p.Offset)) {
		out.Items = append(out.Items, registerKeyDTO(k, now))
	}
	return out, nil
}

// GetRegisterKey implements getRegisterKey.
func (h *Handlers) GetRegisterKey(ctx context.Context, req gen.GetRegisterKeyRequestObject) (gen.GetRegisterKeyResponseObject, error) {
	k, err := h.st.GetRegisterKey(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetRegisterKey200JSONResponse(registerKeyDTO(k, h.now())), nil
}

// parseCIDRs accepts prefixes and bare addresses (a single-host prefix).
// Host bits are cleared.
func parseCIDRs(in []string) ([]netip.Prefix, error) {
	if len(in) > maxRegisterKeyCIDRs {
		return nil, apierr.Invalid("at most %d allowed CIDRs", maxRegisterKeyCIDRs)
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(s); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil || p.Addr().Zone() != "" {
			return nil, apierr.Invalid("invalid CIDR %q", s)
		}
		if a := p.Addr(); a.Is4In6() {
			if p.Bits() < 96 {
				return nil, apierr.Invalid("invalid CIDR %q", s)
			}
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func cleanTags(in []string) ([]string, error) {
	if len(in) > maxDefaultTags {
		return nil, apierr.Invalid("at most %d default tags", maxDefaultTags)
	}
	out := []string{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || slices.Contains(out, t) {
			continue
		}
		if len(t) > maxTagLen {
			return nil, apierr.Invalid("tag %q is too long", t[:32]+"…")
		}
		out = append(out, t)
	}
	return out, nil
}

// CreateRegisterKey implements createRegisterKey. Only the public key and the
// policy are stored; the enrollment string is returned once.
func (h *Handlers) CreateRegisterKey(ctx context.Context, req gen.CreateRegisterKeyRequestObject) (gen.CreateRegisterKeyResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	now := h.now()
	k := store.RegisterKey{
		Name:            strings.TrimSpace(b.Name),
		Target:          store.AgentKind(b.Target),
		ExpiresAt:       b.ExpiresAt,
		MaxUses:         deref(b.MaxUses),
		Approval:        store.ApprovalMode(b.Approval),
		AllowRelaxedTLS: deref(b.AllowRelaxedTls),
		DefaultGroup:    strings.TrimSpace(deref(b.DefaultGroup)),
		CreatedBy:       h.who(ctx),
	}
	switch {
	case k.Name == "" || len(k.Name) > 200:
		return nil, apierr.Invalid("name must be 1 to 200 characters")
	case k.Target != store.AgentKindAgent && k.Target != store.AgentKindScanner:
		return nil, apierr.Invalid("target must be agent or scanner")
	case k.Approval != store.ApprovalAuto && k.Approval != store.ApprovalManual:
		return nil, apierr.Invalid("approval must be auto or manual")
	case k.MaxUses < 0:
		return nil, apierr.Invalid("maxUses must not be negative")
	case k.ExpiresAt != nil && !k.ExpiresAt.After(now):
		return nil, apierr.Invalid("expiresAt must be in the future")
	case len(k.DefaultGroup) > 200:
		return nil, apierr.Invalid("defaultGroup is too long")
	}
	var err error
	if k.AllowedCIDRs, err = parseCIDRs(deref(b.AllowedCidrs)); err != nil {
		return nil, err
	}
	if k.DefaultTags, err = cleanTags(deref(b.DefaultTags)); err != nil {
		return nil, err
	}
	anchor, err := h.pki.AnchorHash()
	if err != nil {
		return nil, mapErr(err)
	}

	var tok token.Token
	var created store.RegisterKey
	for attempt := 0; ; attempt++ {
		if tok, err = token.New(anchor); err != nil {
			return nil, err
		}
		k.ID = tok.KeyID.String()
		k.PublicKey = tok.PublicKey()
		created, err = h.st.CreateRegisterKey(ctx, k)
		if err == nil {
			break
		}
		if !isConflict(err) || attempt == 2 {
			return nil, err
		}
	}
	h.log.Info("register key created", "key_id", created.ID, "name", created.Name, "target", created.Target,
		"approval", created.Approval, "by", created.CreatedBy)
	noStore := "no-store"
	return gen.CreateRegisterKey201JSONResponse{
		Body:    gen.RegisterKeyCreated{Key: registerKeyDTO(created, now), Enrollment: token.Format(tok)},
		Headers: gen.CreateRegisterKey201ResponseHeaders{CacheControl: &noStore},
	}, nil
}

// RevokeRegisterKey implements revokeRegisterKey.
func (h *Handlers) RevokeRegisterKey(ctx context.Context, req gen.RevokeRegisterKeyRequestObject) (gen.RevokeRegisterKeyResponseObject, error) {
	k, err := h.st.GetRegisterKey(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if k.RevokedAt != nil {
		return nil, apierr.New(409, apierr.CodeInvalidState, "the register key is already revoked")
	}
	now := h.now()
	if err := h.st.RevokeRegisterKey(ctx, k.ID, now); err != nil {
		return nil, err
	}
	if k, err = h.st.GetRegisterKey(ctx, k.ID); err != nil {
		return nil, err
	}
	h.log.Info("register key revoked", "key_id", k.ID, "name", k.Name, "by", h.who(ctx))
	return gen.RevokeRegisterKey200JSONResponse(registerKeyDTO(k, now)), nil
}
