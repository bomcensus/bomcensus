// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/integritysvc"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// agentView carries what the agent conversion needs besides the agent.
type agentView struct {
	onlineAfter   time.Time
	bundleVersion int64
	listenTargets map[string]string // agent id → listen target id
	integrity     integritysvc.Policy
}

func (h *Handlers) agentView(ctx context.Context) (agentView, error) {
	v := agentView{onlineAfter: h.now().Add(-OnlineWindow), listenTargets: map[string]string{}}
	var err error
	if v.integrity, err = integritysvc.Load(ctx, h.st); err != nil {
		return v, err
	}
	if v.bundleVersion, err = h.st.TrustBundleVersion(ctx); err != nil {
		return v, err
	}
	targets, err := h.st.ListListenTargets(ctx)
	if err != nil {
		return v, err
	}
	for _, t := range targets {
		if t.AgentID != "" {
			v.listenTargets[t.AgentID] = t.ID
		}
	}
	return v, nil
}

func (v agentView) agent(a store.Agent) gen.Agent {
	out := gen.Agent{
		Id:                a.ID,
		Kind:              gen.AgentKind(a.Kind),
		Hostname:          a.Hostname,
		Description:       optString(a.Description),
		AssetId:           optString(a.AssetID),
		Version:           a.Version,
		Os:                a.OS,
		Arch:              a.Arch,
		Status:            gen.AgentStatus(a.Status(v.onlineAfter)),
		ConnMode:          gen.ConnMode(cmp.Or(a.ConnectMode, store.ConnectModeConnect)),
		ListenAddress:     optString(a.ListenAddress),
		ListenTargetId:    optString(v.listenTargets[a.ID]),
		TlsMode:           gen.TlsMode(cmp.Or(a.TLSMode, store.TLSVerifyPinned)),
		TlsInterceptedBy:  optString(a.ObservedIssuer),
		Privilege:         gen.PrivilegeLevel(cmp.Or(a.Privilege, store.PrivilegeNonRoot)),
		ExecHelper:        a.ExecHelper,
		RegisterKeyId:     a.RegisterKeyID,
		Address:           a.Address,
		CertExpiresAt:     a.CertNotAfter,
		TrustBundleSynced: a.TrustBundleVersion >= v.bundleVersion,
		UpdateState:       gen.UpdateState(cmp.Or(a.UpdateState, store.UpdateUpToDate)),
		UpdateMessage:     optString(a.UpdateMessage),
		EnrolledAt:        a.EnrolledAt,
		LastSeen:          a.EnrolledAt,
		DetectDirIds:      orEmpty(a.DetectDirIDs),
		ScopeId:           optString(a.ScopeID),
	}
	if a.LastSeen != nil {
		out.LastSeen = *a.LastSeen
	}
	if a.Kind == store.AgentKindAgent {
		mode := cmp.Or(a.Integrity, store.IntegrityInherit)
		m, on := gen.IntegrityMode(mode), integritysvc.Enabled(mode, v.integrity.Agents)
		out.Integrity, out.IntegrityEnabled = &m, &on
	}
	return out
}

// agentStoreSorts are the sort fields ListAgents handles itself.
var agentStoreSorts = map[string]string{
	"hostname":   "hostname",
	"version":    "version",
	"address":    "address",
	"lastSeen":   "last_seen",
	"enrolledAt": "enrolled_at",
}

// ListAgents implements listAgents.
func (h *Handlers) ListAgents(ctx context.Context, req gen.ListAgentsRequestObject) (gen.ListAgentsResponseObject, error) {
	p := req.Params
	v, err := h.agentView(ctx)
	if err != nil {
		return nil, err
	}
	f := store.AgentFilter{
		Kind:        store.AgentKind(deref(p.Kind)),
		Status:      store.AgentStatus(deref(p.Status)),
		OnlineAfter: v.onlineAfter,
		ConnectMode: store.ConnectMode(deref(p.ConnMode)),
		TLSMode:     store.TLSVerifyMode(deref(p.TlsMode)),
		Q:           deref(p.Q),
	}
	page := pageOf(p.Limit, p.Offset)
	field, desc := parseSort(p.Sort, "hostname")
	storeSort, sortable := agentStoreSorts[field]

	var agents []store.Agent
	var total int
	if sortable && p.UpdateState == nil && p.RegisterKeyId == nil && p.Version == nil {
		if desc {
			storeSort = "-" + storeSort
		}
		f.Sort = storeSort
		if agents, total, err = h.st.ListAgents(ctx, f, page); err != nil {
			return nil, err
		}
	} else {
		// Filters and sorts the store does not offer are applied here.
		all, err := collectAll(func(pg store.Page) ([]store.Agent, int, error) { return h.st.ListAgents(ctx, f, pg) })
		if err != nil {
			return nil, err
		}
		kept := all[:0]
		for _, a := range all {
			if (p.UpdateState == nil || string(cmp.Or(a.UpdateState, store.UpdateUpToDate)) == string(*p.UpdateState)) &&
				(p.RegisterKeyId == nil || a.RegisterKeyID == *p.RegisterKeyId) &&
				(p.Version == nil || a.Version == *p.Version) {
				kept = append(kept, a)
			}
		}
		sortBy(kept, desc, func(x, y store.Agent) int {
			var c int
			switch field {
			case "status":
				c = cmp.Compare(x.Status(v.onlineAfter), y.Status(v.onlineAfter))
			case "connMode":
				c = cmp.Compare(x.ConnectMode, y.ConnectMode)
			case "tlsMode":
				c = cmp.Compare(x.TLSMode, y.TLSMode)
			case "privilege":
				c = cmp.Compare(x.Privilege, y.Privilege)
			case "version":
				c = cmp.Compare(x.Version, y.Version)
			case "address":
				c = cmp.Compare(x.Address, y.Address)
			case "lastSeen":
				c = cmpTime(x.LastSeen, y.LastSeen)
			case "enrolledAt":
				c = x.EnrolledAt.Compare(y.EnrolledAt)
			}
			return cmp.Or(c, cmpFold(x.Hostname, y.Hostname))
		})
		total = len(kept)
		agents = paginate(kept, page)
	}
	out := gen.ListAgents200JSONResponse{Items: make([]gen.Agent, 0, len(agents)), Total: total}
	for _, a := range agents {
		out.Items = append(out.Items, v.agent(a))
	}
	return out, nil
}

func (h *Handlers) getAgentDTO(ctx context.Context, id string) (gen.Agent, error) {
	a, err := h.st.GetAgent(ctx, id)
	if err != nil {
		return gen.Agent{}, err
	}
	v, err := h.agentView(ctx)
	if err != nil {
		return gen.Agent{}, err
	}
	return v.agent(a), nil
}

// GetAgent implements getAgent.
func (h *Handlers) GetAgent(ctx context.Context, req gen.GetAgentRequestObject) (gen.GetAgentResponseObject, error) {
	a, err := h.getAgentDTO(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetAgent200JSONResponse(a), nil
}

// maxAgentDescription is the longest description in characters.
const maxAgentDescription = 200

// UpdateAgent implements updateAgent.
func (h *Handlers) UpdateAgent(ctx context.Context, req gen.UpdateAgentRequestObject) (gen.UpdateAgentResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	a, err := h.st.GetAgent(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if a.Kind == store.AgentKindScanner {
		if err := sharedWrite(ctx); err != nil {
			return nil, err
		}
	}
	if b.Description != nil {
		desc := strings.TrimSpace(*b.Description)
		if utf8.RuneCountInString(desc) > maxAgentDescription {
			return nil, apierr.Invalid("description must be at most %d characters", maxAgentDescription)
		}
		if strings.ContainsFunc(desc, unicode.IsControl) {
			return nil, apierr.Invalid("description must not contain control characters")
		}
		if err := h.st.SetAgentDescription(ctx, a.ID, desc); err != nil {
			return nil, err
		}
		h.log.Info("agent description changed", "agent_id", a.ID, "hostname", a.Hostname, "by", h.who(ctx))
	}
	if b.DetectDirIds != nil {
		if a.Kind != store.AgentKindAgent {
			return nil, apierr.Invalid("detect directories apply to agents, not scanners")
		}
		if err := h.checkDetectDirs(ctx, *b.DetectDirIds); err != nil {
			return nil, err
		}
		if err := h.st.SetAgentDetectDirs(ctx, a.ID, *b.DetectDirIds); err != nil {
			return nil, err
		}
		h.log.Info("agent detect directories changed", "agent_id", a.ID, "hostname", a.Hostname,
			"count", len(*b.DetectDirIds), "by", h.who(ctx))
	}
	if b.Integrity != nil {
		if a.Kind != store.AgentKindAgent {
			return nil, apierr.Invalid("file integrity applies to agents, not scanners")
		}
		if !b.Integrity.Valid() {
			return nil, apierr.Invalid("unknown integrity mode %q", *b.Integrity)
		}
		if err := h.st.SetAgentIntegrity(ctx, a.ID, string(*b.Integrity)); err != nil {
			return nil, err
		}
		h.log.Info("agent integrity mode changed", "agent_id", a.ID, "hostname", a.Hostname,
			"mode", *b.Integrity, "by", h.who(ctx))
	}
	dto, err := h.getAgentDTO(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	return gen.UpdateAgent200JSONResponse(dto), nil
}

// ApproveAgent implements approveAgent. Approval only changes the state;
// the agent fetches its certificate with its next enroll/result request.
func (h *Handlers) ApproveAgent(ctx context.Context, req gen.ApproveAgentRequestObject) (gen.ApproveAgentResponseObject, error) {
	a, err := h.st.GetAgent(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if a.Kind == store.AgentKindScanner {
		if err := sharedWrite(ctx); err != nil {
			return nil, err
		}
	}
	if a.State != store.AgentPending {
		return nil, apierr.New(409, apierr.CodeInvalidState, "the agent is not pending approval")
	}
	if err := h.st.ApproveAgent(ctx, a.ID, h.now()); err != nil {
		return nil, err
	}
	h.log.Info("agent approved", "agent_id", a.ID, "hostname", a.Hostname, "by", h.who(ctx))
	dto, err := h.getAgentDTO(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	return gen.ApproveAgent200JSONResponse(dto), nil
}

// RevokeAgent implements revokeAgent: the agent and all its certificates
// are revoked.
func (h *Handlers) RevokeAgent(ctx context.Context, req gen.RevokeAgentRequestObject) (gen.RevokeAgentResponseObject, error) {
	a, err := h.st.GetAgent(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if a.Kind == store.AgentKindScanner {
		if err := sharedWrite(ctx); err != nil {
			return nil, err
		}
	}
	if a.State == store.AgentRevoked {
		return nil, apierr.New(409, apierr.CodeInvalidState, "the agent is already revoked")
	}
	if err := h.st.RevokeAgent(ctx, a.ID, h.now()); err != nil {
		return nil, err
	}
	if err := h.pki.NoteAgentRevoked(ctx, a.ID); err != nil {
		// Other replicas converge on their next revocation refresh; so
		// does this one.
		h.log.Warn("cannot update the revocation cache", "agent_id", a.ID, "err", err)
	}
	h.log.Info("agent revoked", "agent_id", a.ID, "hostname", a.Hostname, "by", h.who(ctx))
	dto, err := h.getAgentDTO(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	return gen.RevokeAgent200JSONResponse(dto), nil
}

// ── listen targets ──────────────────────────────────────────────────────

func listenState(s store.ListenTargetState) gen.ListenTargetState {
	if s == store.ListenNew {
		return gen.ListenTargetStateConnecting
	}
	return gen.ListenTargetState(s)
}

func listenTargetDTO(t store.ListenTarget) gen.ListenTarget {
	return gen.ListenTarget{
		Id:              t.ID,
		Address:         t.Address,
		RegisterKeyId:   optString(t.RegisterKeyID),
		AgentId:         optString(t.AgentID),
		State:           listenState(t.State),
		LastError:       optString(t.LastError),
		LastConnectedAt: t.LastConnectedAt,
		CreatedAt:       t.CreatedAt,
		ScopeId:         t.ScopeID,
	}
}

// ListListenTargets implements listListenTargets.
func (h *Handlers) ListListenTargets(ctx context.Context, req gen.ListListenTargetsRequestObject) (gen.ListListenTargetsResponseObject, error) {
	p := req.Params
	all, err := h.st.ListListenTargets(ctx)
	if err != nil {
		return nil, err
	}
	hostnames := map[string]string{}
	if deref(p.Q) != "" {
		for _, t := range all {
			if t.AgentID == "" {
				continue
			}
			if a, err := h.st.GetAgent(ctx, t.AgentID); err == nil {
				hostnames[t.AgentID] = a.Hostname
			}
		}
	}
	kept := make([]store.ListenTarget, 0, len(all))
	for _, t := range all {
		if (p.State == nil || listenState(t.State) == *p.State) && matches(p.Q, t.Address, hostnames[t.AgentID]) {
			kept = append(kept, t)
		}
	}
	field, desc := parseSort(p.Sort, "address")
	sortBy(kept, desc, func(x, y store.ListenTarget) int {
		var c int
		switch field {
		case "state":
			c = cmp.Compare(listenState(x.State), listenState(y.State))
		case "createdAt":
			c = x.CreatedAt.Compare(y.CreatedAt)
		case "lastConnectedAt":
			c = cmpTime(x.LastConnectedAt, y.LastConnectedAt)
		}
		return cmp.Or(c, cmp.Compare(x.Address, y.Address))
	})
	out := gen.ListListenTargets200JSONResponse{Items: []gen.ListenTarget{}, Total: len(kept)}
	for _, t := range paginate(kept, pageOf(p.Limit, p.Offset)) {
		out.Items = append(out.Items, listenTargetDTO(t))
	}
	return out, nil
}

func validHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("address must be host:port")
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return fmt.Errorf("address has an invalid host")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("address has an invalid port")
	}
	return nil
}

// CreateListenTarget implements createListenTarget.
func (h *Handlers) CreateListenTarget(ctx context.Context, req gen.CreateListenTargetRequestObject) (gen.CreateListenTargetResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.Invalid("request body is required")
	}
	addr := strings.TrimSpace(req.Body.Address)
	if len(addr) > 512 {
		return nil, apierr.Invalid("address is too long")
	}
	if err := validHostPort(addr); err != nil {
		return nil, apierr.Invalid("%s", err.Error())
	}
	t := store.ListenTarget{Address: addr}
	if id := deref(req.Body.RegisterKeyId); id != "" {
		// The target takes the scope of its key.
		if err := h.checkListenKey(ctx, id); err != nil {
			return nil, err
		}
		t.RegisterKeyID = id
	} else {
		var err error
		if t.ScopeID, err = newScopeID(ctx, req.Body.ScopeId); err != nil {
			return nil, err
		}
	}
	created, err := h.st.CreateListenTarget(ctx, t)
	if err != nil {
		if isConflict(err) {
			return nil, apierr.Conflict("a listen target with this address exists").Wrap(err)
		}
		return nil, err
	}
	h.log.Info("listen target added", "address", created.Address, "by", h.who(ctx))
	return gen.CreateListenTarget201JSONResponse(listenTargetDTO(created)), nil
}

// checkListenKey checks that id is a register key for agents.
func (h *Handlers) checkListenKey(ctx context.Context, id string) error {
	k, err := h.st.GetRegisterKey(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return apierr.Invalid("register key %s does not exist", id)
		}
		return err
	}
	if k.Target != store.AgentKindAgent {
		return apierr.Invalid("register key %s enrolls scanners, which only support connect mode", id)
	}
	return nil
}

// UpdateListenTarget implements updateListenTarget.
func (h *Handlers) UpdateListenTarget(ctx context.Context, req gen.UpdateListenTargetRequestObject) (gen.UpdateListenTargetResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	t, err := h.st.GetListenTarget(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if b.Address != nil {
		t.Address = strings.TrimSpace(*b.Address)
		if len(t.Address) > 512 {
			return nil, apierr.Invalid("address is too long")
		}
		if err := validHostPort(t.Address); err != nil {
			return nil, apierr.Invalid("%s", err.Error())
		}
	}
	if id, ok := patchString(b.RegisterKeyId); ok {
		if id != "" {
			if err := h.checkListenKey(ctx, id); err != nil {
				return nil, err
			}
		}
		t.RegisterKeyID = id
	}
	updated, err := h.st.UpdateListenTarget(ctx, t)
	if err != nil {
		if isConflict(err) {
			return nil, apierr.Conflict("a listen target with this address exists").Wrap(err)
		}
		return nil, err
	}
	h.log.Info("listen target updated", "listen_target_id", updated.ID, "address", updated.Address, "by", h.who(ctx))
	return gen.UpdateListenTarget200JSONResponse(listenTargetDTO(updated)), nil
}

// DeleteListenTarget implements deleteListenTarget.
func (h *Handlers) DeleteListenTarget(ctx context.Context, req gen.DeleteListenTargetRequestObject) (gen.DeleteListenTargetResponseObject, error) {
	if err := h.st.DeleteListenTarget(ctx, req.Id); err != nil {
		return nil, err
	}
	return gen.DeleteListenTarget204Response{}, nil
}
