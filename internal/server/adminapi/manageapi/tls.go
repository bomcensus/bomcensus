// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package manageapi

import (
	"bytes"
	"context"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/pkisvc"
)

func endpointDTO(e pkisvc.EndpointStatus) gen.TlsEndpoint {
	out := gen.TlsEndpoint{Mode: gen.TlsCertMode(e.Mode), Subject: e.Subject, Issuer: e.Issuer, Names: e.Names}
	if out.Names == nil {
		out.Names = []string{}
	}
	if !e.ExpiresAt.IsZero() {
		t := e.ExpiresAt
		out.ExpiresAt = &t
	}
	return out
}

func (h *Handlers) tlsState(ctx context.Context) (gen.TlsState, error) {
	st, err := h.pki.Status(ctx)
	if err != nil {
		return gen.TlsState{}, mapErr(err)
	}
	unsynced := max(st.UnsyncedAgents, 0)
	agent := endpointDTO(st.Agent)
	// The client certificate for listen-mode agents is reported when it is
	// not the server certificate itself.
	if cl, err := h.pki.AgentClientCertificate(); err == nil && cl.Leaf != nil {
		if srv, err := h.pki.AgentServerCertificate(); err != nil || srv.Leaf == nil || !bytes.Equal(srv.Leaf.Raw, cl.Leaf.Raw) {
			subject, expires := cl.Leaf.Subject.String(), cl.Leaf.NotAfter
			agent.ClientSubject, agent.ClientExpiresAt = &subject, &expires
		}
	}
	out := gen.TlsState{
		Web:              endpointDTO(st.Web),
		Agent:            agent,
		AnchorSpkiHash:   pkisvc.SPKIString(st.AnchorHash),
		AgentCaExpiresAt: st.AgentCAExpiresAt,
		UnsyncedAgents:   unsynced,
	}
	if p := st.Pending; p != nil {
		out.PendingAnchor = &gen.PendingAnchor{
			SpkiHash:       pkisvc.SPKIString(p.SPKIHash),
			Subject:        p.Subject,
			ExpiresAt:      p.ExpiresAt,
			PreparedAt:     p.PreparedAt,
			UnsyncedAgents: unsynced, // nothing bumps the bundle while an anchor is prepared
		}
	}
	return out, nil
}

// GetTlsSettings implements getTlsSettings.
func (h *Handlers) GetTlsSettings(ctx context.Context, _ gen.GetTlsSettingsRequestObject) (gen.GetTlsSettingsResponseObject, error) {
	st, err := h.tlsState(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetTlsSettings200JSONResponse(st), nil
}

// UpdateTlsEndpoint implements updateTlsEndpoint.
func (h *Handlers) UpdateTlsEndpoint(ctx context.Context, req gen.UpdateTlsEndpointRequestObject) (gen.UpdateTlsEndpointResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	chain, key := []byte(deref(b.CertificateChain)), []byte(deref(b.PrivateKey))
	clientChain, clientKey := []byte(deref(b.ClientCertificateChain)), []byte(deref(b.ClientPrivateKey))
	if req.Endpoint != gen.TlsEndpointNameWeb && req.Endpoint != gen.TlsEndpointNameAgent {
		return nil, apierr.Invalid("endpoint must be web or agent")
	}
	if (len(clientChain) > 0 || len(clientKey) > 0) && (req.Endpoint != gen.TlsEndpointNameAgent || b.Mode != gen.TlsCertModeManual) {
		return nil, apierr.Invalid("a client certificate applies to manual Agent TLS only")
	}
	var err error
	switch b.Mode {
	case gen.TlsCertModeAuto:
		if len(chain) > 0 || len(key) > 0 {
			return nil, apierr.Invalid("certificateChain and privateKey must be absent in auto mode")
		}
		if req.Endpoint == gen.TlsEndpointNameWeb {
			err = h.pki.SetWebAuto(ctx)
		} else {
			err = h.pki.SetAgentAuto(ctx)
		}
	case gen.TlsCertModeManual:
		if len(chain) == 0 || len(key) == 0 {
			return nil, apierr.Invalid("certificateChain and privateKey are required in manual mode")
		}
		if req.Endpoint == gen.TlsEndpointNameWeb {
			err = h.pki.SetWebManual(ctx, chain, key)
		} else {
			_, err = h.pki.SetAgentManual(ctx, chain, key, clientChain, clientKey)
		}
	default:
		return nil, apierr.Invalid("mode must be auto or manual")
	}
	if err != nil {
		return nil, mapErr(err)
	}
	h.log.Info("TLS settings changed", "endpoint", req.Endpoint, "mode", b.Mode, "by", h.who(ctx))
	st, err := h.tlsState(ctx)
	if err != nil {
		return nil, err
	}
	return gen.UpdateTlsEndpoint200JSONResponse(st), nil
}

// ChangeAgentTlsAnchor implements changeAgentTlsAnchor.
func (h *Handlers) ChangeAgentTlsAnchor(ctx context.Context, req gen.ChangeAgentTlsAnchorRequestObject) (gen.ChangeAgentTlsAnchorResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, apierr.Invalid("request body is required")
	}
	cert := []byte(deref(b.Certificate))
	if len(cert) > 0 && b.Action != gen.Prepare {
		return nil, apierr.Invalid("certificate applies to prepare only")
	}
	var err error
	switch b.Action {
	case gen.Prepare:
		err = h.pki.PrepareAnchor(ctx, cert)
	case gen.Activate:
		err = h.pki.ActivateAnchor(ctx, deref(b.Force))
	case gen.Cancel:
		err = h.pki.CancelAnchor(ctx)
	default:
		return nil, apierr.Invalid("action must be prepare, activate or cancel")
	}
	if err != nil {
		return nil, mapErr(err)
	}
	h.log.Info("agent TLS anchor change", "action", b.Action, "by", h.who(ctx), "at", h.now().UTC().Format(time.RFC3339))
	st, err := h.tlsState(ctx)
	if err != nil {
		return nil, err
	}
	return gen.ChangeAgentTlsAnchor200JSONResponse(st), nil
}
