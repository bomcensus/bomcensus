// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// subject is an authorized report subject.
type subject struct {
	agent   *store.Agent      // sender record; nil for the embedded scanner
	target  *store.ScanTarget // scan_target
	cluster *store.K8sCluster // k8s_container
	k8s     *report.K8sSubject
}

// authorize checks that sender may report on r's subject: an agent only on
// itself, a scanner on scan targets and clusters assigned to it (the
// embedded scanner, with an empty id, on those assigned to nobody).
func (s *Service) authorize(ctx context.Context, st store.Store, sender Sender, r *report.Report) (subject, error) {
	var subj subject
	a, err := senderAgent(ctx, st, sender)
	if err != nil {
		return subj, err
	}
	subj.agent = a
	kind := subjectKind(r)
	switch sender.Kind {
	case store.AgentKindAgent:
		if kind != report.SubjectSelf {
			return subj, newErr(ErrForbidden, "agent %s sent subject %q", sender.AgentID, kind)
		}
		return subj, nil
	case store.AgentKindScanner:
	default:
		return subj, newErr(ErrForbidden, "unknown sender kind %q", sender.Kind)
	}
	switch kind {
	case report.SubjectScanTarget:
		t, err := st.GetScanTarget(ctx, r.Subject.ScanTargetID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return subj, newErr(ErrForbidden, "unknown scan target %q", r.Subject.ScanTargetID)
			}
			return subj, fmt.Errorf("ingest: get scan target: %w", err)
		}
		if t.ScannerID != sender.AgentID {
			return subj, newErr(ErrForbidden, "scan target %s is not assigned to scanner %q", t.ID, sender.AgentID)
		}
		subj.target = &t
	case report.SubjectK8sContainer:
		k := r.Subject.K8s
		if k == nil || k.ClusterID == "" || k.Namespace == "" || k.Pod == "" || k.Container == "" {
			return subj, newErr(ErrInvalid, "incomplete kubernetes subject")
		}
		c, err := clusterOf(ctx, st, sender, k.ClusterID)
		if err != nil {
			return subj, err
		}
		subj.cluster = &c
		subj.k8s = k
	default:
		return subj, newErr(ErrForbidden, "scanner %q sent subject %q", sender.AgentID, kind)
	}
	return subj, nil
}

// senderAgent loads and checks the sender's record. The embedded scanner
// has none.
func senderAgent(ctx context.Context, st store.Store, sender Sender) (*store.Agent, error) {
	if sender.AgentID == "" {
		if sender.Kind != store.AgentKindScanner {
			return nil, newErr(ErrForbidden, "sender without id")
		}
		return nil, nil
	}
	a, err := st.GetAgent(ctx, sender.AgentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, newErr(ErrForbidden, "unknown sender %s", sender.AgentID)
		}
		return nil, fmt.Errorf("ingest: get agent: %w", err)
	}
	if a.Kind != sender.Kind {
		return nil, newErr(ErrForbidden, "sender %s is a %s, not a %s", a.ID, a.Kind, sender.Kind)
	}
	if a.State != store.AgentApproved {
		return nil, newErr(ErrForbidden, "sender %s is %s", a.ID, a.State)
	}
	return &a, nil
}

// clusterOf loads a cluster and checks that sender is its scanner.
func clusterOf(ctx context.Context, st store.Store, sender Sender, clusterID string) (store.K8sCluster, error) {
	if sender.Kind != store.AgentKindScanner {
		return store.K8sCluster{}, newErr(ErrForbidden, "only scanners report on clusters")
	}
	c, err := st.GetCluster(ctx, clusterID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return c, newErr(ErrForbidden, "unknown cluster %q", clusterID)
		}
		return c, fmt.Errorf("ingest: get cluster: %w", err)
	}
	if c.ScannerID != sender.AgentID {
		return c, newErr(ErrForbidden, "cluster %s is not assigned to scanner %q", c.ID, sender.AgentID)
	}
	return c, nil
}
