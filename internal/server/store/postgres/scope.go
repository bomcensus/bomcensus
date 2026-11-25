// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"fmt"

	"github.com/bomcensus/bomcensus/server/scope"
)

// sqlScope turns the data scope of a call into SQL conditions. Every method
// that reads or writes scoped rows binds one (scoped, bindScope) or checks
// the scope (requireScope, requireAll); a context without a scope fails with
// scope.ErrNone.
//
// For All the conditions are TRUE and for the empty scope FALSE, without a
// parameter. Otherwise they compare with one text[] parameter, bound once
// and shared by all conditions of the statement.
type sqlScope struct {
	s  scope.Scope
	ph string // placeholder of the scope ids; empty for All and the empty scope
}

// bindScope reads the scope of ctx and, unless it is All or empty, adds its
// ids as a parameter with arg.
func bindScope(ctx context.Context, op string, arg func(any) string) (sqlScope, error) {
	s, err := scope.Require(ctx)
	if err != nil {
		return sqlScope{}, fmt.Errorf("postgres: %s: %w", op, err)
	}
	sc := sqlScope{s: s}
	if !s.IsAll() && !s.IsEmpty() {
		sc.ph = arg(s.IDs())
	}
	return sc, nil
}

// scoped starts a statement with args and binds the scope of ctx after
// them.
func scoped(ctx context.Context, op string, args ...any) (*ivQuery, sqlScope, error) {
	q := &ivQuery{args: args}
	sc, err := bindScope(ctx, op, q.arg)
	return q, sc, err
}

// requireScope is bindScope for statements that need no condition.
func requireScope(ctx context.Context, op string) (scope.Scope, error) {
	s, err := scope.Require(ctx)
	if err != nil {
		return scope.Scope{}, fmt.Errorf("postgres: %s: %w", op, err)
	}
	return s, nil
}

// requireAll fails unless ctx carries All. It guards the background
// methods that work across scopes (retention, schedulers).
func requireAll(ctx context.Context, op string) error {
	s, err := requireScope(ctx, op)
	if err != nil {
		return err
	}
	if !s.IsAll() {
		return fmt.Errorf("postgres: %s: %w", op, scope.ErrOutside)
	}
	return nil
}

// fixed returns the condition for All and the empty scope, and ok false
// for a scope of ids.
func (s sqlScope) fixed() (cond string, ok bool) {
	switch {
	case s.s.IsAll():
		return "TRUE", true
	case s.s.IsEmpty():
		return "FALSE", true
	}
	return "", false
}

// col is true when the scope id expression expr is in the scope.
func (s sqlScope) col(expr string) string {
	if c, ok := s.fixed(); ok {
		return c
	}
	return "(" + expr + " = ANY(" + s.ph + "::text[]))"
}

// asset is true when the asset with the id expression expr is in the scope.
func (s sqlScope) asset(expr string) string {
	if c, ok := s.fixed(); ok {
		return c
	}
	return "EXISTS (SELECT 1 FROM assets sa WHERE sa.id = " + expr + " AND " + s.col("sa.scope_id") + ")"
}

// cluster is true when the cluster with the id expression expr is in the
// scope.
func (s sqlScope) cluster(expr string) string {
	if c, ok := s.fixed(); ok {
		return c
	}
	return "EXISTS (SELECT 1 FROM k8s_clusters sk WHERE sk.id = " + expr + " AND " + s.col("sk.scope_id") + ")"
}

// shared is true for a scanner record (kind expression kindExpr is
// 'scanner'), visible to every scope, or one whose scope id expr is in the
// scope.
func (s sqlScope) shared(kindExpr, expr string) string {
	if c, ok := s.fixed(); ok {
		return c
	}
	return "(" + kindExpr + " = 'scanner' OR " + s.col(expr) + ")"
}

// image is true when something in the scope references the image with the
// digest expression expr: a container of an asset, a pod container of a
// cluster, or a tag recorded from an asset or cluster.
func (s sqlScope) image(expr string) string {
	if c, ok := s.fixed(); ok {
		return c
	}
	return `(EXISTS (SELECT 1 FROM asset_containers sct JOIN assets sa ON sa.id = sct.asset_id
			WHERE sct.image_digest = ` + expr + ` AND ` + s.col("sa.scope_id") + `)
		OR EXISTS (SELECT 1 FROM k8s_pod_containers spc JOIN k8s_pods sp ON sp.id = spc.pod_id
			JOIN k8s_clusters sk ON sk.id = sp.cluster_id
			WHERE spc.image_digest = ` + expr + ` AND ` + s.col("sk.scope_id") + `)
		OR EXISTS (SELECT 1 FROM image_tags sit WHERE sit.digest = ` + expr + `
			AND CASE sit.source_kind WHEN 'asset' THEN ` + s.asset("sit.source_id") + `
				ELSE ` + s.cluster("sit.source_id") + ` END))`
}

// component is true when the component with the id expression expr is on
// an asset in the scope or in an image visible in it.
func (s sqlScope) component(expr string) string {
	if c, ok := s.fixed(); ok {
		return c
	}
	return `(EXISTS (SELECT 1 FROM asset_components sac JOIN assets sa ON sa.id = sac.asset_id
			WHERE sac.component_id = ` + expr + ` AND ` + s.col("sa.scope_id") + `)
		OR EXISTS (SELECT 1 FROM image_components sic WHERE sic.component_id = ` + expr + `
			AND ` + s.image("sic.digest") + `))`
}

// rules is the p_scopes argument of triage_rule_for for content that does
// not belong to an asset: NULL for All, otherwise the scope ids.
func (s sqlScope) rules() string {
	switch {
	case s.s.IsAll():
		return "NULL::text[]"
	case s.s.IsEmpty():
		return "'{}'::text[]"
	}
	return s.ph + "::text[]"
}

// checkScope fails with scope.ErrOutside when id is not in s. It checks
// scope ids derived from a parent record.
func checkScope(op string, s scope.Scope, id string) error {
	if !s.Contains(id) {
		return fmt.Errorf("postgres: %s: scope id %q: %w", op, id, scope.ErrOutside)
	}
	return nil
}

// resolveScope picks the scope id of a new root record with scope.Resolve:
// requested when it is in s, otherwise the only id of s or the default
// scope for All.
func resolveScope(op string, s scope.Scope, requested string) (string, error) {
	id, err := scope.Resolve(s, requested)
	if err != nil {
		return "", fmt.Errorf("postgres: %s: scope id %q: %w", op, requested, err)
	}
	return id, nil
}

// isAll reports whether the scope is All.
func (s sqlScope) isAll() bool { return s.s.IsAll() }

// ivScopeAsset fails with ErrNotFound when the asset is not in the scope of
// ctx. It costs no query for All.
func (d *DB) ivScopeAsset(ctx context.Context, op, assetID string) error {
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return err
	}
	if sc.isAll() {
		return nil
	}
	if !ivValidID(assetID) {
		return ivNotFound(op)
	}
	var one int
	err = d.q.QueryRow(ctx, `SELECT 1 FROM assets a WHERE a.id = `+q.arg(assetID)+` AND `+sc.col("a.scope_id"),
		q.args...).Scan(&one)
	return ivErr(op, err)
}

// ivScopeCluster is ivScopeAsset for a cluster.
func (d *DB) ivScopeCluster(ctx context.Context, op, clusterID string) error {
	q, sc, err := scoped(ctx, op)
	if err != nil {
		return err
	}
	if sc.isAll() {
		return nil
	}
	if !ivValidID(clusterID) {
		return ivNotFound(op)
	}
	var one int
	err = d.q.QueryRow(ctx, `SELECT 1 FROM k8s_clusters c WHERE c.id = `+q.arg(clusterID)+` AND `+sc.col("c.scope_id"),
		q.args...).Scan(&one)
	return ivErr(op, err)
}
