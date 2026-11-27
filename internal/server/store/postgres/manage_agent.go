// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bomcensus/bomcensus/internal/server/store"
)

// mgAgentColumns reads an agent through the alias a.
const mgAgentColumns = `a.id::text, a.kind, a.hostname, a.description, a.identity_key, a.hpke_public_key,
	coalesce(a.register_key_id, ''), a.state, a.version, a.os, a.arch, a.connect_mode, a.listen_address,
	a.tls_mode, a.observed_issuer, a.privilege, a.exec_helper, a.address, a.trust_bundle_version,
	a.update_state, a.update_message, coalesce(a.asset_id::text, ''), a.enrolled_at, a.approved_at, a.revoked_at, a.last_seen,
	(SELECT max(c.not_after) FROM agent_certs c WHERE c.agent_id = a.id AND c.revoked_at IS NULL), a.features,
	array(SELECT x.dir_id::text FROM agent_detect_dirs x JOIN detect_dirs dd ON dd.id = x.dir_id
		WHERE x.agent_id = a.id ORDER BY dd.path),
	array(SELECT dd.path FROM agent_detect_dirs x JOIN detect_dirs dd ON dd.id = x.dir_id
		WHERE x.agent_id = a.id ORDER BY dd.path), a.integrity, coalesce(a.scope_id, ''), a.detectors_digest`

// mgScanAgent scans mgAgentColumns followed by extra.
func mgScanAgent(r mgRow, extra ...any) (store.Agent, error) {
	var a store.Agent
	dest := []any{&a.ID, &a.Kind, &a.Hostname, &a.Description, &a.IdentityKey, &a.HPKEPublicKey,
		&a.RegisterKeyID, &a.State, &a.Version, &a.OS, &a.Arch, &a.ConnectMode, &a.ListenAddress,
		&a.TLSMode, &a.ObservedIssuer, &a.Privilege, &a.ExecHelper, &a.Address, &a.TrustBundleVersion,
		&a.UpdateState, &a.UpdateMessage, &a.AssetID, &a.EnrolledAt, &a.ApprovedAt, &a.RevokedAt, &a.LastSeen,
		&a.CertNotAfter, &a.Features, &a.DetectDirIDs, &a.DetectPaths, &a.Integrity, &a.ScopeID, &a.DetectorsDigest}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return store.Agent{}, err
	}
	a.EnrolledAt = a.EnrolledAt.UTC()
	a.ApprovedAt = mgUTCPtr(a.ApprovedAt)
	a.RevokedAt = mgUTCPtr(a.RevokedAt)
	a.LastSeen = mgUTCPtr(a.LastSeen)
	a.CertNotAfter = mgUTCPtr(a.CertNotAfter)
	return a, nil
}

// CreateAgent implements store.Agents.
func (d *DB) CreateAgent(ctx context.Context, a store.Agent) (store.Agent, error) {
	if a.State != store.AgentApproved && a.State != store.AgentPending {
		return store.Agent{}, fmt.Errorf("postgres: create agent: state %q: %w", a.State, store.ErrInvalid)
	}
	if len(a.IdentityKey) == 0 {
		return store.Agent{}, fmt.Errorf("postgres: create agent: no identity key: %w", store.ErrInvalid)
	}
	if a.ID == "" {
		id, err := mgNewID()
		if err != nil {
			return store.Agent{}, err
		}
		a.ID = id
	}
	if a.ConnectMode == "" {
		a.ConnectMode = store.ConnectModeConnect
	}
	if a.TLSMode == "" {
		a.TLSMode = store.TLSVerifyPinned
	}
	if a.UpdateState == "" {
		a.UpdateState = store.UpdateUpToDate
	}
	enrolled := mgOrNow(a.EnrolledAt)
	approved := mgTimePtr(a.ApprovedAt)
	if a.State == store.AgentApproved && a.ApprovedAt == nil {
		approved = enrolled
	}
	scopeID, err := d.mgAgentScope(ctx, a)
	if err != nil {
		return store.Agent{}, err
	}
	out, err := mgScanAgent(d.q.QueryRow(ctx, `
		INSERT INTO agents AS a (id, kind, hostname, identity_key, hpke_public_key, register_key_id, state,
			version, os, arch, connect_mode, listen_address, tls_mode, observed_issuer, privilege, exec_helper,
			address, trust_bundle_version, update_state, asset_id, enrolled_at, approved_at, last_seen, description,
			scope_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25)
		RETURNING `+mgAgentColumns,
		a.ID, a.Kind, a.Hostname, a.IdentityKey, mgBytes(a.HPKEPublicKey), mgText(a.RegisterKeyID), a.State,
		a.Version, a.OS, a.Arch, a.ConnectMode, a.ListenAddress, a.TLSMode, a.ObservedIssuer, a.Privilege,
		a.ExecHelper, a.Address, a.TrustBundleVersion, a.UpdateState, mgText(a.AssetID), enrolled, approved,
		mgTimePtr(a.LastSeen), a.Description, scopeID))
	if err != nil {
		return store.Agent{}, mgErr("create agent", err)
	}
	return out, nil
}

// mgAgentScope is the scope id of a new agent: none for a scanner, that of
// its register key, otherwise a.ScopeID resolved in the scope of ctx.
func (d *DB) mgAgentScope(ctx context.Context, a store.Agent) (any, error) {
	const op = "create agent"
	s, err := requireScope(ctx, op)
	if err != nil {
		return nil, err
	}
	if a.Kind == store.AgentKindScanner {
		return nil, nil
	}
	id := a.ScopeID
	if a.RegisterKeyID != "" {
		var key string
		err := d.q.QueryRow(ctx, `SELECT coalesce(scope_id, '') FROM register_keys WHERE id = $1`, a.RegisterKeyID).Scan(&key)
		switch {
		case err == nil && key != "":
			id = key
		case err != nil && !errors.Is(err, pgx.ErrNoRows):
			return nil, mgErr(op, err)
		}
	}
	id, err = resolveScope(op, s, id)
	if err != nil {
		return nil, err
	}
	return id, nil
}

// mgAgentBy reads one agent by id in the scope of ctx; suffix ends the
// statement (a locking clause).
func (d *DB) mgAgentBy(ctx context.Context, op, cond string, v any, suffix string) (store.Agent, error) {
	q, sc, err := scoped(ctx, op, v)
	if err != nil {
		return store.Agent{}, err
	}
	a, err := mgScanAgent(d.q.QueryRow(ctx, `SELECT `+mgAgentColumns+` FROM agents a WHERE `+cond+` AND `+
		sc.shared("a.kind", "a.scope_id")+suffix, q.args...))
	if err != nil {
		return store.Agent{}, mgErr(op, err)
	}
	return a, nil
}

// GetAgent implements store.Agents.
func (d *DB) GetAgent(ctx context.Context, id string) (store.Agent, error) {
	return d.mgAgentBy(ctx, "get agent", "a.id = $1", id, "")
}

// LockAgent implements store.Agents.
func (d *DB) LockAgent(ctx context.Context, id string) (store.Agent, error) {
	return d.mgAgentBy(ctx, "lock agent", "a.id = $1", id, " FOR SHARE OF a")
}

// GetAgentByIdentityKey implements store.Agents.
func (d *DB) GetAgentByIdentityKey(ctx context.Context, key []byte) (store.Agent, error) {
	return d.mgAgentBy(ctx, "get agent by identity key", "a.identity_key = $1", key, "")
}

// mgAgentStatus is store.Agent.Status with the online threshold $3.
const mgAgentStatus = `(CASE WHEN a.state = 'pending' THEN 'pending_approval'
	WHEN a.state = 'revoked' THEN 'revoked'
	WHEN a.last_seen >= $3 THEN 'online' ELSE 'offline' END)`

var mgAgentSort = map[string]string{
	"hostname":     "a.hostname",
	"status":       mgAgentStatus,
	"version":      `version_sort_key('semver', a.version) COLLATE "C"`,
	"connect_mode": "a.connect_mode",
	"tls_mode":     "a.tls_mode",
	"privilege":    "a.privilege",
	"update_state": `(CASE a.update_state WHEN 'pending' THEN 1 WHEN 'updating' THEN 2 WHEN 'rolled_back' THEN 3 ELSE 0 END)`,
	"address":      "a.address",
	"last_seen":    "a.last_seen",
	"enrolled_at":  "a.enrolled_at",
}

// mgAgentWhere filters with $1..$11 and the scope of the call.
func mgAgentWhere(sc sqlScope) string {
	return `
	WHERE ($1 = '' OR a.kind = $1)
	  AND ($2 = '' OR ` + mgAgentStatus + ` = $2)
	  AND ($4 = '' OR a.connect_mode = $4)
	  AND ($5 = '' OR a.tls_mode = $5)
	  AND ($6 = '' OR strpos(lower(a.hostname), lower($6)) > 0
	              OR strpos(lower(a.description), lower($6)) > 0
	              OR strpos(lower(a.address), lower($6)) > 0
	              OR strpos(a.id::text, lower($6)) > 0
	              OR strpos(lower(a.os), lower($6)) > 0
	              OR strpos(lower(a.listen_address), lower($6)) > 0)
	  AND ($7 = '' OR coalesce(nullif(a.update_state, ''), 'up_to_date') = $7)
	  AND ($8 = '' OR a.register_key_id = $8)
	  AND ($9 = '' OR a.version = $9)
	  AND (NOT $10 OR (a.state <> 'revoked'
	       AND (($11 <> '' AND a.version <> $11) OR coalesce(nullif(a.update_state, ''), 'up_to_date') <> 'up_to_date')))
	  AND ` + sc.shared("a.kind", "a.scope_id")
}

// ListAgents implements store.Agents.
func (d *DB) ListAgents(ctx context.Context, f store.AgentFilter, p store.Page) ([]store.Agent, int, error) {
	const op = "list agents"
	p = p.Normalize()
	order, err := mgOrder(op, f.Sort, "hostname", mgAgentSort, false, "lower(a.hostname), a.id")
	if err != nil {
		return nil, 0, err
	}
	q, sc, err := scoped(ctx, op, string(f.Kind), string(f.Status), f.OnlineAfter.UTC(), string(f.ConnectMode),
		string(f.TLSMode), strings.TrimSpace(f.Q), string(f.UpdateState), f.RegisterKeyID, f.Version,
		f.Outdated, f.TargetVersion)
	if err != nil {
		return nil, 0, err
	}
	args := q.args
	n := len(args)
	rows, err := d.q.Query(ctx, `SELECT `+mgAgentColumns+`, count(*) OVER () FROM agents a`+mgAgentWhere(sc)+
		order+fmt.Sprintf(` LIMIT $%d OFFSET $%d`, n+1, n+2),
		append(args, p.Limit, p.Offset)...)
	if err != nil {
		return nil, 0, mgErr(op, err)
	}
	defer rows.Close()
	out := []store.Agent{}
	total := 0
	for rows.Next() {
		a, err := mgScanAgent(rows, &total)
		if err != nil {
			return nil, 0, mgErr(op, err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mgErr(op, err)
	}
	if len(out) == 0 && p.Offset > 0 {
		if err := d.q.QueryRow(ctx, `SELECT count(*) FROM agents a`+mgAgentWhere(sc), args[:n]...).Scan(&total); err != nil {
			return nil, 0, mgErr(op, err)
		}
	}
	return out, total, nil
}

// ApproveAgent implements store.Agents.
// Scanners are changed only with All, like every agent write below.
func (d *DB) ApproveAgent(ctx context.Context, id string, at time.Time) error {
	q, sc, err := scoped(ctx, "approve agent", id, at.UTC())
	if err != nil {
		return err
	}
	cond := sc.col("scope_id")
	tag, err := d.q.Exec(ctx,
		`UPDATE agents SET state = 'approved', approved_at = $2 WHERE id = $1 AND state = 'pending' AND `+cond, q.args...)
	if err != nil {
		return mgErr("approve agent", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var state store.AgentState
	q, sc, _ = scoped(ctx, "approve agent", id)
	if err := d.q.QueryRow(ctx, `SELECT state FROM agents WHERE id = $1 AND `+sc.col("scope_id"), q.args...).Scan(&state); err != nil {
		return mgErr("approve agent", err)
	}
	if state == store.AgentApproved {
		return nil
	}
	return fmt.Errorf("postgres: approve agent: state %s: %w", state, store.ErrInvalidState)
}

// RevokeAgent implements store.Agents.
func (d *DB) RevokeAgent(ctx context.Context, id string, at time.Time) error {
	q, sc, err := scoped(ctx, "revoke agent", id, at.UTC())
	if err != nil {
		return err
	}
	var n int
	err = d.q.QueryRow(ctx, `
		WITH a AS (
			UPDATE agents SET state = 'revoked', revoked_at = coalesce(revoked_at, $2)
			WHERE id = $1 AND `+sc.col("scope_id")+` RETURNING id
		), c AS (
			UPDATE agent_certs SET revoked_at = $2
			WHERE agent_id IN (SELECT id FROM a) AND revoked_at IS NULL
		), g AS (
			UPDATE assets SET gone_at = $2
			WHERE agent_id IN (SELECT id FROM a) AND gone_at IS NULL
		)
		SELECT count(*) FROM a`, q.args...).Scan(&n)
	if err != nil {
		return mgErr("revoke agent", err)
	}
	if n == 0 {
		return mgNotFound("revoke agent")
	}
	return nil
}

// UpdateAgentPoll implements store.Agents.
func (d *DB) UpdateAgentPoll(ctx context.Context, id string, s store.AgentPollStatus) error {
	return d.mgUpdateAgent(ctx, "update agent poll", `hostname = $2, version = $3, os = $4, arch = $5, connect_mode = $6,
			listen_address = $7, tls_mode = $8, observed_issuer = $9, privilege = $10, exec_helper = $11,
			address = $12, trust_bundle_version = $13, update_state = $14, last_seen = $15,
			update_message = $16, features = $17, detectors_digest = $18`,
		id, s.Hostname, s.Version, s.OS, s.Arch, s.ConnectMode, s.ListenAddress, s.TLSMode, s.ObservedIssuer,
		s.Privilege, s.ExecHelper, s.Address, s.TrustBundleVersion, s.UpdateState, mgOrNow(s.SeenAt),
		s.UpdateMessage, vuStrings(s.Features), s.DetectorsDigest)
}

// mgUpdateAgent runs UPDATE agents SET set WHERE id = $1 for exactly one
// agent in the scope of ctx; args are id followed by the values of set.
func (d *DB) mgUpdateAgent(ctx context.Context, op, set string, args ...any) error {
	q, sc, err := scoped(ctx, op, args...)
	if err != nil {
		return err
	}
	tag, err := d.q.Exec(ctx, `UPDATE agents SET `+set+` WHERE id = $1 AND `+sc.col("scope_id"), q.args...)
	return mgExactlyOne(op, tag, err)
}

// TouchAgent implements store.Agents.
func (d *DB) TouchAgent(ctx context.Context, id string, at time.Time) error {
	return d.mgUpdateAgent(ctx, "touch agent", `last_seen = greatest(last_seen, $2)`, id, at.UTC())
}

// SetAgentDescription implements store.Agents.
func (d *DB) SetAgentDescription(ctx context.Context, id, description string) error {
	return d.mgUpdateAgent(ctx, "set agent description", `description = $2`, id, description)
}

// SetAgentAsset implements store.Agents.
func (d *DB) SetAgentAsset(ctx context.Context, id, assetID string) error {
	return d.mgUpdateAgent(ctx, "set agent asset", `asset_id = $2`, id, mgText(assetID))
}

// AdvanceAgentCounter implements store.Agents.
func (d *DB) AdvanceAgentCounter(ctx context.Context, id string, value uint64) (bool, error) {
	if value > math.MaxInt64 {
		return false, fmt.Errorf("postgres: advance agent counter: %w", store.ErrInvalid)
	}
	// The row lock serializes concurrent calls and the condition is checked
	// again against the committed value, so the counter only grows.
	q, sc, err := scoped(ctx, "advance agent counter", id, int64(value))
	if err != nil {
		return false, err
	}
	tag, err := d.q.Exec(ctx,
		`UPDATE agents SET msg_counter = $2 WHERE id = $1 AND msg_counter < $2 AND `+sc.col("scope_id"), q.args...)
	if err != nil {
		return false, mgErr("advance agent counter", err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	if _, err := d.AgentCounter(ctx, id); err != nil {
		return false, err
	}
	return false, nil
}

// AgentCounter implements store.Agents.
func (d *DB) AgentCounter(ctx context.Context, id string) (uint64, error) {
	q, sc, err := scoped(ctx, "agent counter", id)
	if err != nil {
		return 0, err
	}
	var v int64
	if err := d.q.QueryRow(ctx, `SELECT msg_counter FROM agents WHERE id = $1 AND `+sc.shared("kind", "scope_id"),
		q.args...).Scan(&v); err != nil {
		return 0, mgErr("agent counter", err)
	}
	return uint64(v), nil
}

// CountAgents implements store.Agents.
func (d *DB) CountAgents(ctx context.Context, onlineAfter time.Time) (store.AgentCounts, error) {
	q, sc, err := scoped(ctx, "count agents", onlineAfter.UTC())
	if err != nil {
		return store.AgentCounts{}, err
	}
	var c store.AgentCounts
	err = d.q.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE state = 'approved' AND last_seen >= $1),
			count(*) FILTER (WHERE state = 'approved' AND (last_seen IS NULL OR last_seen < $1)),
			count(*) FILTER (WHERE state = 'pending'),
			count(*) FILTER (WHERE state = 'revoked'),
			count(*) FILTER (WHERE state <> 'revoked' AND tls_mode <> 'pinned'),
			count(*) FILTER (WHERE state = 'approved' AND trust_bundle_version <
				(SELECT coalesce(max(version), 0) FROM trust_bundle)),
			count(*) FILTER (WHERE state <> 'revoked' AND observed_issuer <> '')
		FROM agents WHERE `+sc.shared("kind", "scope_id"), q.args...).
		Scan(&c.Online, &c.Offline, &c.PendingApproval, &c.Revoked, &c.NotPinned, &c.TrustBundleBehind,
			&c.TLSIntercepted)
	if err != nil {
		return store.AgentCounts{}, mgErr("count agents", err)
	}
	return c, nil
}

// InsertAgentCert implements store.AgentCerts.
func (d *DB) InsertAgentCert(ctx context.Context, c store.AgentCert) error {
	_, err := d.q.Exec(ctx, `
		INSERT INTO agent_certs (serial, agent_id, not_before, not_after, revoked_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		c.Serial, c.AgentID, c.NotBefore.UTC(), c.NotAfter.UTC(), mgTimePtr(c.RevokedAt), mgOrNow(c.CreatedAt))
	return mgErr("insert agent cert", err)
}

// ListAgentCerts implements store.AgentCerts.
func (d *DB) ListAgentCerts(ctx context.Context, agentID string) ([]store.AgentCert, error) {
	rows, err := d.q.Query(ctx, `
		SELECT serial, agent_id::text, not_before, not_after, revoked_at, created_at
		FROM agent_certs WHERE agent_id = $1 ORDER BY not_before DESC, serial`, agentID)
	if err != nil {
		return nil, mgErr("list agent certs", err)
	}
	defer rows.Close()
	out := []store.AgentCert{}
	for rows.Next() {
		var c store.AgentCert
		if err := rows.Scan(&c.Serial, &c.AgentID, &c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.CreatedAt); err != nil {
			return nil, mgErr("list agent certs", err)
		}
		c.NotBefore, c.NotAfter, c.CreatedAt = c.NotBefore.UTC(), c.NotAfter.UTC(), c.CreatedAt.UTC()
		c.RevokedAt = mgUTCPtr(c.RevokedAt)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr("list agent certs", err)
	}
	return out, nil
}

// IsAgentCertRevoked implements store.AgentCerts.
func (d *DB) IsAgentCertRevoked(ctx context.Context, serial string) (bool, error) {
	var revoked bool
	err := d.q.QueryRow(ctx, `
		SELECT c.revoked_at IS NOT NULL OR a.state = 'revoked'
		FROM agent_certs c JOIN agents a ON a.id = c.agent_id
		WHERE c.serial = $1`, serial).Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, mgNotFound("is agent cert revoked")
	}
	if err != nil {
		return true, mgErr("is agent cert revoked", err)
	}
	return revoked, nil
}

// RevokeAgentCerts implements store.AgentCerts.
func (d *DB) RevokeAgentCerts(ctx context.Context, agentID string, at time.Time) (int64, error) {
	tag, err := d.q.Exec(ctx,
		`UPDATE agent_certs SET revoked_at = $2 WHERE agent_id = $1 AND revoked_at IS NULL`, agentID, at.UTC())
	if err != nil {
		return 0, mgErr("revoke agent certs", err)
	}
	return tag.RowsAffected(), nil
}

// ListRevokedAgentCerts implements store.AgentCerts.
func (d *DB) ListRevokedAgentCerts(ctx context.Context, since time.Time) ([]store.AgentCert, error) {
	const op = "list revoked agent certs"
	rows, err := d.q.Query(ctx, `
		SELECT c.serial, c.agent_id::text, c.not_before, c.not_after, LEAST(c.revoked_at, a.revoked_at),
			c.created_at
		FROM agent_certs c JOIN agents a ON a.id = c.agent_id
		WHERE c.revoked_at >= $1 OR a.revoked_at >= $1
		ORDER BY c.serial`, mgSince(since))
	if err != nil {
		return nil, mgErr(op, err)
	}
	defer rows.Close()
	out := []store.AgentCert{}
	for rows.Next() {
		var c store.AgentCert
		if err := rows.Scan(&c.Serial, &c.AgentID, &c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.CreatedAt); err != nil {
			return nil, mgErr(op, err)
		}
		c.NotBefore, c.NotAfter, c.CreatedAt = c.NotBefore.UTC(), c.NotAfter.UTC(), c.CreatedAt.UTC()
		c.RevokedAt = mgUTCPtr(c.RevokedAt)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mgErr(op, err)
	}
	return out, nil
}

// mgSince maps a zero time to -infinity.
func mgSince(t time.Time) any {
	if t.IsZero() {
		return "-infinity"
	}
	return t.UTC()
}
