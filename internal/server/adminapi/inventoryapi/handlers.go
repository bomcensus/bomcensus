// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package inventoryapi implements the console API operations of meta,
// authentication, dashboard, assets, components, processes, images and
// Kubernetes. Handlers are thin mappings between API and store types.
// Authorization is done by the router before a handler runs.
package inventoryapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/session"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/version"
	"github.com/bomcensus/bomcensus/server/auth"
	"github.com/bomcensus/bomcensus/server/scope"
)

// Store is the part of the store the handlers read and write.
type Store interface {
	store.InventoryQuery
	store.K8sClusters
	store.AssetRequests
	store.VulnQuery
	store.Notices
	store.Triage
	store.Integrity
	GetActiveFeedServer(ctx context.Context) (store.FeedServer, error)
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
	PutSetting(ctx context.Context, key string, value json.RawMessage) error
	GetScanTarget(ctx context.Context, id string) (store.ScanTarget, error)
	CountMatches(ctx context.Context, e store.MatchEpoch) (store.MatchCounts, error)
}

// AgentStore gives the agent numbers of the dashboard and checks scanner
// references.
type AgentStore interface {
	GetAgent(ctx context.Context, id string) (store.Agent, error)
	CountAgents(ctx context.Context, onlineAfter time.Time) (store.AgentCounts, error)
}

// Authenticator logs users in and out (session.Service).
type Authenticator interface {
	Login(ctx context.Context, username, password string) (auth.Principal, *http.Cookie, error)
	Logout(ctx context.Context) (*http.Cookie, error)
}

// Collector asks for a collection of an asset now: a collect directive to
// its agent, a run of its scan target or an exec collection of a workload.
// It returns store.ErrNotFound for an unknown asset and store.ErrInvalidState
// when the asset cannot be collected (for example a revoked agent).
type Collector interface {
	RequestCollect(ctx context.Context, assetID string) error
}

// ClusterSyncer asks for an inventory sync of a cluster now. It returns
// store.ErrNotFound for an unknown cluster and store.ErrInvalidState when the
// cluster's scanner cannot take the work.
type ClusterSyncer interface {
	RequestSync(ctx context.Context, clusterID string) error
}

// CredentialChecker validates the credential a cluster refers to. It
// returns nil for a stored kubeconfig credential, an error wrapping
// ErrCredentialNotFound when there is none and one wrapping ErrNotKubeconfig
// for a credential of another kind.
type CredentialChecker interface {
	CheckKubeconfig(ctx context.Context, credentialID string) error
}

// Errors of a CredentialChecker.
var (
	ErrCredentialNotFound = errors.New("inventoryapi: credential not found")
	ErrNotKubeconfig      = errors.New("inventoryapi: credential is not a kubeconfig")
)

// DefaultOnlineWindow is how recently an agent must have been seen to count
// as online.
const DefaultOnlineWindow = 3 * time.Minute

// Config holds the dependencies of Handlers. Collector, Syncer and
// Credentials default to implementations that fail with 503.
type Config struct {
	Store  Store
	Agents AgentStore
	// Auth is the built-in login; nil answers 404 to login and logout.
	Auth        Authenticator
	Collector   Collector
	Syncer      ClusterSyncer
	Credentials CredentialChecker
	Logger      *slog.Logger
	// OnlineWindow defaults to DefaultOnlineWindow.
	OnlineWindow time.Duration
	// AgentAddress is the "host:port" agents connect to, shown in /meta:
	// the first Agent TLS server name with the agent port. Empty leaves it
	// out.
	AgentAddress string
	Now          func() time.Time
}

// Handlers implements the inventory part of gen.StrictServerInterface.
type Handlers struct {
	cfg Config
}

// New returns Handlers.
func New(cfg Config) *Handlers {
	if cfg.Collector == nil {
		cfg.Collector = unavailable{}
	}
	if cfg.Syncer == nil {
		cfg.Syncer = unavailable{}
	}
	if cfg.Credentials == nil {
		cfg.Credentials = unavailable{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.OnlineWindow <= 0 {
		cfg.OnlineWindow = DefaultOnlineWindow
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handlers{cfg: cfg}
}

// unavailable stands in for functions that are not wired up.
type unavailable struct{}

func (unavailable) RequestCollect(context.Context, string) error {
	return apierr.Unavailable("on-demand collection is not available")
}

func (unavailable) RequestSync(context.Context, string) error {
	return apierr.Unavailable("cluster sync is not available")
}

func (unavailable) CheckKubeconfig(context.Context, string) error {
	return apierr.Unavailable("credential checks are not available")
}

// CredentialGetter is the store method StoreCredentials needs.
type CredentialGetter interface {
	GetCredential(ctx context.Context, id string) (store.Credential, error)
}

// StoreCredentials is a CredentialChecker over the credential store.
type StoreCredentials struct {
	Store CredentialGetter
}

// CheckKubeconfig implements CredentialChecker.
func (s StoreCredentials) CheckKubeconfig(ctx context.Context, id string) error {
	c, err := s.Store.GetCredential(ctx, id)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalid) {
		return ErrCredentialNotFound
	}
	if err != nil {
		return err
	}
	if c.Kind != store.CredentialKubeconfig {
		return ErrNotKubeconfig
	}
	return nil
}

// logChange records a change made through the console.
func (h *Handlers) logChange(ctx context.Context, msg string, args ...any) {
	h.cfg.Logger.InfoContext(ctx, msg, append(args, "principal", auth.IDFrom(ctx))...)
}

// GetMeta implements gen.StrictServerInterface.
func (h *Handlers) GetMeta(ctx context.Context, _ gen.GetMetaRequestObject) (gen.GetMetaResponseObject, error) {
	return gen.GetMeta200JSONResponse{
		Version:      version.Version,
		Features:     gen.Features{Vulnerabilities: true, SbomExport: false},
		AgentAddress: str(h.cfg.AgentAddress),
	}, nil
}

// Login implements gen.StrictServerInterface.
func (h *Handlers) Login(ctx context.Context, req gen.LoginRequestObject) (gen.LoginResponseObject, error) {
	if h.cfg.Auth == nil {
		return nil, apierr.NotFound("login")
	}
	b := req.Body
	if b == nil || b.Username == "" || b.Password == "" {
		return nil, apierr.Invalid("username and password are required")
	}
	if len(b.Username) > 256 || len(b.Password) > 1024 {
		return nil, apierr.Invalid("username or password too long")
	}
	p, cookie, err := h.cfg.Auth.Login(ctx, b.Username, b.Password)
	var throttled *session.ThrottledError
	switch {
	case errors.As(err, &throttled):
		secs := int((throttled.RetryAfter + time.Second - 1) / time.Second)
		return gen.Login429JSONResponse{TooManyRequestsJSONResponse: gen.TooManyRequestsJSONResponse{
			Body:    gen.Error{Code: apierr.CodeTooManyRequests, Message: "too many failed logins, retry later"},
			Headers: gen.TooManyRequestsResponseHeaders{RetryAfter: &secs},
		}}, nil
	case errors.Is(err, auth.ErrInvalidCredentials):
		return nil, apierr.Unauthenticated("invalid username or password")
	case err != nil:
		return nil, err
	}
	c := cookie.String()
	return gen.Login200JSONResponse{
		Body:    gen.Principal{Id: p.ID(), Name: p.Name()},
		Headers: gen.Login200ResponseHeaders{SetCookie: &c},
	}, nil
}

// Logout implements gen.StrictServerInterface.
func (h *Handlers) Logout(ctx context.Context, _ gen.LogoutRequestObject) (gen.LogoutResponseObject, error) {
	if h.cfg.Auth == nil {
		return nil, apierr.NotFound("login")
	}
	cookie, err := h.cfg.Auth.Logout(ctx)
	if err != nil {
		return nil, err
	}
	c := cookie.String()
	return gen.Logout204Response{Headers: gen.Logout204ResponseHeaders{SetCookie: &c}}, nil
}

// GetCurrentUser implements gen.StrictServerInterface.
func (h *Handlers) GetCurrentUser(ctx context.Context, _ gen.GetCurrentUserRequestObject) (gen.GetCurrentUserResponseObject, error) {
	p, ok := auth.FromContext(ctx)
	if !ok {
		return nil, apierr.Unauthenticated("login required")
	}
	return gen.GetCurrentUser200JSONResponse{Id: p.ID(), Name: p.Name()}, nil
}

// dashboardCoverages is the order of the coverage counts; every value is
// present.
var dashboardCoverages = []gen.Coverage{
	gen.CoverageFull, gen.CoveragePartial, gen.CoverageProcessOnly,
	gen.CoverageInventoryOnly, gen.CoverageUnsupported, gen.CoverageFailed,
}

// GetDashboard implements gen.StrictServerInterface.
func (h *Handlers) GetDashboard(ctx context.Context, _ gen.GetDashboardRequestObject) (gen.GetDashboardResponseObject, error) {
	inv, err := h.cfg.Store.Dashboard(ctx)
	if err != nil {
		return nil, err
	}
	ag, err := h.cfg.Agents.CountAgents(ctx, h.cfg.Now().Add(-h.cfg.OnlineWindow))
	if err != nil {
		return nil, err
	}
	out := gen.GetDashboard200JSONResponse{
		Assets: gen.DashboardAssets{
			Total:     inv.Assets,
			Hosts:     inv.Hosts,
			Workloads: inv.Workloads,
			Limited:   inv.LimitedCoverage,
		},
		Processes: gen.DashboardProcesses{RestartRequired: inv.NeedsRestart, Suspicious: inv.Suspicious},
		Agents: gen.DashboardAgents{
			Online:          ag.Online,
			Offline:         ag.Offline,
			PendingApproval: ag.PendingApproval,
			Revoked:         ag.Revoked,
			NotPinned:       ag.NotPinned,
			TlsIntercepted:  ag.TLSIntercepted,
		},
	}
	for _, c := range dashboardCoverages {
		out.Coverage = append(out.Coverage, gen.CoverageCount{Coverage: c, Count: inv.AssetsByCoverage[store.Coverage(c)]})
	}
	return out, nil
}

// newScopeID is the data scope of a record created by the request:
// requested when it is in the request's scope, otherwise the only scope of
// the request, or the default scope for a request that sees every scope.
// scope.ErrOutside (403) otherwise.
func newScopeID(ctx context.Context, requested *string) (string, error) {
	s, err := scope.Require(ctx)
	if err != nil {
		return "", err
	}
	return scope.Resolve(s, deref(requested))
}
