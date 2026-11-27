// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

// scFix is what scFixture creates in one scope. Every string field is a
// marker of the scope: no call in another scope may return it.
type scFix struct {
	Mark                         string // also part of every name
	KeyID, AgentID, AssetID      string
	AgentKey                     string // identity key, as a string marker
	CredID, KubeCredID, TargetID string
	SSHAssetID                   string
	ClusterID, WorkloadID        string
	WorkloadAssetID, Namespace   string
	Pod, PodDigest               string
	CompID, ImgDigest            string
	ListenID, TriageID, AllowID  string
	ReportID, VulnID, Path       string
	NoticeID                     string
	idKey                        []byte
}

func (f scFix) markers() []string {
	var out []string
	v := reflect.ValueOf(f)
	for i := 0; i < v.NumField(); i++ {
		if fv := v.Field(i); fv.Kind() == reflect.String && fv.String() != "" {
			out = append(out, fv.String())
		}
	}
	return out
}

// scShared is created with All and visible to every scope.
type scShared struct {
	ScannerID  string
	SharedComp string // openssl, installed in both scopes
	SharedVuln string
}

func scRandKey() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// scFixture fills scope id with one of everything, created in that scope.
func scFixture(t *testing.T, db *DB, id, mark string, sh scShared) scFix {
	t.Helper()
	ctx := scope.With(ivCtx(t), scope.Of(id))
	f := scFix{Mark: mark, Namespace: "ns-" + mark, Pod: "pod-" + mark, PodDigest: "sha256:pod-" + mark,
		ImgDigest: "sha256:img-" + mark, VulnID: "CVE-" + strings.ToUpper(mark), Path: "/etc/" + mark + ".conf",
		NoticeID: "kisa-" + mark, idKey: scRandKey()}
	f.AgentKey = fmt.Sprintf("%x", f.idKey)
	keyID := strings.Repeat(mark[2:], 11)
	k, err := db.CreateRegisterKey(ctx, store.RegisterKey{ID: keyID, Name: "key-" + mark, PublicKey: scRandKey(),
		Target: store.AgentKindAgent, Approval: store.ApprovalAuto})
	ivMust(t, err)
	if k.ScopeID != id {
		t.Fatalf("register key scope %q", k.ScopeID)
	}
	f.KeyID = k.ID
	a, err := db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, Hostname: "host-" + mark,
		IdentityKey: f.idKey, RegisterKeyID: k.ID, State: store.AgentApproved, LastSeen: ptr(ivT0)})
	ivMust(t, err)
	if a.ScopeID != id {
		t.Fatalf("agent scope %q", a.ScopeID)
	}
	f.AgentID = a.ID

	ref, err := db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: a.ID, MachineID: "machine-shared"},
		store.AssetInit{Name: "asset-" + mark, Method: store.CollectAgent, SeenAt: ivT0})
	ivMust(t, err)
	f.AssetID = ref.ID
	ivMust(t, db.UpdateAssetFacts(ctx, f.AssetID, store.AssetFacts{Group: "web", SeenAt: ivT0}))
	ivMust(t, db.SetSectionStates(ctx, f.AssetID, []store.SectionState{{Section: "packages", Coverage: store.CoverageFull, CollectedAt: ivT0}}))
	own := ivDeb("pkg-"+mark, "1.0")
	res, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: f.AssetID, Source: store.SourcePackages},
		ivPkgObs(own, ivDeb("openssl", "3.0.13")), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	f.CompID = res.ComponentIDs[0]
	_, err = db.PutImageContent(ctx, store.ImageContent{Digest: f.ImgDigest, Coverage: store.CoverageFull, CollectedAt: ivT0,
		Packages: ivPkgObs(ivDeb("imgpkg-"+mark, "1.0"))})
	ivMust(t, err)
	ivMust(t, db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceAsset, ID: f.AssetID},
		[]store.ImageObservation{{Digest: f.ImgDigest, RepoTags: []string{"repo/" + mark + ":1"}}}, store.ReplaceOptions{At: ivT0}))
	ivMust(t, db.ReplaceContainers(ctx, f.AssetID, []store.ContainerObservation{{Name: "ct-" + mark, ImageDigest: f.ImgDigest,
		ImageRef: "repo/" + mark + ":1", Runtime: store.RuntimeDocker, Instances: 1, Coverage: store.CoverageFull}},
		store.ReplaceOptions{At: ivT0}))
	_, err = db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: f.AssetID}, store.ProcessSnapshot{At: ivT0,
		Processes: []store.ProcessObservation{{PID: 10, Exe: "/usr/bin/" + mark, StartedAt: ivT0,
			Listen: []store.ListenAddr{{Proto: "tcp", Address: "0.0.0.0", Port: 8443}}}}})
	ivMust(t, err)
	ivMust(t, db.PutGoSymbolQuery(ctx, store.GoSymbolQuery{AssetID: f.AssetID, Query: json.RawMessage(`{"m":"` + mark + `"}`)}))

	// Vulnerabilities: one of the scope's own component, one of the shared
	// one. Findings are applied directly.
	srv, err := db.GetActiveFeedServer(ctx)
	ivMust(t, err)
	img, err := db.LookupComponentIDs(ctx, []store.Component{ivDeb("imgpkg-"+mark, "1.0")})
	ivMust(t, err)
	vuln := []store.ComponentVuln{{VulnID: f.VulnID, Method: "package", FixState: "fixed", Severity: "high"}}
	ivMust(t, db.SaveMatches(ctx, store.MatchBatch{Epoch: store.MatchEpoch{ServerID: srv.ID, Revision: 1},
		Components: []store.ComponentMatch{{ComponentID: f.CompID, Status: store.MatchChecked, Vulns: vuln,
			Notices: []string{f.NoticeID}},
			{ComponentID: img[0], Status: store.MatchChecked, Vulns: vuln}},
		Vulns:   []store.VulnMeta{{ID: f.VulnID, Severity: "high"}},
		Notices: []store.Notice{{ID: f.NoticeID, Source: "kisa", Title: "notice-" + mark}}}))
	in, err := db.FindingInputs(ctx, f.AssetID)
	ivMust(t, err)
	procs := []store.FindingProcessRef{{PID: 10, Exe: "/usr/bin/" + mark}}
	_, err = db.ApplyFindings(ctx, f.AssetID, []store.FindingRow{
		{ComponentID: f.CompID, VulnID: f.VulnID, Exposure: store.ExposureRunning, Processes: procs},
		{ComponentID: sh.SharedComp, VulnID: sh.SharedVuln, Exposure: store.ExposureRunning, Processes: procs},
	}, in.Stamp)
	ivMust(t, err)

	c, err := db.CreateCredential(ctx, store.Credential{Name: "cred", Kind: store.CredentialSSHPassword, Username: "u-" + mark,
		Secret: []byte("s")})
	ivMust(t, err)
	f.CredID = c.ID
	kc, err := db.CreateCredential(ctx, store.Credential{Name: "kube", Kind: store.CredentialKubeconfig, Secret: []byte("k")})
	ivMust(t, err)
	f.KubeCredID = kc.ID
	st, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "target-" + mark, Address: "10.0.0.1", Port: 22,
		CredentialID: c.ID, ScannerID: sh.ScannerID, IntervalMinutes: 60})
	ivMust(t, err)
	f.TargetID = st.ID
	ssh, err := db.UpsertHostAsset(ctx, store.HostIdentity{ScanTargetID: st.ID, ScannerID: sh.ScannerID, Address: "10.0.0.1"},
		store.AssetInit{Name: "ssh-" + mark, Group: "grp-" + mark, Method: store.CollectSSH, SeenAt: ivT0})
	ivMust(t, err)
	f.SSHAssetID = ssh.ID

	cl, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "cluster", Connection: store.K8sKubeconfig,
		CredentialID: kc.ID, ScannerID: sh.ScannerID})
	ivMust(t, err)
	f.ClusterID = cl.ID
	inv, err := db.ReplaceClusterInventory(ctx, cl.ID, store.K8sInventory{At: ivT0, Workloads: []store.K8sWorkloadObservation{{
		Namespace: f.Namespace, Kind: "Deployment", Name: "wl-" + mark, Replicas: 1,
		Pods: []store.K8sPodObservation{{Name: f.Pod, Phase: "Running", StartedAt: ivT0,
			Containers: []store.K8sPodContainerObservation{{Name: "c", ImageRef: "pod/" + mark, ImageDigest: f.PodDigest}}}},
	}}})
	ivMust(t, err)
	f.WorkloadID, f.WorkloadAssetID = inv.Workloads[0].ID, inv.Workloads[0].AssetID

	lt, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: mark + ".example:7000", RegisterKeyID: k.ID})
	ivMust(t, err)
	f.ListenID = lt.ID

	tr, err := db.CreateTriageRule(ctx, store.TriageRule{VulnID: f.VulnID, ScopeKind: store.TriageScopeAsset,
		ScopeValue: f.AssetID, Justification: "code_not_present", Note: "note-" + mark})
	ivMust(t, err)
	f.TriageID = tr.ID

	sha := strings.Repeat(mark[2:], 64)
	ivMust(t, db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: f.AssetID, PassKey: "pass-" + mark, At: ivT0,
		Done: true, Checked: 1, Coverage: "full", Findings: []store.IntegrityObservation{itModified(f.Path, sha)}}))
	ar, err := db.CreateIntegrityAllowRule(ctx, store.IntegrityAllowRule{Scope: store.IntegrityScopeAsset, AssetID: f.SSHAssetID,
		Path: f.Path, Status: store.IntegrityModified, ActualSHA256: sha, Note: "allow-" + mark})
	ivMust(t, err)
	f.AllowID = ar.ID

	f.ReportID, err = db.StoreReport(ctx, store.RawReport{SourceID: a.ID, AssetID: f.AssetID, ReceivedAt: ivT0,
		Body: []byte("report-" + mark)})
	ivMust(t, err)
	return f
}

// scSetup makes scopes a and b and the shared records.
func scSetup(t *testing.T) (*DB, scShared, scFix, scFix) {
	db := newTestDB(t)
	all := ivCtx(t)
	var sh scShared
	sc, err := db.CreateAgent(all, store.Agent{Kind: store.AgentKindScanner, Hostname: "scanner", IdentityKey: scRandKey(),
		HPKEPublicKey: scRandKey(), State: store.AgentApproved})
	ivMust(t, err)
	if sc.ScopeID != "" {
		t.Fatalf("scanner scope %q", sc.ScopeID)
	}
	sh.ScannerID = sc.ID
	// The shared component is created on a throwaway asset first, so that
	// both scopes install the same row.
	tmp := ivHost(t, db, "seed")
	res, err := db.ReplaceAssetComponents(all, store.ComponentScope{AssetID: tmp, Source: store.SourcePackages},
		ivPkgObs(ivDeb("openssl", "3.0.13")), store.ReplaceOptions{At: ivT0})
	ivMust(t, err)
	sh.SharedComp = res.ComponentIDs[0]
	_, err = db.q.Exec(all, `DELETE FROM assets WHERE id = $1`, tmp)
	ivMust(t, err)
	sh.SharedVuln = "CVE-SHARED"
	srv, err := db.GetActiveFeedServer(all)
	ivMust(t, err)
	ivMust(t, db.SaveMatches(all, store.MatchBatch{Epoch: store.MatchEpoch{ServerID: srv.ID, Revision: 1},
		Components: []store.ComponentMatch{{ComponentID: sh.SharedComp, Status: store.MatchChecked,
			Vulns:   []store.ComponentVuln{{VulnID: sh.SharedVuln, Method: "package", FixState: "fixed", Severity: "critical"}},
			Notices: []string{"kisa-shared"}}},
		Vulns:   []store.VulnMeta{{ID: sh.SharedVuln, Severity: "critical"}},
		Notices: []store.Notice{{ID: "kisa-shared", Source: "kisa", Title: "shared notice"}}}))
	fa := scFixture(t, db, "a", "zza", sh)
	fb := scFixture(t, db, "b", "zzb", sh)
	return db, sh, fa, fb
}

// scRead is one read of scoped data, called with the scope a: once with
// the fixtures of a (own) and once with those of b (other).
type scRead struct {
	name string
	// wantOwn requires a marker of a in the result with the own fixtures.
	wantOwn bool
	// byID requires ErrNotFound with the other fixtures.
	byID bool
	call func(ctx context.Context, db *DB, f scFix, sh scShared) (any, error)
	// check, if set, inspects the result with the own fixtures.
	check func(t *testing.T, v any)
}

func scPage() store.Page { return store.Page{Limit: 1000} }

func scVulnOpts() store.VulnViewOptions {
	return store.VulnViewOptions{At: ivT0, IncludeDeferred: true, IncludeNegligible: true}
}

func scReads() []scRead {
	type F = scFix
	type S = scShared
	ctxDB := func(fn func(ctx context.Context, db *DB, f F) (any, error)) func(context.Context, *DB, F, S) (any, error) {
		return func(ctx context.Context, db *DB, f F, _ S) (any, error) { return fn(ctx, db, f) }
	}
	two := func(a any, _ int, err error) (any, error) { return a, err }
	return []scRead{
		{name: "ListAssets", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListAssets(ctx, store.AssetFilter{IncludeGone: true}, scPage()))
		})},
		{name: "ListAssetGroups", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListAssetGroups(ctx, store.AssetGroupFilter{}, scPage()))
		}), check: func(t *testing.T, v any) {
			for _, g := range v.([]store.AssetGroupRow) {
				if g.Name == "web" && g.Assets != 1 {
					t.Errorf("group web counts %d assets, want those of the scope only", g.Assets)
				}
			}
		}},
		{name: "GetAsset", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetAsset(ctx, f.AssetID)
		}), check: func(t *testing.T, v any) {
			if a := v.(store.AssetDetail); a.ScopeID != "a" || a.DuplicateMachineID {
				t.Errorf("asset scope %q duplicate %v", a.ScopeID, a.DuplicateMachineID)
			}
		}},
		{name: "ListAssetComponents", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListAssetComponents(ctx, f.AssetID, store.AssetComponentFilter{IncludeRemoved: true}, scPage()))
		})},
		{name: "ListAssetInstances", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListAssetInstances(ctx, f.WorkloadAssetID, store.PodFilter{IncludeGone: true}, scPage()))
		})},
		{name: "ListComponents", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListComponents(ctx, store.ComponentFilter{}, scPage()))
		})},
		{name: "GetComponent", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetComponent(ctx, f.CompID)
		})},
		{name: "ListComponentAssets", wantOwn: true, call: func(ctx context.Context, db *DB, f F, sh S) (any, error) {
			own, _, err := db.ListComponentAssets(ctx, f.CompID, store.ComponentAssetFilter{IncludeRemoved: true}, scPage())
			if err != nil {
				return nil, err
			}
			shared, _, err := db.ListComponentAssets(ctx, sh.SharedComp, store.ComponentAssetFilter{IncludeRemoved: true}, scPage())
			return []any{own, shared}, err
		}},
		{name: "ListProcesses", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListProcesses(ctx, store.ProcessFilter{}, scPage()))
		})},
		{name: "ListListenPorts", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListListenPorts(ctx, store.ListenPortFilter{}, scPage()))
		})},
		{name: "ListImages", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListImages(ctx, store.ImageFilter{}, scPage()))
		})},
		{name: "GetImage", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetImage(ctx, f.ImgDigest)
		})},
		{name: "ListImageComponents", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListImageComponents(ctx, f.ImgDigest, store.ImageComponentFilter{}, scPage()))
		})},
		{name: "ListWorkloads", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListWorkloads(ctx, f.ClusterID, store.WorkloadFilter{IncludeGone: true}, scPage()))
		})},
		{name: "ListWorkloadNamespaces", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.ListWorkloadNamespaces(ctx, f.ClusterID)
		})},
		{name: "ListWorkloadPods", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListWorkloadPods(ctx, f.WorkloadID, store.PodFilter{IncludeGone: true}, scPage()))
		})},
		{name: "GetWorkload", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetWorkload(ctx, f.WorkloadID)
		})},
		{name: "GetPod", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetPod(ctx, f.ClusterID, f.Namespace, f.Pod)
		})},
		{name: "Dashboard", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.Dashboard(ctx)
		}), check: func(t *testing.T, v any) {
			// Host, SSH host and workload of a; images of a's container and pod.
			if d := v.(store.InventoryCounts); d.Assets != 3 || d.Clusters != 1 || d.Images != 2 {
				t.Errorf("dashboard %+v", d)
			}
		}},
		{name: "ListClusters", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListClusters(ctx, store.ClusterFilter{}, scPage()))
		})},
		{name: "GetCluster", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetCluster(ctx, f.ClusterID)
		})},
		{name: "GetReport", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			r, err := db.GetReport(ctx, f.ReportID)
			return string(r.Body) + r.AssetID, err
		})},
		{name: "CountAgents", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.CountAgents(ctx, ivT0.Add(-time.Hour))
		}), check: func(t *testing.T, v any) {
			// The agent of a and the shared scanner.
			if c := v.(store.AgentCounts); c.Online+c.Offline+c.PendingApproval+c.Revoked != 2 {
				t.Errorf("agent counts %+v", c)
			}
		}},
		{name: "DetectorTableUsage", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.DetectorTableUsage(ctx)
		}), check: func(t *testing.T, v any) {
			// The agent of a and the shared scanner.
			n := 0
			for _, u := range v.([]store.DetectorTableUsage) {
				n += u.Count
			}
			if n != 2 {
				t.Errorf("detector table usage %+v", v)
			}
		}},
		{name: "GetAgent", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetAgent(ctx, f.AgentID)
		})},
		{name: "LockAgent", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.LockAgent(ctx, f.AgentID)
		})},
		{name: "GetAgentByIdentityKey", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetAgentByIdentityKey(ctx, f.idKey)
		})},
		{name: "ListAgents", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListAgents(ctx, store.AgentFilter{}, scPage()))
		}), check: func(t *testing.T, v any) {
			if n := len(v.([]store.Agent)); n != 2 {
				t.Errorf("%d agents, want the scope's and the shared scanner", n)
			}
		}},
		{name: "AgentCounter", byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.AgentCounter(ctx, f.AgentID)
		})},
		{name: "GetRegisterKey", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetRegisterKey(ctx, f.KeyID)
		})},
		{name: "ListRegisterKeys", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListRegisterKeys(ctx, store.RegisterKeyFilter{}, scPage()))
		})},
		{name: "GetListenTarget", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetListenTarget(ctx, f.ListenID)
		})},
		{name: "ListListenTargets", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListListenTargets(ctx, store.ListenTargetFilter{}, scPage()))
		})},
		{name: "ListCredentials", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.ListCredentials(ctx)
		})},
		{name: "GetCredential", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetCredential(ctx, f.CredID)
		})},
		{name: "GetCredentialWithSecret", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetCredentialWithSecret(ctx, f.CredID)
		})},
		{name: "GetScanTarget", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetScanTarget(ctx, f.TargetID)
		})},
		{name: "ListScanTargets", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListScanTargets(ctx, store.ScanTargetFilter{}, scPage()))
		})},
		{name: "VulnComponents", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.VulnComponents(ctx, scVulnOpts())
		}), check: func(t *testing.T, v any) {
			for _, r := range v.([]store.VulnComponentRow) {
				if r.Assets != 1 {
					t.Errorf("component %s on %d assets, want the scope's only", r.Component.Name, r.Assets)
				}
			}
		}},
		{name: "VulnCves", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.VulnCves(ctx, scVulnOpts())
		}), check: func(t *testing.T, v any) {
			for _, r := range v.([]store.VulnCveRow) {
				if r.Assets != 1 {
					t.Errorf("%s on %d assets, want the scope's only", r.Meta.ID, r.Assets)
				}
			}
		}},
		{name: "VulnProcesses", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.VulnProcesses(ctx, scVulnOpts())
		})},
		{name: "VulnImages", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.VulnImages(ctx, scVulnOpts())
		})},
		{name: "ImageVulns", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.ImageVulns(ctx, f.ImgDigest, ivT0)
		})},
		{name: "CountDeferred", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.CountDeferred(ctx, ivT0)
		}), check: func(t *testing.T, v any) {
			// The scope's own vulnerability is deferred by its asset rule.
			if v.(int) != 1 {
				t.Errorf("deferred %v", v)
			}
		}},
		{name: "CountNegligible", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.CountNegligible(ctx, ivT0)
		})},
		{name: "CountFindingAssets", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.CountFindingAssets(ctx, ivT0)
		}), check: func(t *testing.T, v any) {
			if v.(int) != 1 {
				t.Errorf("finding assets %v", v)
			}
		}},
		{name: "OpenFindings", wantOwn: true, call: func(ctx context.Context, db *DB, f F, sh S) (any, error) {
			own, err := db.OpenFindings(ctx, store.OpenFindingFilter{AssetID: f.AssetID, At: ivT0})
			if err != nil {
				return nil, err
			}
			shared, err := db.OpenFindings(ctx, store.OpenFindingFilter{VulnID: sh.SharedVuln, At: ivT0})
			return []any{own, shared}, err
		}},
		{name: "FindingInputs", byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.FindingInputs(ctx, f.AssetID)
		})},
		{name: "ListTriageRules", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.ListTriageRules(ctx, ivT0, true)
		})},
		{name: "GetTriageRule", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetTriageRule(ctx, f.TriageID)
		})},
		{name: "ListTriageEvents", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.ListTriageEvents(ctx, 0, 1000)
		})},
		{name: "ClusterGoSymbolQueries", byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.ClusterGoSymbolQueries(ctx, f.ClusterID)
		})},
		{name: "GoSymbolQueryFor", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			q, err := db.GoSymbolQueryFor(ctx, f.AssetID, "")
			return string(q.Query), err
		})},
		{name: "LastIntegrityPass", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.LastIntegrityPass(ctx, f.AssetID)
		})},
		{name: "LastCompletedIntegrityPass", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.LastCompletedIntegrityPass(ctx, f.AssetID)
		})},
		{name: "ListIntegrityGroups", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListIntegrityGroups(ctx, store.IntegrityFilter{IncludeAllowed: true}, scPage()))
		})},
		{name: "ListIntegrityFindings", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListIntegrityFindings(ctx, store.IntegrityFilter{IncludeAllowed: true}, scPage()))
		})},
		{name: "IntegritySummary", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.IntegritySummary(ctx, ivT0.Add(-time.Hour))
		}), check: func(t *testing.T, v any) {
			if s := v.(store.IntegritySummary); s.Assets != 1 || s.Rules != 1 || s.Tracked != 1 || s.Completed != 1 {
				t.Errorf("integrity summary %+v", s)
			}
		}},
		{name: "ListIntegrityAllowRules", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListIntegrityAllowRules(ctx, true, scPage()))
		})},
		{name: "CountMatches", call: func(ctx context.Context, db *DB, f F, _ S) (any, error) {
			srv, err := db.GetActiveFeedServer(ctx)
			if err != nil {
				return nil, err
			}
			return db.CountMatches(ctx, store.MatchEpoch{ServerID: srv.ID, Revision: 1})
		}, check: func(t *testing.T, v any) {
			// pkg-zza, openssl and imgpkg-zza; nothing of b.
			if c := v.(store.MatchCounts); c.Checked+c.Pending != 3 {
				t.Errorf("match counts %+v", c)
			}
		}},
		{name: "ListNotices", wantOwn: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return two(db.ListNotices(ctx, store.NoticeFilter{IncludeRead: true}, scPage()))
		}), check: func(t *testing.T, v any) {
			for _, n := range v.([]store.NoticeRow) {
				if n.Assets != 1 {
					t.Errorf("notice %s on %d assets, want the scope's only", n.ID, n.Assets)
				}
			}
		}},
		{name: "GetNotice", wantOwn: true, byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.GetNotice(ctx, f.NoticeID)
		})},
		{name: "ListNoticeMatches", wantOwn: true, call: func(ctx context.Context, db *DB, f F, _ S) (any, error) {
			own, err := db.ListNoticeMatches(ctx, store.NoticeMatchFilter{NoticeID: f.NoticeID})
			if err != nil {
				return nil, err
			}
			shared, err := db.ListNoticeMatches(ctx, store.NoticeMatchFilter{NoticeID: "kisa-shared"})
			if err != nil {
				return nil, err
			}
			asset, err := db.ListNoticeMatches(ctx, store.NoticeMatchFilter{AssetID: f.AssetID})
			return []any{own, shared, asset}, err
		}},
		{name: "CountNotices", call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.CountNotices(ctx)
		}), check: func(t *testing.T, v any) {
			// The scope's own notice and the shared one.
			if c := v.(store.NoticeCounts); c.Total != 2 {
				t.Errorf("notice counts %+v", c)
			}
		}},
		{name: "ComponentsAtLocations", byID: true, call: ctxDB(func(ctx context.Context, db *DB, f F) (any, error) {
			return db.ComponentsAtLocations(ctx, f.AssetID, []store.ComponentLocation{{Path: "/var/lib/dpkg/status"}})
		})},
	}
}

// scWrite is a write in the scope a against a record of b (or a new record
// asked for in b); it must fail with want.
type scWrite struct {
	name string
	want error
	call func(ctx context.Context, db *DB, own, other scFix, sh scShared) error
}

func scWrites() []scWrite {
	nf, out := store.ErrNotFound, scope.ErrOutside
	type F = scFix
	type S = scShared
	w := func(name string, want error, fn func(ctx context.Context, db *DB, b F) error) scWrite {
		return scWrite{name: name, want: want, call: func(ctx context.Context, db *DB, _, b F, _ S) error { return fn(ctx, db, b) }}
	}
	return []scWrite{
		w("RevokeRegisterKey", nf, func(ctx context.Context, db *DB, b F) error { return db.RevokeRegisterKey(ctx, b.KeyID, ivT0) }),
		w("ConsumeRegisterKey", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.ConsumeRegisterKey(ctx, b.KeyID, ivT0)
			return err
		}),
		w("CreateRegisterKey", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateRegisterKey(ctx, store.RegisterKey{ID: "zzzzzzzzzzz", Name: "x", PublicKey: scRandKey(),
				Target: store.AgentKindAgent, Approval: store.ApprovalAuto, ScopeID: "b"})
			return err
		}),
		{name: "CreateRegisterKey/scanner", want: out, call: func(ctx context.Context, db *DB, _, _ F, _ S) error {
			_, err := db.CreateRegisterKey(ctx, store.RegisterKey{ID: "yyyyyyyyyyy", Name: "x", PublicKey: scRandKey(),
				Target: store.AgentKindScanner, Approval: store.ApprovalAuto})
			return err
		}},
		w("CreateAgent", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateAgent(ctx, store.Agent{Kind: store.AgentKindAgent, IdentityKey: scRandKey(),
				RegisterKeyID: b.KeyID, State: store.AgentApproved})
			return err
		}),
		w("ApproveAgent", nf, func(ctx context.Context, db *DB, b F) error { return db.ApproveAgent(ctx, b.AgentID, ivT0) }),
		w("RevokeAgent", nf, func(ctx context.Context, db *DB, b F) error { return db.RevokeAgent(ctx, b.AgentID, ivT0) }),
		w("UpdateAgentPoll", nf, func(ctx context.Context, db *DB, b F) error {
			return db.UpdateAgentPoll(ctx, b.AgentID, store.AgentPollStatus{ConnectMode: store.ConnectModeConnect,
				TLSMode: store.TLSVerifyPinned, UpdateState: store.UpdateUpToDate})
		}),
		w("TouchAgent", nf, func(ctx context.Context, db *DB, b F) error { return db.TouchAgent(ctx, b.AgentID, ivT0) }),
		w("SetAgentDescription", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetAgentDescription(ctx, b.AgentID, "x")
		}),
		w("SetAgentAsset", nf, func(ctx context.Context, db *DB, b F) error { return db.SetAgentAsset(ctx, b.AgentID, "") }),
		w("AdvanceAgentCounter", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.AdvanceAgentCounter(ctx, b.AgentID, 99)
			return err
		}),
		w("SetAgentIntegrity", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetAgentIntegrity(ctx, b.AgentID, store.IntegrityOn)
		}),
		w("SetAgentDetectDirs", nf, func(ctx context.Context, db *DB, b F) error { return db.SetAgentDetectDirs(ctx, b.AgentID, nil) }),
		w("CreateListenTarget", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateListenTarget(ctx, store.ListenTarget{Address: "new.example:1", ScopeID: "b"})
			return err
		}),
		w("UpdateListenTarget", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.UpdateListenTarget(ctx, store.ListenTarget{ID: b.ListenID, Address: "x.example:1"})
			return err
		}),
		w("DeleteListenTarget", nf, func(ctx context.Context, db *DB, b F) error { return db.DeleteListenTarget(ctx, b.ListenID) }),
		w("BindListenTargetAgent", nf, func(ctx context.Context, db *DB, b F) error {
			return db.BindListenTargetAgent(ctx, b.ListenID, b.AgentID)
		}),
		w("AcquireListenLeases", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.AcquireListenLeases(ctx, "o", time.Minute, ivT0, 0)
			return err
		}),
		w("RenewListenLease", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.RenewListenLease(ctx, b.ListenID, "o", time.Minute, ivT0)
			return err
		}),
		w("ReleaseListenLease", out, func(ctx context.Context, db *DB, b F) error { return db.ReleaseListenLease(ctx, b.ListenID, "o") }),
		w("RecordListenState", out, func(ctx context.Context, db *DB, b F) error {
			return db.RecordListenState(ctx, b.ListenID, "o", store.ListenConnected, "", ivT0)
		}),
		w("CreateCredential", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateCredential(ctx, store.Credential{Name: "x", Kind: store.CredentialSSHPassword, Secret: []byte("s"), ScopeID: "b"})
			return err
		}),
		w("UpdateCredentialSecret", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.UpdateCredentialSecret(ctx, store.Credential{ID: b.CredID, Secret: []byte("s")})
			return err
		}),
		w("DeleteCredential", nf, func(ctx context.Context, db *DB, b F) error { return db.DeleteCredential(ctx, b.KubeCredID) }),
		w("CreateScanTarget", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "x", Address: "x", Port: 22, CredentialID: b.CredID, ScopeID: "b"})
			return err
		}),
		{name: "CreateScanTarget/credential", want: out, call: func(ctx context.Context, db *DB, _, b F, _ S) error {
			_, err := db.CreateScanTarget(ctx, store.ScanTarget{Name: "x", Address: "x", Port: 22, CredentialID: b.CredID})
			return err
		}},
		{name: "UpdateScanTarget/credential", want: out, call: func(ctx context.Context, db *DB, a, b F, _ S) error {
			t, err := db.GetScanTarget(ctx, a.TargetID)
			if err != nil {
				return err
			}
			t.CredentialID = b.CredID
			return db.UpdateScanTarget(ctx, t)
		}},
		w("UpdateScanTarget", nf, func(ctx context.Context, db *DB, b F) error {
			return db.UpdateScanTarget(ctx, store.ScanTarget{ID: b.TargetID, Name: "x", Address: "x", Port: 22, CredentialID: b.CredID})
		}),
		w("DeleteScanTarget", nf, func(ctx context.Context, db *DB, b F) error { return db.DeleteScanTarget(ctx, b.TargetID) }),
		w("SetScanTargetHostKey", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetScanTargetHostKey(ctx, b.TargetID, []byte("k"))
		}),
		w("ClearScanTargetHostKey", nf, func(ctx context.Context, db *DB, b F) error { return db.ClearScanTargetHostKey(ctx, b.TargetID) }),
		w("SetScanTargetAsset", nf, func(ctx context.Context, db *DB, b F) error { return db.SetScanTargetAsset(ctx, b.TargetID, "") }),
		w("RecordScanRun", nf, func(ctx context.Context, db *DB, b F) error {
			return db.RecordScanRun(ctx, b.TargetID, store.ScanRun{At: ivT0, Result: store.ScanOK})
		}),
		w("SetScanTargetIntegrity", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetScanTargetIntegrity(ctx, b.TargetID, store.IntegrityOn)
		}),
		w("SetScanTargetDetectDirs", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetScanTargetDetectDirs(ctx, b.TargetID, nil)
		}),
		w("ListDueScanTargets", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.ListDueScanTargets(ctx, "", ivT0, 0)
			return err
		}),
		w("CreateCluster", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "x", Connection: store.K8sInCluster, ScopeID: "b"})
			return err
		}),
		{name: "CreateCluster/credential", want: out, call: func(ctx context.Context, db *DB, _, b F, _ S) error {
			_, err := db.CreateCluster(ctx, store.K8sClusterConfig{Name: "x", Connection: store.K8sKubeconfig, CredentialID: b.KubeCredID})
			return err
		}},
		w("UpdateCluster", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.UpdateCluster(ctx, b.ClusterID, store.K8sClusterConfig{Name: "x", Connection: store.K8sInCluster})
			return err
		}),
		w("DeleteCluster", nf, func(ctx context.Context, db *DB, b F) error { return db.DeleteCluster(ctx, b.ClusterID) }),
		w("RecordClusterSync", nf, func(ctx context.Context, db *DB, b F) error {
			return db.RecordClusterSync(ctx, b.ClusterID, store.K8sSyncOK, "", ivT0)
		}),
		w("ReplaceClusterInventory", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.ReplaceClusterInventory(ctx, b.ClusterID, store.K8sInventory{At: ivT0})
			return err
		}),
		w("SetPodContainerCoverage", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetPodContainerCoverage(ctx, b.ClusterID, b.Namespace, b.Pod, "c", store.CoverageFull, "")
		}),
		w("UpsertWorkloadAsset", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.UpsertWorkloadAsset(ctx, store.WorkloadIdentity{ClusterID: b.ClusterID, Namespace: "n", Kind: "Pod", Name: "p"},
				store.AssetInit{})
			return err
		}),
		w("UpsertHostAsset", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.UpsertHostAsset(ctx, store.HostIdentity{AgentID: b.AgentID}, store.AssetInit{Name: "x"})
			return err
		}),
		w("UpdateAssetFacts", nf, func(ctx context.Context, db *DB, b F) error {
			return db.UpdateAssetFacts(ctx, b.AssetID, store.AssetFacts{Name: "x"})
		}),
		w("SetSectionStates", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetSectionStates(ctx, b.AssetID, []store.SectionState{{Section: "packages", Coverage: store.CoverageFull}})
		}),
		w("MarkCollectRequested", nf, func(ctx context.Context, db *DB, b F) error { return db.MarkCollectRequested(ctx, b.AssetID, ivT0) }),
		w("ReplaceAssetComponents", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.ReplaceAssetComponents(ctx, store.ComponentScope{AssetID: b.AssetID, Source: store.SourcePackages}, nil,
				store.ReplaceOptions{})
			return err
		}),
		w("ReplaceContainers", nf, func(ctx context.Context, db *DB, b F) error {
			return db.ReplaceContainers(ctx, b.AssetID, nil, store.ReplaceOptions{})
		}),
		w("SetContainerCoverage", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SetContainerCoverage(ctx, b.AssetID, "ct-"+b.Mark, store.CoverageFull, "")
		}),
		w("UpsertImages", nf, func(ctx context.Context, db *DB, b F) error {
			return db.UpsertImages(ctx, store.ImageSource{Kind: store.ImageSourceAsset, ID: b.AssetID}, nil, store.ReplaceOptions{})
		}),
		w("ReplaceProcesses", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.ReplaceProcesses(ctx, store.ProcessScope{AssetID: b.AssetID}, store.ProcessSnapshot{})
			return err
		}),
		w("ApplyFindings", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.ApplyFindings(ctx, b.AssetID, nil, store.FindingStamp{})
			return err
		}),
		w("DirtyFindingAssets", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.DirtyFindingAssets(ctx, 10)
			return err
		}),
		w("StoreReport", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.StoreReport(ctx, store.RawReport{AssetID: b.AssetID})
			return err
		}),
		w("SetReportAsset", out, func(ctx context.Context, db *DB, b F) error { return db.SetReportAsset(ctx, b.ReportID, b.AssetID) }),
		w("DeleteReportsBefore", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.DeleteReportsBefore(ctx, ivT0)
			return err
		}),
		w("DeleteProcessEventsBefore", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.DeleteProcessEventsBefore(ctx, ivT0)
			return err
		}),
		w("PurgeGone", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.PurgeGone(ctx, ivT0)
			return err
		}),
		w("ReplaceGoBinaries", nf, func(ctx context.Context, db *DB, b F) error {
			return db.ReplaceGoBinaries(ctx, store.GoBinaryScope{AssetID: b.AssetID}, nil, store.ReplaceOptions{})
		}),
		w("SaveGoSymbolResults", nf, func(ctx context.Context, db *DB, b F) error {
			return db.SaveGoSymbolResults(ctx, b.AssetID, []store.GoSymbolResult{{SHA256: "s", Name: "n", Result: "absent"}})
		}),
		w("PutGoSymbolQuery", nf, func(ctx context.Context, db *DB, b F) error {
			return db.PutGoSymbolQuery(ctx, store.GoSymbolQuery{AssetID: b.AssetID, Query: json.RawMessage(`{}`)})
		}),
		w("DeleteGoSymbolQuery", nf, func(ctx context.Context, db *DB, b F) error { return db.DeleteGoSymbolQuery(ctx, b.AssetID, "") }),
		w("GoSymbolAssets", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.GoSymbolAssets(ctx, ivT0, 10)
			return err
		}),
		w("RecordIntegrityChunk", nf, func(ctx context.Context, db *DB, b F) error {
			return db.RecordIntegrityChunk(ctx, store.IntegrityChunk{AssetID: b.AssetID, PassKey: "p"})
		}),
		w("CreateIntegrityAllowRule", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateIntegrityAllowRule(ctx, store.IntegrityAllowRule{Scope: store.IntegrityScopeFleet, Path: "/x",
				Status: store.IntegrityMissing, Note: "n", ScopeID: "b"})
			return err
		}),
		{name: "CreateIntegrityAllowRule/asset", want: nf, call: func(ctx context.Context, db *DB, _, b F, _ S) error {
			_, err := db.CreateIntegrityAllowRule(ctx, store.IntegrityAllowRule{Scope: store.IntegrityScopeAsset, AssetID: b.AssetID,
				Path: "/x", Status: store.IntegrityMissing, Note: "n"})
			return err
		}},
		w("RevokeIntegrityAllowRule", nf, func(ctx context.Context, db *DB, b F) error {
			return db.RevokeIntegrityAllowRule(ctx, b.AllowID, "x", ivT0)
		}),
		w("CreateTriageRule", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.CreateTriageRule(ctx, store.TriageRule{VulnID: b.VulnID, ScopeKind: store.TriageScopeGroup, ScopeValue: "web",
				Justification: "code_not_present", ScopeID: "b"})
			return err
		}),
		{name: "CreateTriageRule/asset", want: nf, call: func(ctx context.Context, db *DB, _, b F, _ S) error {
			_, err := db.CreateTriageRule(ctx, store.TriageRule{VulnID: b.VulnID, ScopeKind: store.TriageScopeAsset,
				ScopeValue: b.AssetID, Justification: "code_not_present"})
			return err
		}},
		w("RevokeTriageRule", nf, func(ctx context.Context, db *DB, b F) error {
			_, err := db.RevokeTriageRule(ctx, b.TriageID, "x", ivT0)
			return err
		}),
		w("ExpireTriageRules", out, func(ctx context.Context, db *DB, b F) error {
			_, err := db.ExpireTriageRules(ctx, ivT0)
			return err
		}),
		// Notices of b are not visible: nothing is marked.
		w("MarkNoticesRead", nf, func(ctx context.Context, db *DB, b F) error {
			return scNone(db.MarkNoticesRead(ctx, []string{b.NoticeID}, "x", ivT0))
		}),
		w("MarkNoticesUnread", nf, func(ctx context.Context, db *DB, b F) error {
			return scNone(db.MarkNoticesUnread(ctx, []string{b.NoticeID}))
		}),
	}
}

// scNone turns a call that changed nothing into ErrNotFound.
func scNone(n int, err error) error {
	if err == nil && n == 0 {
		return store.ErrNotFound
	}
	return err
}

// scUnscoped are the methods that read or write no scoped data, with why.
var scUnscoped = map[string]string{
	"WithTx": "transaction wrapper; the methods called inside check the scope",
	// Global configuration and infrastructure.
	"GetSetting": "global settings", "PutSetting": "global settings",
	"GetFeedInstance": "feed configuration", "CreateFeedInstance": "feed configuration",
	"ListFeedServers": "feed configuration", "GetFeedServer": "feed configuration",
	"GetActiveFeedServer": "feed configuration", "CreateFeedServer": "feed configuration",
	"UpdateFeedServer": "feed configuration", "DeleteFeedServer": "feed configuration",
	"ActivateFeedServer": "feed configuration", "TrustFeedServerKey": "feed configuration",
	"RecordFeedServerKeyChange": "feed configuration", "AcceptFeedServerKey": "feed configuration",
	"RecordFeedServerOK": "feed configuration", "RecordFeedServerError": "feed configuration",
	"RecordFeedData": "feed configuration",
	"GetPKIObject":   "server PKI", "ListPKIObjects": "server PKI", "PutPKIObject": "server PKI",
	"DeletePKIObject": "server PKI", "GetTLSSetting": "server PKI", "PutTLSSetting": "server PKI",
	"TrustBundleVersion": "server PKI", "BumpTrustBundleVersion": "server PKI",
	"CreateRelease": "agent releases", "GetRelease": "agent releases", "ListReleases": "agent releases",
	"DeleteRelease": "agent releases", "PutReleaseFile": "agent releases", "ListReleaseFiles": "agent releases",
	"OpenReleaseFile": "agent releases", "GetUpdateSettings": "agent releases", "PutUpdateSettings": "agent releases",
	"CreateSession": "console sessions", "GetSession": "console sessions", "DeleteSession": "console sessions",
	"DeleteExpiredSessions": "console sessions",
	"CreateEnrollSession":   "enrollment handshake state", "TakeEnrollSession": "enrollment handshake state",
	"DeleteExpiredEnrollSessions": "enrollment handshake state",
	"AcquireScanLease":            "scan job leases, keyed by job", "RenewScanLease": "scan job leases, keyed by job",
	"ReleaseScanLease": "scan job leases, keyed by job", "GetScanLease": "scan job leases, keyed by job",
	"DeleteExpiredScanLeases": "scan job leases, keyed by job",
	"CreateDetectDir":         "detect directory definitions; assigning one checks the owner's scope",
	"ListDetectDirs":          "detect directory definitions", "GetDetectDir": "detect directory definitions",
	"UpdateDetectDir": "detect directory definitions", "DeleteDetectDir": "detect directory definitions",
	"LatestDetectorTable": "detector table, global", "GetDetectorTable": "detector table, global",
	"AddDetectorTable": "detector table, global", "ListDetectorTables": "detector table, global",
	"EnqueueDirective":      "internal agent queue; callers check the agent or asset first",
	"ListPendingDirectives": "internal agent queue", "MarkDirectivesDelivered": "internal agent queue",
	"AckDirectives": "internal agent queue", "DeleteExpiredDirectives": "internal agent queue",
	"PutAgentEnrollment": "enrollment request of an agent, read by enrollment and ingest only",
	"GetAgentEnrollment": "enrollment request of an agent, read by enrollment and ingest only",
	"InsertAgentCert":    "agent certificate revocation data", "ListAgentCerts": "agent certificate revocation data",
	"IsAgentCertRevoked": "agent certificate revocation data", "RevokeAgentCerts": "agent certificate revocation data",
	"ListRevokedAgentCerts": "agent certificate revocation data",
	// Advisory data and content addressed by identity or digest.
	"PendingMatches": "component matching over all live components (matcher job)",
	"SaveMatches":    "advisory data", "ResetMatches": "advisory data", "GetComponentMatch": "advisory data",
	"ListComponentVulns": "advisory data", "GetVulnMeta": "advisory data",
	"LookupComponentIDs": "components by identity, no scoped rows", "ComponentsByFileHash": "content by hash",
	"RecordFileHashes": "content by hash", "PutImageContent": "image content by digest",
	"KnownImageContent": "image content by digest", "ImageContentCoverage": "image content by digest",
}

func scHas(v any, markers []string) (string, bool) {
	s := fmt.Sprintf("%+v", v)
	for _, m := range markers {
		if strings.Contains(s, m) {
			return m, true
		}
	}
	return "", false
}

// TestScopeIsolation reads and writes in scope a and checks that nothing of
// scope b is returned or changed, and that every method of store.Store is
// covered here or listed as unscoped.
func TestScopeIsolation(t *testing.T) {
	db, sh, fa, fb := scSetup(t)
	ctxA := scope.With(ivCtx(t), scope.Of("a"))
	reads, writes := scReads(), scWrites()

	t.Run("coverage", func(t *testing.T) {
		covered := map[string]bool{}
		for _, r := range reads {
			covered[r.name] = true
		}
		for _, w := range writes {
			covered[strings.SplitN(w.name, "/", 2)[0]] = true
		}
		ty := reflect.TypeOf((*store.Store)(nil)).Elem()
		var missing []string
		for i := 0; i < ty.NumMethod(); i++ {
			name := ty.Method(i).Name
			_, unscoped := scUnscoped[name]
			switch {
			case covered[name] && unscoped:
				t.Errorf("%s is tested as scoped and listed as unscoped", name)
			case !covered[name] && !unscoped:
				missing = append(missing, name)
			}
			delete(covered, name)
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("store methods neither scope-tested nor listed in scUnscoped: %v", missing)
		}
		for name := range covered {
			t.Errorf("tested method %s is not in store.Store", name)
		}
	})

	for _, r := range reads {
		t.Run("read/"+r.name, func(t *testing.T) {
			own, err := r.call(ctxA, db, fa, sh)
			if err != nil {
				t.Fatalf("own: %v", err)
			}
			if m, ok := scHas(own, fb.markers()); ok {
				t.Errorf("own call returns %q of scope b: %+v", m, own)
			}
			if r.wantOwn {
				if _, ok := scHas(own, fa.markers()); !ok {
					t.Errorf("own call returns nothing of scope a: %+v", own)
				}
			}
			if r.check != nil {
				r.check(t, own)
			}
			other, err := r.call(ctxA, db, fb, sh)
			switch {
			case r.byID && !errors.Is(err, store.ErrNotFound):
				t.Errorf("record of scope b: %v, want ErrNotFound (%+v)", err, other)
			case err != nil && !errors.Is(err, store.ErrNotFound):
				t.Errorf("records of scope b: %v", err)
			case err == nil:
				if m, ok := scHas(other, fb.markers()); ok {
					t.Errorf("returns %q of scope b: %+v", m, other)
				}
			}
			if _, err := r.call(ivCtxNoScope(t), db, fa, sh); !errors.Is(err, scope.ErrNone) {
				t.Errorf("without a scope: %v, want scope.ErrNone", err)
			}
		})
	}

	for _, w := range writes {
		t.Run("write/"+w.name, func(t *testing.T) {
			if err := w.call(ctxA, db, fa, fb, sh); !errors.Is(err, w.want) {
				t.Errorf("in scope a against scope b: %v, want %v", err, w.want)
			}
			if err := w.call(ivCtxNoScope(t), db, fa, fb, sh); !errors.Is(err, scope.ErrNone) {
				t.Errorf("without a scope: %v, want scope.ErrNone", err)
			}
		})
	}

	// Nothing of b changed: its records read back as created.
	all := ivCtx(t)
	if a, err := db.GetAgent(all, fb.AgentID); err != nil || a.State != store.AgentApproved || a.Description != "" {
		t.Errorf("agent of b changed: %+v %v", a, err)
	}
	if k, err := db.GetRegisterKey(all, fb.KeyID); err != nil || k.RevokedAt != nil || k.UsedCount != 0 {
		t.Errorf("register key of b changed: %+v %v", k, err)
	}
	if _, err := db.GetCluster(all, fb.ClusterID); err != nil {
		t.Errorf("cluster of b: %v", err)
	}
	if r, err := db.GetTriageRule(all, fb.TriageID); err != nil || r.RevokedAt != nil {
		t.Errorf("triage rule of b changed: %+v %v", r, err)
	}
}

// ivCtxNoScope is a test context without a data scope.
func ivCtxNoScope(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// TestScopeAllAndEmpty checks the two fixed scopes: All sees both scopes,
// the empty scope nothing.
func TestScopeAllAndEmpty(t *testing.T) {
	db, _, fa, fb := scSetup(t)
	assets, _, err := db.ListAssets(ivCtx(t), store.AssetFilter{}, scPage())
	ivMust(t, err)
	if len(assets) != 6 {
		t.Fatalf("All sees %d assets, want 6", len(assets))
	}
	none := scope.With(ivCtx(t), scope.Of())
	if assets, _, err := db.ListAssets(none, store.AssetFilter{}, scPage()); err != nil || len(assets) != 0 {
		t.Fatalf("empty scope: %d assets, %v", len(assets), err)
	}
	if _, err := db.GetAsset(none, fa.AssetID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty scope get: %v", err)
	}
	both := scope.With(ivCtx(t), scope.Of("a", "b"))
	if assets, _, err := db.ListAssets(both, store.AssetFilter{ScopeID: "b"}, scPage()); err != nil || len(assets) != 3 {
		t.Fatalf("filter by scope b: %d assets, %v", len(assets), err)
	}
	// A report without an asset is visible to All only.
	id, err := db.StoreReport(ivCtx(t), store.RawReport{Body: []byte("x")})
	ivMust(t, err)
	if _, err := db.GetReport(both, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("report without asset in a scope: %v", err)
	}
	if _, err := db.GetReport(ivCtx(t), id); err != nil {
		t.Fatal(err)
	}
	// Names are unique per scope: b reuses the names of a.
	if fa.CredID == fb.CredID {
		t.Fatal("credentials shared")
	}
}

// TestScopeRules checks that triage and integrity allow rules of scope b
// do not affect the findings of scope a.
func TestScopeRules(t *testing.T) {
	db, sh, fa, fb := scSetup(t)
	all := ivCtx(t)
	ctxB := scope.With(ivCtx(t), scope.Of("b"))

	// A purl rule and a group rule of b on the vulnerability both scopes
	// have, and a fleet allow rule of b on the file both scopes changed.
	_, err := db.CreateTriageRule(ctxB, store.TriageRule{VulnID: sh.SharedVuln, ScopeKind: store.TriageScopePURL,
		ScopeValue: "pkg:deb/ubuntu/openssl@3.0.13", PURLLike: "pkg:deb/ubuntu/openssl@3.0.13", Justification: "code_not_present"})
	ivMust(t, err)
	_, err = db.CreateTriageRule(ctxB, store.TriageRule{VulnID: sh.SharedVuln, ScopeKind: store.TriageScopeGroup,
		ScopeValue: "web", Justification: "code_not_present"})
	ivMust(t, err)
	sha := strings.Repeat("c", 64)
	for _, f := range []scFix{fa, fb} {
		ivMust(t, db.RecordIntegrityChunk(all, store.IntegrityChunk{AssetID: f.AssetID, PassKey: "p2-" + f.Mark, At: ivT0,
			Coverage: "full", Findings: []store.IntegrityObservation{itModified("/etc/shared.conf", sha)}}))
	}
	_, err = db.CreateIntegrityAllowRule(ctxB, store.IntegrityAllowRule{Scope: store.IntegrityScopeFleet, Path: "/etc/shared.conf",
		Status: store.IntegrityModified, ActualSHA256: sha, Note: "b only"})
	ivMust(t, err)

	open, err := db.OpenFindings(all, store.OpenFindingFilter{VulnID: sh.SharedVuln, At: ivT0})
	ivMust(t, err)
	if len(open) != 2 {
		t.Fatalf("open findings %d", len(open))
	}
	for _, o := range open {
		deferred := o.Triage != nil && o.Triage.Active
		if want := o.AssetID == fb.AssetID; deferred != want {
			t.Errorf("finding of %s deferred %v, want %v", o.AssetName, deferred, want)
		}
		if o.Triage != nil && o.Triage.Rule.ScopeID != "b" {
			t.Errorf("rule scope %q", o.Triage.Rule.ScopeID)
		}
	}
	vulns, err := db.VulnCves(scope.With(ivCtx(t), scope.Of("a")), store.VulnViewOptions{At: ivT0})
	ivMust(t, err)
	shown := false
	for _, v := range vulns {
		shown = shown || v.Meta.ID == sh.SharedVuln
	}
	if !shown {
		t.Error("a rule of b hides the vulnerability from a")
	}
	// The newest rule decides a finding: together the two rules of b
	// decide the one finding of b's asset.
	rules, err := db.ListTriageRules(ctxB, ivT0, false)
	ivMust(t, err)
	decided := 0
	for _, r := range rules {
		if r.ScopeKind != store.TriageScopeAsset {
			decided += r.Findings
		}
	}
	if decided != 1 {
		t.Errorf("the rules of b decide %d findings, want 1", decided)
	}

	ints, _, err := db.ListIntegrityFindings(all, store.IntegrityFilter{Path: "/etc/shared.conf", IncludeAllowed: true}, scPage())
	ivMust(t, err)
	if len(ints) != 2 {
		t.Fatalf("integrity findings %d", len(ints))
	}
	for _, f := range ints {
		if allowed, want := f.AllowedBy != "", f.AssetID == fb.AssetID; allowed != want {
			t.Errorf("integrity finding of %s allowed %v, want %v", f.AssetName, allowed, want)
		}
	}
	allows, _, err := db.ListIntegrityAllowRules(ctxB, false, scPage())
	ivMust(t, err)
	for _, r := range allows {
		if r.Scope == store.IntegrityScopeFleet && r.Hidden != 1 {
			t.Errorf("fleet rule of b hides %d findings, want 1", r.Hidden)
		}
	}
}
