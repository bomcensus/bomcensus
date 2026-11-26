// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package inventoryapi

import (
	"strings"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// Query parameter limits from the API description.
const (
	defaultLimit = 200
	maxLimit     = 1000
	maxQLen      = 256
)

// page validates limit and offset.
func page(limit, offset *int) (store.Page, error) {
	p := store.Page{Limit: defaultLimit}
	if limit != nil {
		if *limit < 1 || *limit > maxLimit {
			return p, apierr.Invalid("limit must be between 1 and %d", maxLimit)
		}
		p.Limit = *limit
	}
	if offset != nil {
		if *offset < 0 {
			return p, apierr.Invalid("offset must not be negative")
		}
		p.Offset = *offset
	}
	return p, nil
}

// query validates the free-text parameter.
func query(q *string) (string, error) {
	if q == nil {
		return "", nil
	}
	if len(*q) > maxQLen {
		return "", apierr.Invalid("q must be at most %d bytes", maxQLen)
	}
	return strings.TrimSpace(*q), nil
}

// sortKey maps an API sort value (a field name, optionally prefixed with
// "-") to the store's key through keys. Nil or empty selects the store
// default.
func sortKey[S ~string](v *S, keys map[string]string) (string, error) {
	if v == nil || *v == "" {
		return "", nil
	}
	s := string(*v)
	field, desc := strings.CutPrefix(s, "-")
	k, ok := keys[field]
	if !ok {
		return "", apierr.Invalid("unknown sort %q", s)
	}
	if desc {
		return "-" + k, nil
	}
	return k, nil
}

// enum validates an optional enum parameter.
func enum[E interface {
	~string
	Valid() bool
}](name string, v *E) (string, error) {
	if v == nil || *v == "" {
		return "", nil
	}
	if !(*v).Valid() {
		return "", apierr.Invalid("unknown %s %q", name, string(*v))
	}
	return string(*v), nil
}

func str(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ptr[T any](v T) *T { return &v }

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func assetOS(a store.Asset) *gen.AssetOs {
	if a.OS == (store.OSInfo{}) && a.Kernel == "" && a.Arch == "" {
		return nil
	}
	return &gen.AssetOs{Family: a.OS.Family, Name: a.OS.Name, Version: a.OS.Version, Kernel: str(a.Kernel), Arch: a.Arch}
}

func privilege(p store.Privilege) *gen.PrivilegeLevel {
	if p == "" {
		return nil
	}
	return ptr(gen.PrivilegeLevel(p))
}

func assetSummary(a store.Asset, containers int) gen.AssetSummary {
	return gen.AssetSummary{
		Id:                 a.ID,
		ScopeId:            a.ScopeID,
		Name:               a.Name,
		Kind:               gen.AssetKind(a.Kind),
		Group:              a.Group,
		Tags:               strs(a.Tags),
		Os:                 assetOS(a),
		Address:            str(a.Address),
		Method:             gen.CollectMethod(a.Method),
		Coverage:           gen.Coverage(a.Coverage),
		CoverageReason:     str(a.CoverageReason),
		Privilege:          privilege(a.Privilege),
		AgentId:            str(a.AgentID),
		ScanTargetId:       str(a.ScanTargetID),
		ClusterId:          str(a.ClusterID),
		ClusterName:        str(a.ClusterName),
		Namespace:          str(a.Namespace),
		WorkloadKind:       str(a.WorkloadKind),
		ContainerCount:     containers,
		CollectRequestedAt: a.CollectRequestedAt,
		FirstSeen:          a.FirstSeen,
		LastSeen:           a.LastSeen,
	}
}

// rowSummary is assetSummary of a list row, with its container images.
func rowSummary(r store.AssetRow) gen.AssetSummary {
	s := assetSummary(r.Asset, r.Containers)
	s.Images = ptr(strs(r.Images))
	return s
}

func assetContainer(c store.Container) gen.AssetContainer {
	var w *gen.ContainerWorkload
	if c.Workload != nil {
		w = &gen.ContainerWorkload{AssetId: c.Workload.AssetID, Name: c.Workload.Name, Pod: c.Workload.Pod}
	}
	return gen.AssetContainer{
		Workload:       w,
		Name:           c.Name,
		ImageRef:       c.ImageRef,
		ImageDigest:    str(c.ImageDigest),
		Runtime:        gen.ContainerRuntime(c.Runtime),
		Instances:      c.Instances,
		Coverage:       gen.Coverage(c.Coverage),
		CoverageReason: str(c.CoverageReason),
		StartedAt:      c.StartedAt,
	}
}

func softwareComponent(c store.Component) gen.SoftwareComponent {
	return gen.SoftwareComponent{
		Id:            c.ID,
		Type:          gen.ComponentType(c.Type),
		Name:          c.Name,
		Version:       c.Version,
		Build:         str(c.Build),
		Purl:          c.PURL,
		Cpe:           str(c.CPE),
		SourceName:    str(c.SourceName),
		SourceVersion: str(c.SourceVersion),
		Distro:        str(c.Distro),
		Arch:          str(c.Arch),
		Vendor:        str(c.Vendor),
		Origin:        gen.ComponentOrigin(c.Origin),
	}
}

func componentSummary(r store.ComponentRow) gen.ComponentSummary {
	c := softwareComponent(r.Component)
	return gen.ComponentSummary{
		Id: c.Id, Type: c.Type, Name: c.Name, Version: c.Version, Build: c.Build, Purl: c.Purl, Cpe: c.Cpe,
		SourceName: c.SourceName, SourceVersion: c.SourceVersion, Distro: c.Distro, Arch: c.Arch,
		Vendor: c.Vendor, Origin: c.Origin, AssetCount: r.Assets, RunningAssetCount: r.RunningAssets,
	}
}

func layer(l string) *gen.ComponentLayer {
	if l == "" {
		return nil
	}
	return ptr(gen.ComponentLayer(l))
}

func processInfo(r store.ProcessRow) gen.ProcessInfo {
	libs := []gen.MappedLib{}
	for _, l := range r.Libs {
		s := gen.MappedLibState(l.State)
		if !s.Valid() {
			continue
		}
		libs = append(libs, gen.MappedLib{Path: l.Path, State: s, Sha256: str(l.SHA256)})
	}
	listen := make([]gen.ListenPort, 0, len(r.Listen))
	for _, l := range r.Listen {
		listen = append(listen, gen.ListenPort{Proto: gen.ListenProto(l.Proto), Address: l.Address, Port: l.Port})
	}
	src := gen.ExeSource(r.ExeSource)
	if src == "" {
		src = gen.Proc
	}
	state := gen.ExeState(r.ExeState)
	if state == "" {
		state = gen.ExeStateNormal
	}
	return gen.ProcessInfo{
		Id:          r.ID,
		AssetId:     r.AssetID,
		AssetName:   r.Asset.Name,
		Pid:         r.PID,
		Ppid:        ptr(r.PPID),
		User:        r.User,
		Uid:         ptr(r.UID),
		ExePath:     r.Exe,
		ExeSource:   src,
		Sha256:      str(r.SHA256),
		Cmdline:     r.Cmdline,
		StartedAt:   r.StartedAt,
		ExeState:    state,
		DeletedLibs: libs,
		Listen:      listen,
		Container:   str(r.Container),
		ComponentId: str(r.ComponentID),
	}
}

func podPhase(p string) gen.K8sPodPhase {
	if v := gen.K8sPodPhase(p); v.Valid() {
		return v
	}
	return gen.K8sPodPhaseUnknown
}

func k8sPod(p store.K8sPod) gen.K8sPod {
	cs := make([]gen.K8sPodContainer, 0, len(p.Containers))
	for _, c := range p.Containers {
		cs = append(cs, gen.K8sPodContainer{
			Name:           c.Name,
			ImageRef:       c.ImageRef,
			ImageDigest:    str(c.ImageDigest),
			Coverage:       gen.Coverage(c.Coverage),
			CoverageReason: str(c.CoverageReason),
		})
	}
	return gen.K8sPod{
		Id:         p.ID,
		WorkloadId: p.WorkloadID,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Node:       p.Node,
		Phase:      podPhase(p.Phase),
		StartedAt:  p.StartedAt,
		Containers: cs,
	}
}

func k8sPods(ps []store.K8sPod, total int) gen.K8sPodList {
	out := gen.K8sPodList{Items: make([]gen.K8sPod, 0, len(ps)), Total: total}
	for _, p := range ps {
		out.Items = append(out.Items, k8sPod(p))
	}
	return out
}

// podFilter maps the common pod list parameters.
func podFilter[S ~string](q *string, phase *gen.K8sPodPhase, sort *S) (store.PodFilter, error) {
	var f store.PodFilter
	var err error
	if f.Q, err = query(q); err != nil {
		return f, err
	}
	if f.Phase, err = enum("phase", phase); err != nil {
		return f, err
	}
	f.Sort, err = sortKey(sort, map[string]string{
		"name": "name", "node": "node", "phase": "phase", "startedAt": "started_at",
	})
	return f, err
}

func k8sFilterOut(f store.K8sFilter) gen.K8sFilter {
	return gen.K8sFilter{
		NsInclude:         strs(f.NSInclude),
		NsExclude:         strs(f.NSExclude),
		LabelInclude:      strs(f.LabelInclude),
		LabelExclude:      strs(f.LabelExclude),
		AnnotationInclude: strs(f.AnnotationInclude),
		AnnotationExclude: strs(f.AnnotationExclude),
	}
}

func k8sFilterIn(f gen.K8sFilter) store.K8sFilter {
	return store.K8sFilter{
		NSInclude:         strs(f.NsInclude),
		NSExclude:         strs(f.NsExclude),
		LabelInclude:      strs(f.LabelInclude),
		LabelExclude:      strs(f.LabelExclude),
		AnnotationInclude: strs(f.AnnotationInclude),
		AnnotationExclude: strs(f.AnnotationExclude),
	}
}

// k8sCluster maps a cluster.
func k8sCluster(c store.K8sCluster) gen.K8sCluster {
	status := gen.K8sSyncStatus(c.SyncStatus)
	if !status.Valid() {
		status = gen.K8sSyncStatusNever
	}
	var msg *string
	if status == gen.K8sSyncStatusFailed {
		msg = str(c.SyncMessage)
	}
	return gen.K8sCluster{
		Id:            c.ID,
		Name:          c.Name,
		Version:       str(c.Version),
		ScannerId:     str(c.ScannerID),
		Connection:    gen.K8sConnection(c.Connection),
		CredentialId:  str(c.CredentialID),
		ExecEnabled:   c.ExecEnabled,
		Filter:        k8sFilterOut(c.Filter),
		SyncStatus:    status,
		SyncMessage:   msg,
		LastSync:      c.LastSync,
		WorkloadCount: c.Workloads,
		ExcludedCount: c.Excluded,
		CreatedAt:     c.CreatedAt,
		ScopeId:       c.ScopeID,
	}
}
