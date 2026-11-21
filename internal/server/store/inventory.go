// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"time"
)

// Inventory covers assets, containers, components, processes, images and
// Kubernetes objects: what ingest writes and what the console reads. Services
// should depend on the narrowest of the embedded interfaces they need.
//
// List methods take a filter whose Sort field names one of the documented
// keys, optionally prefixed with "-" for descending order; an unknown key
// fails with ErrInvalid. They return one page of items and the total number
// of matches.
type Inventory interface {
	AssetIngest
	ComponentIngest
	ContainerIngest
	ProcessIngest
	K8sIngest
	Reports
	K8sClusters
	InventoryQuery
	AssetRequests
	InventoryRetention
}

// AssetIngest identifies assets and records what a report says about them.
type AssetIngest interface {
	// UpsertHostAsset finds the host asset for id or creates it with init.
	// Identity order: agent id, then the asset linked to the scan target,
	// then machine id, then scanner and address. An agent id that is new
	// takes over an existing asset with the same machine id and no agent; if
	// that asset already has another agent, a new asset is created and
	// DuplicateMachineID is set. A machine id or agent id that was not stored
	// yet is added to the found asset. With ScanTargetID the found or created
	// asset is linked to the scan target (ErrNotFound when it does not
	// exist).
	UpsertHostAsset(ctx context.Context, id HostIdentity, init AssetInit) (AssetRef, error)
	// UpsertWorkloadAsset finds or creates the asset of a workload. A gone
	// asset is brought back.
	UpsertWorkloadAsset(ctx context.Context, id WorkloadIdentity, init AssetInit) (AssetRef, error)
	// UpdateAssetFacts applies f to the asset (see AssetFacts for which
	// fields are left alone).
	UpdateAssetFacts(ctx context.Context, assetID string, f AssetFacts) error
	// SetSectionStates inserts or replaces the given section states. The
	// baseline coverage of a state is raised to the new coverage when that
	// is at least as complete as the stored baseline and kept otherwise
	// (SectionState.Baseline).
	SetSectionStates(ctx context.Context, assetID string, states []SectionState) error
}

// ComponentIngest records software found on assets and in images.
type ComponentIngest interface {
	// ReplaceAssetComponents makes obs the current component set of scope.
	// Global components are created as needed. Items that are new start a
	// history interval at opts.At; items no longer observed get removed_at
	// opts.At unless opts.KeepMissing is set. An item that comes back after
	// removal starts a new interval. Observations of the same component are
	// merged. ReplaceResult.ComponentIDs gives the component of each
	// observation.
	ReplaceAssetComponents(ctx context.Context, scope ComponentScope, obs []ComponentObservation, opts ReplaceOptions) (ReplaceResult, error)
	// PutImageContent stores the content of an image digest. Content is
	// written once: it is skipped when the digest already has content,
	// unless the stored content is not full coverage and the new one is.
	// Written reports whether it was stored.
	PutImageContent(ctx context.Context, c ImageContent) (written bool, err error)
	// KnownImageContent returns the subset of digests whose content is known.
	KnownImageContent(ctx context.Context, digests []string) ([]string, error)
	// ImageContentCoverage returns the coverage of the known content of a
	// digest (the best one collected so far), or "" when the content is not
	// known or the digest is unknown.
	ImageContentCoverage(ctx context.Context, digest string) (Coverage, error)
	// RecordFileHashes remembers which component a file hash belongs to.
	RecordFileHashes(ctx context.Context, hashes []FileHash, at time.Time) error
	// ComponentsByFileHash maps each known hash to the component last seen
	// with it.
	ComponentsByFileHash(ctx context.Context, sha256s []string) (map[string]string, error)
	// ComponentsAtLocations maps each location to the component of the asset
	// that has its path among its locations now: a component of the asset
	// itself for an empty Container, else one of that container (its own
	// rows or the content of its image digest). Locations without a match
	// are left out. When several components match, the first by name,
	// version, layer, source and id wins.
	ComponentsAtLocations(ctx context.Context, assetID string, locs []ComponentLocation) (map[ComponentLocation]string, error)
	// LookupComponentIDs returns the id of each component by identity, or
	// "" for one that is not stored.
	LookupComponentIDs(ctx context.Context, comps []Component) ([]string, error)
}

// ComponentLocation is a file path inside an asset or one of its
// containers.
type ComponentLocation struct {
	Container string
	Path      string
}

// ContainerIngest records containers and images.
type ContainerIngest interface {
	// ReplaceContainers makes cs the current containers of the asset.
	// Containers not in cs are marked gone (instances 0) unless
	// opts.KeepMissing is set; a gone container that is observed again comes
	// back. Every digest gets an images row.
	ReplaceContainers(ctx context.Context, assetID string, cs []ContainerObservation, opts ReplaceOptions) error
	// SetContainerCoverage records how much of one container was collected.
	SetContainerCoverage(ctx context.Context, assetID, name string, coverage Coverage, reason string) error
	// UpsertImages records images seen on hosts or clusters. Repo tags are
	// merged with the stored ones.
	UpsertImages(ctx context.Context, images []ImageObservation, at time.Time) error
}

// ProcessIngest records running processes.
type ProcessIngest interface {
	// ReplaceProcesses makes snap the current process set of scope, with
	// listen ports, and appends appeared and disappeared events. A process
	// is identified by pid and start time. A process without ComponentID is
	// linked through file_hashes when its sha256 is known.
	ReplaceProcesses(ctx context.Context, scope ProcessScope, snap ProcessSnapshot) (ProcessDelta, error)
}

// K8sIngest records the result of a Kubernetes inventory sync.
type K8sIngest interface {
	// ReplaceClusterInventory makes inv the current workloads and pods of
	// the cluster. Workloads and pods not in inv are marked gone. Every
	// workload that is not excluded gets an asset (created when needed) and
	// its containers are derived from its pods: image of the most recently
	// started pod, instances = running pods. Assets of gone or excluded
	// workloads are marked gone. The cluster's version and last sync are
	// updated.
	ReplaceClusterInventory(ctx context.Context, clusterID string, inv K8sInventory) (K8sInventoryResult, error)
	// SetPodContainerCoverage records how much of one pod container was
	// collected through exec.
	SetPodContainerCoverage(ctx context.Context, clusterID, namespace, pod, container string, coverage Coverage, reason string) error
}

// Reports stores raw reports.
type Reports interface {
	StoreReport(ctx context.Context, r RawReport) (id string, err error)
	GetReport(ctx context.Context, id string) (RawReport, error)
	SetReportAsset(ctx context.Context, reportID, assetID string) error
	// DeleteReportsBefore removes reports received before t.
	DeleteReportsBefore(ctx context.Context, t time.Time) (int64, error)
}

// K8sClusters manages cluster connections.
type K8sClusters interface {
	// CreateCluster fails with ErrConflict when the name is taken.
	CreateCluster(ctx context.Context, c K8sClusterConfig) (K8sCluster, error)
	GetCluster(ctx context.Context, id string) (K8sCluster, error)
	// UpdateCluster replaces the configuration.
	UpdateCluster(ctx context.Context, id string, c K8sClusterConfig) (K8sCluster, error)
	// DeleteCluster removes the cluster with its workloads, pods and
	// workload assets.
	DeleteCluster(ctx context.Context, id string) error
	// ListClusters sorts by name (default), version, connection,
	// exec_enabled, workloads, excluded or last_sync.
	ListClusters(ctx context.Context, f ClusterFilter, p Page) ([]K8sClusterRow, int, error)
	// RecordClusterSync stores the outcome of a sync attempt made at at.
	// An outcome older than the stored one is ignored. LastSync is not
	// changed; a stored inventory (ReplaceClusterInventory) records ok.
	RecordClusterSync(ctx context.Context, id string, status K8sSyncStatus, message string, at time.Time) error
}

// AssetRequests records requests made about assets.
type AssetRequests interface {
	// MarkCollectRequested records that a collection of the asset was
	// requested at at (Asset.CollectRequestedAt). A report collected at or
	// after that time clears it.
	MarkCollectRequested(ctx context.Context, assetID string, at time.Time) error
}

// InventoryQuery is what the console reads.
type InventoryQuery interface {
	// ListAssets sorts by name (default), kind, os, group, method,
	// coverage, containers, first_seen or last_seen.
	ListAssets(ctx context.Context, f AssetFilter, p Page) ([]AssetRow, int, error)
	// ListAssetGroups lists the groups of current assets. Sorts by name
	// (default) or assets.
	ListAssetGroups(ctx context.Context, f AssetGroupFilter, p Page) ([]AssetGroupRow, int, error)
	GetAsset(ctx context.Context, id string) (AssetDetail, error)
	// ListAssetComponents returns the asset's own components and, for each
	// of its containers, the content of the container's image digest
	// (layer image). Sorts by name (default), version, type, origin,
	// method, in_use, container or first_seen.
	ListAssetComponents(ctx context.Context, assetID string, f AssetComponentFilter, p Page) ([]AssetComponentRow, int, error)
	// ListAssetInstances returns the pods of a workload asset (none for a
	// host). Sorts by name (default), node, phase or started_at.
	ListAssetInstances(ctx context.Context, assetID string, f PodFilter, p Page) ([]K8sPod, int, error)

	// ListComponents sorts by name (default), version, type, origin, purl
	// or assets.
	ListComponents(ctx context.Context, f ComponentFilter, p Page) ([]ComponentRow, int, error)
	GetComponent(ctx context.Context, id string) (ComponentRow, error)
	// ListComponentAssets returns where the component is installed now.
	// Sorts by asset (default), container, method, in_use or first_seen.
	ListComponentAssets(ctx context.Context, componentID string, f ComponentAssetFilter, p Page) ([]ComponentAssetRow, int, error)

	// ListProcesses sorts by asset (default), pid, exe, user, state or
	// started_at.
	ListProcesses(ctx context.Context, f ProcessFilter, p Page) ([]ProcessRow, int, error)
	// ListListenPorts sorts by port (default), address, proto, exe, user or
	// asset.
	ListListenPorts(ctx context.Context, f ListenPortFilter, p Page) ([]ListenPortRow, int, error)

	// ListImages aggregates containers by digest. Sorts by tag (default),
	// digest, os, arch, size, assets, containers, instances or first_seen.
	ListImages(ctx context.Context, f ImageFilter, p Page) ([]ImageRow, int, error)
	// GetImage returns the image with the containers that run it.
	GetImage(ctx context.Context, digest string) (ImageDetail, error)
	// ListImageComponents sorts by name (default), version, type or source.
	ListImageComponents(ctx context.Context, digest string, f ImageComponentFilter, p Page) ([]ImageComponentRow, int, error)

	// ListWorkloads sorts by namespace (default), kind, name, replicas or
	// pods.
	ListWorkloads(ctx context.Context, clusterID string, f WorkloadFilter, p Page) ([]K8sWorkloadRow, int, error)
	// ListWorkloadPods sorts like ListAssetInstances.
	ListWorkloadPods(ctx context.Context, workloadID string, f PodFilter, p Page) ([]K8sPod, int, error)
	// GetWorkload returns a workload, also a gone one.
	GetWorkload(ctx context.Context, id string) (K8sWorkload, error)
	// GetPod returns a pod of a cluster by namespace and name, also a gone
	// one.
	GetPod(ctx context.Context, clusterID, namespace, name string) (K8sPod, error)

	Dashboard(ctx context.Context) (InventoryCounts, error)
}

// InventoryRetention deletes old inventory data.
type InventoryRetention interface {
	// PurgeGone deletes assets, containers, workloads and pods that have been
	// gone since before t.
	PurgeGone(ctx context.Context, before time.Time) (PurgeResult, error)
	// DeleteProcessEventsBefore removes process events older than t.
	DeleteProcessEventsBefore(ctx context.Context, t time.Time) (int64, error)
}

// ReplaceOptions controls a replace operation.
type ReplaceOptions struct {
	// At is when the observation was made. Zero means now.
	At time.Time
	// KeepMissing is set when the coverage of the observation is reduced:
	// items that were not observed are kept as they are instead of being
	// marked removed or gone.
	KeepMissing bool
}

// RawReport is a received report as uploaded (zstd-compressed JSON).
type RawReport struct {
	ID string
	// SourceID is the agent or scanner that uploaded it; empty for the
	// embedded scanner.
	SourceID string
	// SenderKind is the kind of the uploader.
	SenderKind AgentKind
	// RemoteAddr is the uploader's address, if known.
	RemoteAddr  string
	SubjectKind string
	// Subject is the report's subject as JSON, if any.
	Subject    []byte
	AssetID    string
	ReceivedAt time.Time
	Body       []byte
}

// InventoryCounts are the inventory numbers of the dashboard.
type InventoryCounts struct {
	Assets int
	// Hosts and Workloads split Assets by kind.
	Hosts     int
	Workloads int
	// AssetsByCoverage counts current assets by overall coverage.
	AssetsByCoverage map[Coverage]int
	// LimitedCoverage counts current assets whose coverage is not full.
	LimitedCoverage int
	NeedsRestart    int
	Suspicious      int
	Components      int
	Images          int
	Clusters        int
}

// PurgeResult counts what PurgeGone deleted.
type PurgeResult struct {
	Assets     int64
	Containers int64
	Workloads  int64
	Pods       int64
}
