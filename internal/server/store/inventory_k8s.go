// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import "time"

// K8sConnection is how the scanner reaches the cluster API.
type K8sConnection string

const (
	K8sInCluster  K8sConnection = "in_cluster"
	K8sKubeconfig K8sConnection = "kubeconfig"
)

// K8sFilter selects the workloads that become assets. Exclude always wins.
type K8sFilter struct {
	NSInclude         []string `json:"ns_include"`
	NSExclude         []string `json:"ns_exclude"`
	LabelInclude      []string `json:"label_include"`
	LabelExclude      []string `json:"label_exclude"`
	AnnotationInclude []string `json:"annotation_include"`
	AnnotationExclude []string `json:"annotation_exclude"`
}

// K8sClusterConfig is the configuration of a cluster connection.
type K8sClusterConfig struct {
	Name       string
	Connection K8sConnection
	// CredentialID is the kubeconfig credential; empty for in-cluster.
	CredentialID string
	ScannerID    string
	ExecEnabled  bool
	Filter       K8sFilter
}

// K8sSyncStatus is the outcome of the last sync attempt of a cluster.
type K8sSyncStatus string

const (
	K8sSyncNever  K8sSyncStatus = "never"
	K8sSyncOK     K8sSyncStatus = "ok"
	K8sSyncFailed K8sSyncStatus = "failed"
)

// K8sCluster is a cluster connection.
type K8sCluster struct {
	ID string
	K8sClusterConfig
	Version string
	// LastSync is when the last stored inventory was collected.
	LastSync *time.Time
	// SyncStatus and SyncMessage describe the last sync attempt.
	// Read-only (RecordClusterSync).
	SyncStatus  K8sSyncStatus
	SyncMessage string
	// Workloads and Excluded count current workloads and those excluded by
	// the filter. Read-only.
	Workloads int
	Excluded  int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// K8sClusterRow is a cluster in a list.
type K8sClusterRow struct {
	K8sCluster
}

// ClusterFilter narrows ListClusters.
type ClusterFilter struct {
	// Q matches name or version.
	Q    string
	Sort string
}

// K8sInventory is the result of one inventory sync of a cluster.
type K8sInventory struct {
	Version   string
	At        time.Time // zero means now
	Workloads []K8sWorkloadObservation
}

// K8sWorkloadObservation is a top-level workload with its pods.
type K8sWorkloadObservation struct {
	Namespace  string
	Kind       string
	Name       string
	Replicas   int
	Excluded   bool
	ExcludedBy string
	Pods       []K8sPodObservation
}

// K8sPodObservation is one pod of a workload.
type K8sPodObservation struct {
	Name       string
	Node       string
	Phase      string // Running, Pending, Succeeded, Failed
	StartedAt  time.Time
	Containers []K8sPodContainerObservation
}

// K8sPodContainerObservation is one container of a pod.
type K8sPodContainerObservation struct {
	Name        string
	ImageRef    string
	ImageDigest string
}

// K8sInventoryResult lists the current workloads after a sync.
type K8sInventoryResult struct {
	Workloads []K8sWorkloadRef
	// GoneWorkloads counts workloads marked gone by this sync.
	GoneWorkloads int
}

// K8sWorkloadRef ties a workload to its asset. AssetID is empty for an
// excluded workload.
type K8sWorkloadRef struct {
	ID           string
	Namespace    string
	Kind         string
	Name         string
	Excluded     bool
	AssetID      string
	AssetCreated bool
}

// K8sWorkload is a workload of a cluster.
type K8sWorkload struct {
	ID         string
	ClusterID  string
	Namespace  string
	Kind       string
	Name       string
	Replicas   int
	AssetID    string
	Excluded   bool
	ExcludedBy string
	FirstSeen  time.Time
	LastSeen   time.Time
	GoneAt     *time.Time
}

// K8sWorkloadRow is a workload with a summary of its current pods.
type K8sWorkloadRow struct {
	K8sWorkload
	Pods int
	// Coverages are the distinct coverages of the pods' containers.
	Coverages []Coverage
}

// WorkloadFilter narrows ListWorkloads. Zero fields do not filter.
type WorkloadFilter struct {
	Namespace string
	Kind      string
	Excluded  *bool
	// Q matches name, namespace or kind.
	Q           string
	IncludeGone bool
	Sort        string
}

// K8sPod is a pod, the instance of a workload.
type K8sPod struct {
	ID         string
	WorkloadID string
	Namespace  string
	Name       string
	Node       string
	Phase      string
	StartedAt  *time.Time
	Containers []K8sPodContainer
	FirstSeen  time.Time
	LastSeen   time.Time
	GoneAt     *time.Time
}

// K8sPodContainer is a container of a pod with its collection coverage.
type K8sPodContainer struct {
	Name           string   `json:"name"`
	ImageRef       string   `json:"image_ref"`
	ImageDigest    string   `json:"image_digest"`
	Coverage       Coverage `json:"coverage"`
	CoverageReason string   `json:"coverage_reason"`
}

// PodFilter narrows pod lists.
type PodFilter struct {
	Phase string
	// Q matches pod or node name.
	Q           string
	IncludeGone bool
	Sort        string
}
