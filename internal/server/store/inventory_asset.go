// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import "time"

// AssetKind is what an asset is. Containers belong to assets; images are not
// assets.
type AssetKind string

const (
	AssetHost     AssetKind = "host"
	AssetWorkload AssetKind = "workload"
)

// CollectMethod is how an asset is collected.
type CollectMethod string

const (
	CollectAgent        CollectMethod = "agent"
	CollectSSH          CollectMethod = "ssh"
	CollectWinRM        CollectMethod = "winrm"
	CollectK8sExec      CollectMethod = "k8s_exec"
	CollectK8sInventory CollectMethod = "k8s_inventory"
)

// Coverage says how much of something could be collected. Sections use
// full, partial and none; assets and containers use the others as well.
type Coverage string

const (
	CoverageFull          Coverage = "full"
	CoveragePartial       Coverage = "partial"
	CoverageNone          Coverage = "none"
	CoverageProcessOnly   Coverage = "process_only"
	CoverageInventoryOnly Coverage = "inventory_only"
	CoverageUnsupported   Coverage = "unsupported"
	CoverageFailed        Coverage = "failed"

	// CoverageLimited is a filter value only: anything but full.
	CoverageLimited Coverage = "limited"
)

// HostIdentity identifies a host asset. At least one of AgentID, MachineID,
// ScanTargetID or ScannerID with Address must be set.
type HostIdentity struct {
	AgentID   string
	MachineID string
	// ScanTargetID identifies the host through the asset its scan target is
	// linked to; a new asset is linked to the target.
	ScanTargetID string
	ScannerID    string
	Address      string
}

// WorkloadIdentity identifies a workload asset. Kind is the top-level
// controller kind (Deployment, StatefulSet, DaemonSet, CronJob, Pod).
type WorkloadIdentity struct {
	ClusterID string
	Namespace string
	Kind      string
	Name      string
}

// AssetInit holds the values a new asset starts with. It is ignored when the
// asset exists.
type AssetInit struct {
	Name   string
	Group  string
	Tags   []string
	Method CollectMethod
	// SeenAt is the first and last seen time. Zero means now.
	SeenAt time.Time
}

// AssetRef is the result of an asset upsert.
type AssetRef struct {
	ID      string
	Created bool
	// DuplicateMachineID is set when another host asset has the same
	// machine id (a cloned machine).
	DuplicateMachineID bool
}

// OSInfo describes the operating system of an asset.
type OSInfo struct {
	Family  string // "linux", "windows"
	ID      string // os-release ID
	Name    string
	Version string
}

// AssetFacts updates an asset. Empty strings, a nil Tags, an all-empty OS
// and a zero SeenAt leave the stored values unchanged. CoverageReason is
// applied together with Coverage.
type AssetFacts struct {
	Name           string
	Group          string
	Tags           []string
	OS             OSInfo
	Kernel         string
	Arch           string
	Address        string
	Method         CollectMethod
	Privilege      Privilege
	Coverage       Coverage
	CoverageReason string
	// SeenAt raises last_seen, lowers first_seen and clears gone.
	SeenAt time.Time
}

// Asset is a host or a workload.
type Asset struct {
	ID             string
	Kind           AssetKind
	Name           string
	Group          string
	Tags           []string
	OS             OSInfo
	Kernel         string
	Arch           string
	Address        string
	Method         CollectMethod
	Coverage       Coverage
	CoverageReason string
	Privilege      Privilege

	AgentID   string
	MachineID string
	ScannerID string
	// ScanTargetID is the scan target linked to the asset, if any.
	// Read-only.
	ScanTargetID string

	// Workload identity; empty for hosts.
	ClusterID    string
	ClusterName  string
	Namespace    string
	WorkloadKind string
	WorkloadName string

	FirstSeen time.Time
	LastSeen  time.Time
	GoneAt    *time.Time
	// CollectRequestedAt is the time of a requested collection that no
	// report has answered yet.
	CollectRequestedAt *time.Time

	DuplicateMachineID bool
}

// Location is "cluster / namespace" for a workload and the address for a
// host.
func (a Asset) Location() string {
	if a.Kind != AssetWorkload {
		return a.Address
	}
	switch {
	case a.ClusterName != "" && a.Namespace != "":
		return a.ClusterName + " / " + a.Namespace
	case a.ClusterName != "":
		return a.ClusterName
	}
	return a.Namespace
}

// AssetBrief is the part of an asset shown next to related rows.
type AssetBrief struct {
	ID          string
	Name        string
	Kind        AssetKind
	Address     string
	ClusterID   string
	ClusterName string
	Namespace   string
}

// Location is as Asset.Location.
func (a AssetBrief) Location() string {
	return Asset{Kind: a.Kind, Address: a.Address, ClusterName: a.ClusterName, Namespace: a.Namespace}.Location()
}

// AssetRow is an asset in a list.
type AssetRow struct {
	Asset
	// Containers counts containers that are not gone.
	Containers int
	// Images are the distinct image references of those containers.
	Images []string
}

// AssetDetail is one asset with its sections and containers.
type AssetDetail struct {
	Asset
	// WorkloadID and Replicas are those of the workload of a workload asset
	// (its current workload record, else the last one).
	WorkloadID string
	Replicas   int
	Sections   []SectionState
	// Containers includes gone ones (GoneAt set), current ones first.
	Containers []Container
}

// AssetFilter narrows ListAssets. Zero fields do not filter.
type AssetFilter struct {
	Kind      AssetKind
	Group     string
	Method    CollectMethod
	Coverage  Coverage // also CoverageLimited
	ClusterID string
	// Tag keeps assets that carry the tag.
	Tag string
	// Q matches a case-insensitive substring of name, address, OS name or
	// version, a tag or a container image reference.
	Q           string
	IncludeGone bool
	Sort        string
}

// SectionState is the last collection of one report section.
type SectionState struct {
	// Container is empty for the asset itself.
	Container   string
	Section     string
	Coverage    Coverage
	Reason      string
	Digest      string
	CollectedAt time.Time
	// Baseline is the best coverage the stored items of the section were
	// collected with: raised by a report with at least that coverage, kept
	// by a reduced one (ARCH 3.6). Read-only; SetSectionStates derives it.
	Baseline Coverage
}

// CoverageRank orders section coverages from least (0) to most complete.
func CoverageRank(c Coverage) int {
	switch c {
	case CoverageFull:
		return 3
	case CoveragePartial:
		return 2
	case CoverageProcessOnly:
		return 1
	}
	return 0
}

// AssetGroupFilter narrows ListAssetGroups.
type AssetGroupFilter struct {
	// Q matches a case-insensitive substring of the group name.
	Q    string
	Sort string
}

// AssetGroupRow is a group with the number of current assets in it.
type AssetGroupRow struct {
	Name   string
	Assets int
}
