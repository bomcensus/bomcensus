// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import "time"

// Container runtimes.
const (
	RuntimeKubernetes = "kubernetes"
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
)

// ContainerObservation is one container of an asset. Name is the key inside
// the asset.
type ContainerObservation struct {
	Name string
	// RuntimeID is the runtime's container id (host containers), used to
	// attribute processes.
	RuntimeID   string
	ImageRef    string
	ImageDigest string
	Runtime     string
	// Instances is 1 or 0 for a host container, the number of running pods
	// for a workload container.
	Instances int
	// Coverage empty keeps the stored coverage; a new container, or one
	// whose digest changed, then gets CoverageInventoryOnly.
	Coverage       Coverage
	CoverageReason string
	StartedAt      time.Time // zero when unknown
	// PodUID and PodContainer are set for a host container that the
	// kubelet created for a pod: the pod's uid and the container's name in
	// the pod.
	PodUID       string
	PodContainer string
}

// Container is a container of an asset.
type Container struct {
	Name           string
	RuntimeID      string
	ImageRef       string
	ImageDigest    string
	Runtime        string
	Instances      int
	Coverage       Coverage
	CoverageReason string
	StartedAt      *time.Time
	// PreviousDigest is the digest before the last image change.
	PreviousDigest string
	// DigestSince is when the container was first seen with ImageDigest.
	DigestSince time.Time
	FirstSeen   time.Time
	LastSeen    time.Time
	GoneAt      *time.Time
	// PodUID and PodContainer are as in ContainerObservation.
	PodUID       string
	PodContainer string
	// Workload is the workload asset that owns a pod container of a host:
	// its findings are the workload's. Read-only.
	Workload *ContainerWorkload
}

// ContainerWorkload is the workload asset a host container is linked to.
type ContainerWorkload struct {
	AssetID string
	Name    string
	Pod     string
}

// ImageObservation is an image seen on a host or in a cluster.
type ImageObservation struct {
	Digest   string
	RepoTags []string
	OS       string
	Arch     string
	Size     int64
}

// ImageSourceKind is what observed the tags of an image.
type ImageSourceKind string

// Image sources.
const (
	// ImageSourceAsset is a host asset: its runtime image list and the image
	// references of its containers.
	ImageSourceAsset ImageSourceKind = "asset"
	// ImageSourceCluster is a Kubernetes cluster: the image references of
	// its pod containers.
	ImageSourceCluster ImageSourceKind = "cluster"
)

// ImageSource identifies an observer of image tags.
type ImageSource struct {
	Kind ImageSourceKind
	ID   string
}

// PreviousTag is a tag that pointed to an image digest and no longer does.
type PreviousTag struct {
	Tag      string
	LastSeen time.Time
}

// Image is the inventory record of an image digest. Images are not assets.
type Image struct {
	Digest string
	// Tags point to the digest now: a live source (an asset or cluster that
	// is not gone) lists them for the digest in its latest observation.
	Tags []string
	// PreviousTags pointed to the digest before, most recently seen first.
	PreviousTags []PreviousTag
	OS           string
	Arch         string
	Size         int64
	FirstSeen    time.Time
	LastSeen     time.Time
	// ContentCollectedAt is set when the content of the digest is known.
	ContentCollectedAt *time.Time
	ContentCoverage    Coverage
}

// ContentKnown reports whether the image's software is known.
func (i Image) ContentKnown() bool { return i.ContentCollectedAt != nil }

// ImageRow is an image with its usage by current containers.
type ImageRow struct {
	Image
	Assets     int
	Containers int
	Instances  int
	// Components counts the components of the image content.
	Components int
}

// ImageUse is one container running an image.
type ImageUse struct {
	Asset     AssetRow
	Container Container
}

// ImageDetail is one image with the containers that run it.
type ImageDetail struct {
	ImageRow
	Uses []ImageUse
}

// ImageFilter narrows ListImages. Zero fields do not filter.
type ImageFilter struct {
	// InUseOnly keeps images that a current container runs.
	InUseOnly bool
	// ContentKnown keeps images whose content is (true) or is not (false)
	// known.
	ContentKnown *bool
	// Q matches digest or a current or previous tag.
	Q    string
	Sort string
}
