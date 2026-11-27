// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import "time"

// ComponentOrigin tells which advisories apply to a component.
type ComponentOrigin string

const (
	OriginDistro     ComponentOrigin = "distro"
	OriginThirdParty ComponentOrigin = "third_party"
	OriginUpstream   ComponentOrigin = "upstream"
)

// ComponentSource is the report section a component came from.
type ComponentSource string

const (
	SourcePackages  ComponentSource = "packages"
	SourceArtifacts ComponentSource = "artifacts"
)

// Layer of a container component. Empty for components of the asset itself.
const (
	LayerImage   = "image"
	LayerRuntime = "runtime"
)

// Detection methods of an installed component.
const (
	DetectPackageDB = "package_db"
	DetectExec      = "exec"
	DetectStatic    = "static"
	DetectManifest  = "manifest"
	DetectBuildInfo = "buildinfo"
)

// Component is a globally deduplicated piece of software.
//
// Its identity is (Type, Name, Version, Arch, Distro, PURL) and Build when it
// is set, compared exactly: two observations with equal values are the same
// component. The
// other fields are attributes taken from the first observation.
type Component struct {
	ID            string
	Type          string // deb, rpm, apk, maven, golang, binary, windows, middleware
	Name          string
	Version       string
	Build         string // vendor build or revision from a detector; identity when set
	Arch          string
	Distro        string // distro qualifier, e.g. "ubuntu-24.04"
	PURL          string
	CPE           string
	SourceName    string
	SourceVersion string
	Vendor        string
	Origin        ComponentOrigin
	// Modularity is the rpm module stream label
	// (name:stream:version:context), empty for other packages.
	Modularity string
}

// ComponentScope is one component set of an asset.
type ComponentScope struct {
	AssetID string
	// Container is empty for the asset itself.
	Container string
	Source    ComponentSource
	// Layer is empty for the asset itself, LayerRuntime (or LayerImage when
	// the image content cannot be stored by digest) for a container.
	Layer string
}

// ComponentObservation is one component seen in a scope.
type ComponentObservation struct {
	// Component carries identity and attributes; ID is ignored.
	Component      Component
	Locations      []string
	InUse          bool
	Method         string
	VersionCommand string
	VersionRaw     string
}

// ReplaceResult counts the changes of ReplaceAssetComponents.
type ReplaceResult struct {
	Added   int
	Removed int
	// Changed counts kept items whose locations, in-use flag, method or
	// version output changed.
	Changed int
	// NewComponents are the IDs of global components created by this call.
	NewComponents []string
	// ComponentIDs[i] is the component of the i-th observation.
	ComponentIDs []string
}

// ImageContent is the software of one image digest.
type ImageContent struct {
	Digest      string
	Coverage    Coverage
	CollectedAt time.Time
	// Exec is set when the content was collected inside a container of the
	// image (exec into a pod), where version commands may run. Content read
	// from a container root on the host has static versions only.
	Exec      bool
	Packages  []ComponentObservation
	Artifacts []ComponentObservation
}

// FileHash links a file's SHA-256 to a component.
type FileHash struct {
	SHA256      string
	ComponentID string
	Path        string
}

// Placement is where and how a component is installed.
type Placement struct {
	// Container is empty for the asset itself.
	Container      string
	Layer          string
	Source         ComponentSource
	Locations      []string
	InUse          bool
	Method         string
	VersionCommand string
	VersionRaw     string
	FirstSeen      time.Time
	RemovedAt      *time.Time
}

// AssetComponentRow is a component of one asset.
type AssetComponentRow struct {
	Component Component
	Placement
}

// AssetComponentFilter narrows ListAssetComponents. Zero fields do not
// filter.
type AssetComponentFilter struct {
	// Container selects one container; a pointer to "" selects the asset
	// itself.
	Container *string
	Type      string
	Origin    ComponentOrigin
	Source    ComponentSource
	// Layer keeps rows of that layer (LayerImage or LayerRuntime).
	Layer     string
	InUseOnly bool
	// InUse keeps rows whose in-use flag equals the value. InUseOnly is the
	// same as InUse true.
	InUse *bool
	// Q matches name, version, purl, container or a location.
	Q string
	// IncludeRemoved adds history: removed items and the image content of
	// gone containers.
	IncludeRemoved bool
	Sort           string
}

// ComponentRow is a component with the number of assets it is installed on.
type ComponentRow struct {
	Component
	Assets int
	// RunningAssets counts the assets on which a running process executes
	// or maps the component now.
	RunningAssets int
}

// ComponentFilter narrows ListComponents. Zero fields do not filter.
type ComponentFilter struct {
	Type   string
	Origin ComponentOrigin
	// Source keeps components installed from that section somewhere.
	Source ComponentSource
	// InstalledOnly drops components that are installed nowhere now.
	InstalledOnly bool
	// RunningOnly drops components that no running process uses now.
	RunningOnly bool
	// Q matches name or purl.
	Q    string
	Sort string
}

// ComponentAssetRow is one installation of a component.
type ComponentAssetRow struct {
	Asset AssetRow
	Placement
}

// ComponentAssetFilter narrows ListComponentAssets. Zero fields do not
// filter.
type ComponentAssetFilter struct {
	Kind AssetKind
	// InUse keeps rows whose in-use flag equals the value.
	InUse  *bool
	Method string
	// IncludeRemoved adds history: removed installations and the image
	// content of gone containers. Gone assets are not listed.
	IncludeRemoved bool
	// Q matches asset name, container or a location.
	Q    string
	Sort string
}

// ImageComponentRow is a component of an image.
type ImageComponentRow struct {
	Component Component
	Placement
}

// ImageComponentFilter narrows ListImageComponents.
type ImageComponentFilter struct {
	Type   string
	Source ComponentSource
	// Q matches name, version or purl.
	Q    string
	Sort string
}
