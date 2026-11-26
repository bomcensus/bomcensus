// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package report defines the collection report: what a probe writes, what an
// agent or scanner uploads and what the server ingests. It is the only schema
// shared by all of them.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is bumped on incompatible changes. The server keeps accepting
// older versions because agents can lag behind.
const SchemaVersion = 1

// Section names used in requests, digests and policies.
const (
	SectionHost       = "host"
	SectionPackages   = "packages"
	SectionArtifacts  = "artifacts"
	SectionProcesses  = "processes"
	SectionContainers = "containers"
	// SectionGoSymbols is not collected: it answers Request.GoSymbols and
	// is not part of AllSections. A request naming only it collects
	// nothing else.
	SectionGoSymbols = "go_symbols"
	// SectionIntegrity is not part of AllSections either: it is collected
	// only when named together with Request.Integrity, and alone.
	SectionIntegrity = "integrity"
)

// AllSections lists the sections in collection order.
var AllSections = []string{SectionHost, SectionPackages, SectionArtifacts, SectionProcesses, SectionContainers}

// Coverage says how much of a section could be collected.
type Coverage string

const (
	CoverageFull    Coverage = "full"
	CoveragePartial Coverage = "partial"
	CoverageNone    Coverage = "none"
)

// SectionMeta is embedded in every section.
type SectionMeta struct {
	// Digest is the hex SHA-256 of the section body (see Digest).
	Digest string `json:"digest,omitempty"`
	// Unchanged is set when the digest equals the one the requester already
	// has. The section then carries no items.
	Unchanged bool     `json:"unchanged,omitempty"`
	Coverage  Coverage `json:"coverage"`
	// Reason explains a coverage other than full, in plain English.
	Reason      string    `json:"reason,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	DurationMs  int64     `json:"duration_ms,omitempty"`
}

// Report is one collection result for one subject.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	ProbeVersion  string    `json:"probe_version"`
	CollectedAt   time.Time `json:"collected_at"`
	// Subject is filled in by the agent or scanner, never by the probe.
	Subject   *Subject  `json:"subject,omitempty"`
	Privilege Privilege `json:"privilege"`

	Host       *HostSection       `json:"host,omitempty"`
	Packages   *PackagesSection   `json:"packages,omitempty"`
	Artifacts  *ArtifactsSection  `json:"artifacts,omitempty"`
	Processes  *ProcessesSection  `json:"processes,omitempty"`
	Containers *ContainersSection `json:"containers,omitempty"`
	GoSymbols  *GoSymbolsSection  `json:"go_symbols,omitempty"`
	Integrity  *IntegritySection  `json:"integrity,omitempty"`

	// Detectors is the detector table used for the artifacts and the
	// container contents. Older probes do not report it.
	Detectors *DetectorUse `json:"detectors,omitempty"`

	// Cache is opaque probe state (file hash cache). The caller stores it and
	// passes it back in the next Request. Never uploaded to the server.
	Cache json.RawMessage `json:"cache,omitempty"`
}

// SubjectKind tells what a report describes.
type SubjectKind string

const (
	// SubjectSelf is the host the reporting agent runs on.
	SubjectSelf SubjectKind = "self"
	// SubjectScanTarget is a host reached by a scanner over SSH.
	SubjectScanTarget SubjectKind = "scan_target"
	// SubjectK8sContainer is one container of one pod, collected through exec.
	SubjectK8sContainer SubjectKind = "k8s_container"
)

type Subject struct {
	Kind         SubjectKind `json:"kind"`
	ScanTargetID string      `json:"scan_target_id,omitempty"`
	K8s          *K8sSubject `json:"k8s,omitempty"`
}

type K8sSubject struct {
	ClusterID   string `json:"cluster_id"`
	Namespace   string `json:"namespace"`
	Pod         string `json:"pod"`
	Container   string `json:"container"`
	ImageRef    string `json:"image_ref,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
}

// Privilege levels.
const (
	PrivilegePrivileged = "privileged"
	PrivilegeNonRoot    = "non_root"
)

// Privilege describes what the probe was allowed to read.
type Privilege struct {
	// Level is PrivilegePrivileged when the probe could read other users'
	// processes and files, PrivilegeNonRoot otherwise.
	Level        string   `json:"level"`
	UID          int      `json:"uid"`
	Capabilities []string `json:"capabilities,omitempty"`
	ExecHelper   bool     `json:"exec_helper,omitempty"`
}

// ── host ────────────────────────────────────────────────────────────────

type HostSection struct {
	SectionMeta
	Hostname  string `json:"hostname"`
	MachineID string `json:"machine_id,omitempty"`
	OS        OS     `json:"os"`
	Kernel    string `json:"kernel,omitempty"`
	Arch      string `json:"arch"`
}

// OS mirrors /etc/os-release on Linux. For Windows see
// internal/collect/hostinfo.
type OS struct {
	Family     string `json:"family"` // "linux" or "windows"
	ID         string `json:"id,omitempty"`
	IDLike     string `json:"id_like,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	Codename   string `json:"codename,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
}

// ── packages ────────────────────────────────────────────────────────────

const (
	PackageDeb = "deb"
	PackageRPM = "rpm"
	PackageAPK = "apk"
)

type PackagesSection struct {
	SectionMeta
	// Databases lists the package databases that were read.
	Databases []PackageDB `json:"databases,omitempty"`
	Packages  []Package   `json:"packages,omitempty"`
}

type PackageDB struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// Package is one installed OS package, as recorded by the package database.
type Package struct {
	Type string `json:"type"`
	Name string `json:"name"`
	// Version is the full native version string (dpkg: [epoch:]upstream[-revision],
	// rpm: [epoch:]version-release, apk: version-rN).
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	// SourceName and SourceVersion identify the source package. Distribution
	// advisories are keyed by source package.
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	Maintainer    string `json:"maintainer,omitempty"`
	// ModularityLabel is the rpm module stream label, if any.
	ModularityLabel string `json:"modularity_label,omitempty"`
	// Status is the dpkg status ("install ok installed") when it is not the
	// normal installed state.
	Status string `json:"status,omitempty"`
}

// ── artifacts ───────────────────────────────────────────────────────────

const (
	ArtifactJar      = "jar"       // JAR/WAR/EAR, including nested ones
	ArtifactGoBinary = "go_binary" // executable with Go build info
	ArtifactGoModule = "go_module" // a module listed in a Go binary's build info
	ArtifactSoftware = "software"  // matched by a known-software detector
	// ArtifactPackageFile is a running executable that nothing but its OS
	// package accounts for. It only carries OwnerPackage, the hash and the
	// in-use flag, so that the package can be linked to its processes.
	ArtifactPackageFile = "package_file"
)

// Detection methods.
const (
	MethodExec      = "exec"      // version command was run
	MethodStatic    = "static"    // version extracted from file contents
	MethodManifest  = "manifest"  // pom.properties, MANIFEST.MF and similar
	MethodBuildInfo = "buildinfo" // Go build info
	MethodPackageDB = "pkgdb"     // file list of the OS package database
)

// Layers of a container file system.
const (
	LayerImage   = "image"
	LayerRuntime = "runtime"
)

type ArtifactsSection struct {
	SectionMeta
	// WalkPaths are the directories that were walked. The other artifacts
	// come from running processes. Not part of the digest.
	WalkPaths []string   `json:"walk_paths,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

// Artifact is a piece of software found outside the package database, or a
// file that a detector recognized.
type Artifact struct {
	Kind string `json:"kind"`
	// Path is the file on disk. For a nested archive entry it is the outermost
	// file and Nested lists the entry names leading to this artifact.
	Path   string   `json:"path"`
	Nested []string `json:"nested,omitempty"`

	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// Build is the vendor build or revision number a detector found next to
	// the version ("117458" for a Genian NAC svn revision). Builds of the
	// same version are different components.
	Build string `json:"build,omitempty"`
	// Detector is the id of the known-software detector that matched.
	Detector string `json:"detector,omitempty"`
	Method   string `json:"method"`
	// VersionOutput is the raw result of the version command (MethodExec).
	VersionOutput *VersionOutput `json:"version_output,omitempty"`
	// StaticVersion is set when both exec and static extraction produced a
	// version and they differ.
	StaticVersion string `json:"static_version,omitempty"`

	// PURL and CPE are suggestions from the detector. The server normalizes.
	PURL string `json:"purl,omitempty"`
	CPE  string `json:"cpe,omitempty"`

	// Maven coordinates for jars.
	GroupID    string `json:"group_id,omitempty"`
	ArtifactID string `json:"artifact_id,omitempty"`

	// GoVersion is the toolchain version of a Go binary, GOOS and GOARCH
	// its target from the build settings.
	GoVersion string `json:"go_version,omitempty"`
	GOOS      string `json:"goos,omitempty"`
	GOARCH    string `json:"goarch,omitempty"`
	// Module is the module path for ArtifactGoModule.
	Module string `json:"module,omitempty"`

	SHA256 string `json:"sha256,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	Size   int64  `json:"size,omitempty"`

	// InUse is true when a running process executes or has opened the file.
	InUse bool `json:"in_use,omitempty"`
	// OwnerPackage is the OS package that owns Path, if any. Such artifacts
	// are linked to the package instead of becoming separate components.
	OwnerPackage string `json:"owner_package,omitempty"`
	// Layer is set inside container scopes when it can be told apart.
	Layer string `json:"layer,omitempty"`
}

// VersionOutput is kept verbatim, truncated to 64 KiB per stream.
type VersionOutput struct {
	Command   []string `json:"command"`
	Stdout    string   `json:"stdout,omitempty"`
	Stderr    string   `json:"stderr,omitempty"`
	ExitCode  int      `json:"exit_code"`
	Truncated bool     `json:"truncated,omitempty"`
}

// ── processes ───────────────────────────────────────────────────────────

// States of an executable or library mapping.
const (
	ExeNormal   = "normal"
	ExeReplaced = "replaced" // another file now exists at the path
	ExeDeleted  = "deleted"  // nothing exists at the path
	ExeMemfd    = "memfd"    // executed from an anonymous memory file
)

// Sources of Process.Exe.
const (
	ExeFromProc    = "proc"    // read from /proc/<pid>/exe
	ExeFromCmdline = "cmdline" // guessed from argv[0]; no hash, state unknown
)

type ProcessesSection struct {
	SectionMeta
	Processes []Process `json:"processes,omitempty"`
	// UnownedPorts are listening sockets whose owning process could not be
	// determined (other users' processes without privileges).
	UnownedPorts []UnownedPort `json:"unowned_ports,omitempty"`
	// ProbeMountNS is the mount namespace of the probe itself, when it read
	// its own /proc. Inside a container it identifies the container, so that
	// processes of other containers sharing the PID namespace can be told
	// apart by Process.MountNS.
	ProbeMountNS uint64 `json:"probe_mount_ns,omitempty"`
}

type Process struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid,omitempty"`
	User string `json:"user"`
	UID  int    `json:"uid"`
	// Exe is the executable path without the " (deleted)" suffix.
	Exe       string `json:"exe"`
	ExeSource string `json:"exe_source"`
	ExeState  string `json:"exe_state"`
	SHA256    string `json:"sha256,omitempty"`
	// Cmdline has secrets masked.
	Cmdline   string      `json:"cmdline,omitempty"`
	StartedAt time.Time   `json:"started_at"`
	Libs      []MappedLib `json:"libs,omitempty"`
	Listen    []Listen    `json:"listen,omitempty"`
	// ContainerID is the runtime container id taken from the cgroup path.
	ContainerID string `json:"container_id,omitempty"`
	// MountNS is the inode of the mount namespace, zero when unreadable.
	MountNS uint64 `json:"mount_ns,omitempty"`
	// Packages are the OS packages that own the executable and the files
	// the process maps for execution (shared libraries), as named by the
	// package database of the process's root. Only meaningful when
	// PackagesKnown: that database was read and the mappings were too.
	Packages      []string `json:"packages,omitempty"`
	PackagesKnown bool     `json:"packages_known,omitempty"`
	// Mapped are the paths of the other files mapped for execution. The
	// probe turns them into Packages; they are not reported.
	Mapped []string `json:"-"`
}

// MappedLib is an executable mapping whose file was replaced or deleted.
type MappedLib struct {
	Path   string `json:"path"`
	State  string `json:"state"` // ExeReplaced or ExeDeleted
	SHA256 string `json:"sha256,omitempty"`
}

type Listen struct {
	Proto   string `json:"proto"` // "tcp" or "udp"
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type UnownedPort struct {
	Listen
	UID int `json:"uid"`
}

// ── containers ──────────────────────────────────────────────────────────

type ContainersSection struct {
	SectionMeta
	// InventoryCoverage is the coverage of the container and image lists
	// alone. Coverage is lower than it when the content scan fell short.
	// Empty means the same as Coverage.
	InventoryCoverage Coverage    `json:"inventory_coverage,omitempty"`
	Runtimes          []string    `json:"runtimes,omitempty"` // "docker", "containerd"
	Containers        []Container `json:"containers,omitempty"`
	Images            []Image     `json:"images,omitempty"`
	// ImageScopes holds the content of running containers, once per image
	// digest. Filled by the probe, not by the container collector.
	ImageScopes []ImageScope `json:"image_scopes,omitempty"`
}

type Container struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Runtime     string    `json:"runtime"`
	ImageRef    string    `json:"image_ref,omitempty"`
	ImageDigest string    `json:"image_digest,omitempty"`
	Running     bool      `json:"running"`
	StartedAt   time.Time `json:"started_at,omitzero"`
	// InitPID and UpperDir are probe-internal hints and are not uploaded.
	InitPID  int    `json:"init_pid,omitempty"`
	UpperDir string `json:"upper_dir,omitempty"`
	// Coverage of this container's content and the reason when not full.
	Coverage Coverage `json:"coverage"`
	Reason   string   `json:"reason,omitempty"`
	// Runtime lists artifacts added or changed after start, when the writable
	// layer could be told apart.
	RuntimeArtifacts []Artifact `json:"runtime_artifacts,omitempty"`
}

type Image struct {
	Digest   string   `json:"digest"`
	RepoTags []string `json:"repo_tags,omitempty"`
	OS       string   `json:"os,omitempty"`
	Arch     string   `json:"arch,omitempty"`
	Size     int64    `json:"size,omitempty"`
}

// ImageScope is the software found in one image, read through a running
// container of that image.
type ImageScope struct {
	Digest    string     `json:"digest"`
	OS        *OS        `json:"os,omitempty"`
	Packages  []Package  `json:"packages,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
	// FromContainer is the container id the content was read from.
	FromContainer string `json:"from_container,omitempty"`
}

// ── request ─────────────────────────────────────────────────────────────

// Request is what the caller writes to the probe's standard input.
type Request struct {
	// Sections to collect. Empty means all.
	Sections []string `json:"sections,omitempty"`
	// KnownDigests maps section name to the digest the caller already has.
	KnownDigests map[string]string `json:"known_digests,omitempty"`
	Policy       Policy            `json:"policy"`
	// Cache is Report.Cache from the previous run.
	Cache json.RawMessage `json:"cache,omitempty"`
	// GoSymbols asks whether functions are linked into Go binaries. It is
	// answered in Report.GoSymbols whatever Sections says.
	GoSymbols *GoSymbolQuery `json:"go_symbols,omitempty"`
	// Integrity starts or continues a package file integrity pass. It is
	// answered in Report.Integrity when Sections names SectionIntegrity.
	Integrity *IntegrityQuery `json:"integrity,omitempty"`
	// Detectors replaces the probe's built-in detector table, within the
	// limits of SECURITY.md. Nil uses the built-in table; older probes
	// ignore it.
	Detectors *DetectorTable `json:"detectors,omitempty"`
}

// Policy comes from the server and bounds what the probe does.
type Policy struct {
	// ExecVersion allows running version commands of known software.
	ExecVersion bool `json:"exec_version"`
	// ExcludePaths are skipped by the file system walk, in addition to the
	// built-in ones (/proc, /sys, /dev, network mounts).
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	// WalkPaths are the absolute directories of the inspected host walked
	// for software. Empty means no walk: only the executables of running
	// processes and the archives they hold open are inspected. Container
	// roots are image content and are always walked whole.
	WalkPaths []string `json:"walk_paths,omitempty"`
	// CollectCmdline can be turned off to leave command lines out entirely.
	CollectCmdline bool `json:"collect_cmdline"`
	// ScanContainers reads the content of running containers on a host.
	ScanContainers bool `json:"scan_containers"`
	// MaxRuntimeSeconds bounds one probe run. Zero means the default.
	MaxRuntimeSeconds int `json:"max_runtime_seconds,omitempty"`
	// MemoryLimitMB sets GOMEMLIMIT for the probe. Zero means the default.
	MemoryLimitMB int `json:"memory_limit_mb,omitempty"`
}

// DefaultPolicy is used when the server has not sent one yet.
func DefaultPolicy() Policy {
	return Policy{ExecVersion: true, CollectCmdline: true, ScanContainers: true}
}

// ── go symbols ──────────────────────────────────────────────────────────

// Limits of a GoSymbolQuery. A probe rejects a request that exceeds any of
// them as a whole.
const (
	MaxGoSymbolFiles        = 64
	MaxGoSymbolNamesPerFile = 512
	MaxGoSymbolNames        = 4096
	MaxGoSymbolNameLen      = 512
)

// FeatureGoSymbols is the feature an agent or scanner reports when it
// passes GoSymbolQuery to the probe and uploads the answers.
const FeatureGoSymbols = "go_symbols"

// Answers for one function name.
const (
	GoSymbolPresent    = "present"
	GoSymbolAbsent     = "absent"
	GoSymbolNotChecked = "not_checked"
)

// GoSymbolQuery names Go binaries the requester saw in an earlier report
// and the functions to look up in each.
type GoSymbolQuery struct {
	Files []GoSymbolFile `json:"files"`
}

// GoSymbolFile is one binary. Names are package path qualified function
// names as the Go vulnerability database writes them ("net/http.Serve",
// "net/http.Server.Serve" or "net/http.(*Server).Serve").
type GoSymbolFile struct {
	// Container is the runtime id of a running container; Path is then
	// inside its root. Empty for the subject's own file system.
	Container string `json:"container,omitempty"`
	Path      string `json:"path"`
	// SHA256 must match the file, else every name is not checked.
	SHA256 string   `json:"sha256"`
	Names  []string `json:"names"`
}

// Validate checks the limits and the form of the query.
func (q *GoSymbolQuery) Validate() error {
	if len(q.Files) > MaxGoSymbolFiles {
		return fmt.Errorf("go symbols: %d files, at most %d", len(q.Files), MaxGoSymbolFiles)
	}
	total := 0
	for _, f := range q.Files {
		if !strings.HasPrefix(f.Path, "/") && !isWindowsAbs(f.Path) {
			return fmt.Errorf("go symbols: path %q is not absolute", f.Path)
		}
		if len(f.SHA256) != 64 {
			return fmt.Errorf("go symbols: %s: bad sha256", f.Path)
		}
		if len(f.Names) > MaxGoSymbolNamesPerFile {
			return fmt.Errorf("go symbols: %s: %d names, at most %d", f.Path, len(f.Names), MaxGoSymbolNamesPerFile)
		}
		total += len(f.Names)
		for _, n := range f.Names {
			if n == "" || len(n) > MaxGoSymbolNameLen {
				return fmt.Errorf("go symbols: %s: name of %d bytes", f.Path, len(n))
			}
		}
	}
	if total > MaxGoSymbolNames {
		return fmt.Errorf("go symbols: %d names, at most %d", total, MaxGoSymbolNames)
	}
	return nil
}

// isWindowsAbs reports whether p is an absolute Windows path: with a drive
// letter or a UNC path.
func isWindowsAbs(p string) bool {
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') || strings.HasPrefix(p, `\\`)
}

// GoSymbolsSection answers a GoSymbolQuery, one entry per requested file in
// request order. It has no digest and is never unchanged.
type GoSymbolsSection struct {
	SectionMeta
	Files []GoSymbolAnswer `json:"files,omitempty"`
}

type GoSymbolAnswer struct {
	Container string `json:"container,omitempty"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	// Results maps every requested name to GoSymbolPresent, GoSymbolAbsent
	// or GoSymbolNotChecked.
	Results map[string]string `json:"results"`
	// Reason explains why names were not checked.
	Reason string `json:"reason,omitempty"`
}

// ── integrity ───────────────────────────────────────────────────────────

// FeatureIntegrity is the feature an agent or scanner reports when it runs
// integrity passes.
const FeatureIntegrity = "integrity"

// Statuses of an integrity finding.
const (
	IntegrityModified = "modified"
	IntegrityMissing  = "missing"
)

// Limits of an integrity request.
const (
	MaxIntegrityRuntimeSeconds = 5 * 3600
	MaxIntegrityExcludes       = 256
	MaxIntegrityExcludeLen     = 1024
	MaxIntegrityCursorLen      = 4096
	MaxIntegrityPassIDLen      = 64
	MaxIntegrityReadMBps       = 1000
	// MaxIntegrityFindings bounds the findings of one chunk. A chunk that
	// reaches it ends early; the rest of the pass continues in the next.
	MaxIntegrityFindings = 5000
)

// IntegrityQuery asks the probe to compare package files with the digests
// their package database records. A pass over all packages may take several
// chunks; each chunk returns a cursor that the next one continues from.
type IntegrityQuery struct {
	// PassID names the pass; the probe returns it unchanged.
	PassID string `json:"pass_id"`
	// Cursor is IntegritySection.Cursor of the previous chunk, empty for the
	// first chunk of a pass.
	Cursor string `json:"cursor,omitempty"`
	// FullRehash hashes every file even when the cache knows it.
	FullRehash bool `json:"full_rehash,omitempty"`
	// MaxReadMBps bounds the read rate. Zero means the default.
	MaxReadMBps int `json:"max_read_mbps,omitempty"`
	// ExcludePaths are path prefixes or globs ("**" matches any number of
	// directories) that are not checked.
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	// Cache is IntegritySection.Cache of the previous chunk.
	Cache json.RawMessage `json:"cache,omitempty"`
}

// Validate checks the limits of the query.
func (q *IntegrityQuery) Validate() error {
	if q.PassID == "" || len(q.PassID) > MaxIntegrityPassIDLen {
		return fmt.Errorf("integrity: pass id must be 1 to %d bytes", MaxIntegrityPassIDLen)
	}
	if len(q.Cursor) > MaxIntegrityCursorLen {
		return fmt.Errorf("integrity: cursor longer than %d bytes", MaxIntegrityCursorLen)
	}
	if q.MaxReadMBps < 0 || q.MaxReadMBps > MaxIntegrityReadMBps {
		return fmt.Errorf("integrity: read rate must be 0 to %d MB/s", MaxIntegrityReadMBps)
	}
	if len(q.ExcludePaths) > MaxIntegrityExcludes {
		return fmt.Errorf("integrity: more than %d exclude paths", MaxIntegrityExcludes)
	}
	for _, p := range q.ExcludePaths {
		if !strings.HasPrefix(p, "/") || len(p) > MaxIntegrityExcludeLen {
			return fmt.Errorf("integrity: exclude path %q must be absolute and at most %d bytes", p, MaxIntegrityExcludeLen)
		}
	}
	return nil
}

// IntegritySection is the result of one chunk of an integrity pass.
type IntegritySection struct {
	SectionMeta
	PassID string `json:"pass_id"`
	// PassDone is set by the chunk that checked the last package.
	PassDone bool `json:"pass_done"`
	// Cursor is where the next chunk starts.
	Cursor string `json:"cursor,omitempty"`
	// UTCOffsetSeconds is the inspected host's offset from UTC now, so that
	// a scanner can place the next window in the host's local time.
	UTCOffsetSeconds int `json:"utc_offset_s"`
	// Packages, Checked, Excluded and Unreadable count this chunk. Excluded
	// files are conffiles and other files the database marks as
	// changeable, policy exclusions and files too large to hash.
	Packages   int                `json:"packages"`
	Checked    int64              `json:"checked"`
	Excluded   int64              `json:"excluded"`
	Unreadable int64              `json:"unreadable"`
	Findings   []IntegrityFinding `json:"findings,omitempty"`
	// Cache is opaque probe state for the next chunk. Never uploaded.
	Cache json.RawMessage `json:"cache,omitempty"`
}

// IntegrityFinding is a package file whose content differs from the
// database digest, or that is missing.
type IntegrityFinding struct {
	PkgType string `json:"pkg_type"`
	Package string `json:"package"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Path    string `json:"path"`
	Status  string `json:"status"`
	// Algo is the database's algorithm; Expected and Actual are hex in it.
	Algo     string `json:"algo"`
	Expected string `json:"expected"`
	Actual   string `json:"actual,omitempty"`
	// ActualSHA256 is set when Algo is not sha256.
	ActualSHA256 string    `json:"actual_sha256,omitempty"`
	Size         int64     `json:"size,omitempty"`
	Mtime        time.Time `json:"mtime,omitzero"`
	Ctime        time.Time `json:"ctime,omitzero"`
}

// SHA256 returns the actual SHA-256 of a modified file, empty when missing.
func (f *IntegrityFinding) SHA256() string {
	if f.Algo == "sha256" {
		return f.Actual
	}
	return f.ActualSHA256
}
