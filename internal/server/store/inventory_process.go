// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import "time"

// States of an executable or library mapping.
const (
	ExeNormal   = "normal"
	ExeReplaced = "replaced"
	ExeDeleted  = "deleted"
	ExeMemfd    = "memfd"
)

// Process list views.
const (
	ProcessViewAll        = "all"
	ProcessViewRestart    = "restart"    // replaced executable or library
	ProcessViewSuspicious = "suspicious" // deleted or memfd executable, deleted library
	ProcessViewListen     = "listen"     // has listen ports
)

// ProcessScope selects the process set a snapshot replaces. For a host, Pod
// and Container are empty and the snapshot is the whole host (processes carry
// their own container). For a workload, a snapshot comes from one container
// of one pod and every process belongs to that container.
type ProcessScope struct {
	AssetID   string
	Pod       string
	Container string
}

// MappedLib is an executable mapping whose file was replaced or deleted.
type MappedLib struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	SHA256 string `json:"sha256,omitempty"`
}

// ListenAddr is a listening socket.
type ListenAddr struct {
	Proto   string
	Address string
	Port    int
}

// UnownedPort is a listening socket whose process is not known.
type UnownedPort struct {
	ListenAddr
	UID int
}

// ProcessObservation is one running process.
type ProcessObservation struct {
	PID       int
	PPID      int
	User      string
	UID       int
	Exe       string
	ExeSource string
	ExeState  string
	SHA256    string
	Cmdline   string
	StartedAt time.Time
	Libs      []MappedLib
	Listen    []ListenAddr
	// Container is the container name on a host; ignored for a pod scope.
	Container string
	// Packages are the OS packages owning the executable and the shared
	// libraries the process maps; nil when the probe did not tell.
	Packages []string
	// ComponentID is the component of the executable, if known.
	ComponentID string
}

// ProcessSnapshot is the full process set of a scope at one time.
type ProcessSnapshot struct {
	At           time.Time // zero means now
	Processes    []ProcessObservation
	UnownedPorts []UnownedPort
}

// ProcessDelta counts what ReplaceProcesses changed.
type ProcessDelta struct {
	Appeared    int
	Disappeared int
	Kept        int
}

// Process is a current process of an asset.
type Process struct {
	ID          string
	AssetID     string
	Pod         string
	Container   string
	PID         int
	PPID        int
	User        string
	UID         int
	Exe         string
	ExeSource   string
	ExeState    string
	SHA256      string
	Cmdline     string
	StartedAt   time.Time
	Libs        []MappedLib
	Listen      []ListenAddr
	ComponentID string
	FirstSeen   time.Time
	LastSeen    time.Time
}

// NeedsRestart reports a replaced executable or library: an old version is
// still in memory.
func (p Process) NeedsRestart() bool {
	if p.ExeState == ExeReplaced {
		return true
	}
	for _, l := range p.Libs {
		if l.State == ExeReplaced {
			return true
		}
	}
	return false
}

// Suspicious reports a deleted or memfd executable or a deleted library.
func (p Process) Suspicious() bool {
	if p.ExeState == ExeDeleted || p.ExeState == ExeMemfd {
		return true
	}
	for _, l := range p.Libs {
		if l.State == ExeDeleted {
			return true
		}
	}
	return false
}

// ProcessRow is a process with its asset and executable component.
type ProcessRow struct {
	Process
	Asset     AssetBrief
	Component *Component
}

// ProcessFilter narrows ListProcesses. Zero fields do not filter.
type ProcessFilter struct {
	AssetID string
	// Container selects one container; a pointer to "" selects the asset
	// itself.
	Container *string
	View      string // ProcessView*
	ExeState  string
	// Q matches executable, user, command line, pid or asset name.
	Q    string
	Sort string
}

// ListenPortRow is one listening socket with its process, if known.
type ListenPortRow struct {
	ListenAddr
	Asset     AssetBrief
	Pod       string
	Container string
	// ProcessID is empty for an unowned port; UID is then the socket owner.
	ProcessID string
	PID       int
	Exe       string
	User      string
	UID       int
	Component *Component
}

// ListenPortFilter narrows ListListenPorts. Zero fields do not filter.
type ListenPortFilter struct {
	AssetID string
	Proto   string
	Port    int
	// Q matches address, executable, user or asset name.
	Q    string
	Sort string
}
