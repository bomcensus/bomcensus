// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package report

// DetectorSchemaVersion is the version of the detector table format. A probe
// ignores a table with another version and uses its built-in table.
const DetectorSchemaVersion = 1

// DetectorTable is the known-software detector table. The probe has one
// built in (internal/detectors/detectors.yaml); the server may send another
// in Request.Detectors. Its digest is the hex SHA-256 of its JSON encoding
// (internal/detectors.Digest). What a probe accepts from a table that is
// not its own is described in SECURITY.md.
type DetectorTable struct {
	SchemaVersion int            `json:"schema_version"`
	Detectors     []DetectorSpec `json:"detectors"`
}

// DetectorSpec recognizes one piece of known software by file name and
// finds its version (see internal/collect/artifact.Detector).
type DetectorSpec struct {
	// ID is stable; it is reported in Artifact.Detector.
	ID string `json:"id"`
	// Name is the reported software name unless a rule overrides it.
	Name string `json:"name"`
	// Names are path.Match patterns for the base name of the file.
	Names []string `json:"names"`
	// Paths, when set, are path.Match patterns for the trailing components
	// of the path ("bin/java"); one of them must match.
	Paths []string `json:"paths,omitempty"`
	// Archive matches Java archives instead of ELF executables.
	Archive bool `json:"archive,omitempty"`

	// Exec is the argument list of the version command. It is run only
	// for detectors whose command is the same as in the probe's own table.
	Exec []string      `json:"exec,omitempty"`
	Env  []DetectorEnv `json:"env,omitempty"`
	// Parse extracts the version from the command output.
	Parse []DetectorRule `json:"parse,omitempty"`
	// AddressSpaceMB overrides the address space limit of the command.
	AddressSpaceMB int `json:"address_space_mb,omitempty"`

	// Static rules are tried in order; the first that yields a version
	// wins.
	Static []DetectorStatic `json:"static,omitempty"`

	// PURL and CPE are templates; {version} is replaced.
	PURL string `json:"purl,omitempty"`
	CPE  string `json:"cpe,omitempty"`
}

// DetectorEnv is an environment variable of the version command: the
// directory Up levels above the file.
type DetectorEnv struct {
	Name string `json:"name"`
	Up   int    `json:"up"`
}

// DetectorRule extracts a version with a Go regular expression (RE2): the
// group named "version" if there is one, else the first group. A group
// named "build" captures the build number.
type DetectorRule struct {
	Pattern string `json:"pattern"`
	// Name, PURL and CPE override the detector's values when set.
	Name string `json:"name,omitempty"`
	PURL string `json:"purl,omitempty"`
	CPE  string `json:"cpe,omitempty"`
}

// DetectorStatic reads a version without running anything.
type DetectorStatic struct {
	// File is relative to the directory of the matched file and may hold
	// glob characters. Empty means the matched file.
	File string `json:"file,omitempty"`
	// Entry reads one entry of a zip archive (File, or the matched file).
	Entry string `json:"entry,omitempty"`
	// BuildSetting matches the rules against one Go build setting.
	BuildSetting string `json:"build_setting,omitempty"`
	// GoMain takes the main module version of a Go binary.
	GoMain bool           `json:"go_main,omitempty"`
	Rules  []DetectorRule `json:"rules,omitempty"`
	// Limit bounds the bytes scanned. Zero means the default.
	Limit int64 `json:"limit,omitempty"`
}

// Sources of the detector table a probe used.
const (
	DetectorsBuiltin = "builtin" // the probe's own table
	DetectorsRequest = "request" // Request.Detectors
)

// DetectorUse is the detector table a probe used for a report.
type DetectorUse struct {
	// Digest of the table (internal/detectors.Digest), before entries were
	// dropped.
	Digest string `json:"digest"`
	// Source is DetectorsBuiltin or DetectorsRequest.
	Source string `json:"source"`
	// Error says why Request.Detectors was not used; the built-in table
	// was used instead.
	Error string `json:"error,omitempty"`
	// Rejected lists the entries of the table that were dropped.
	Rejected []DetectorRejection `json:"rejected,omitempty"`
	// StaticOnly lists the detectors whose version command was not run
	// because it differs from the probe's own table.
	StaticOnly []string `json:"static_only,omitempty"`
}

// DetectorRejection is an entry that a probe did not use.
type DetectorRejection struct {
	// Index is the position in the table, ID the entry's id as given.
	Index  int    `json:"index"`
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason"`
}
