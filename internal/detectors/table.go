// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package detectors holds the known-software detector table as data: the
// built-in table (detectors.yaml, embedded here and copied into the manager
// Helm chart by make generate), its YAML and JSON forms, its digest and the
// rules that decide how much a probe trusts a table it did not build in
// (Resolve, SECURITY.md).
//
// The probe (internal/collect/artifact) turns a resolved table into its
// detectors; the server validates and distributes tables with the same
// code.
package detectors

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"sigs.k8s.io/yaml"

	"github.com/bomcensus/bomcensus/internal/report"
)

// Size bounds of a table.
const (
	// MaxYAMLSize bounds the YAML text an administrator saves.
	MaxYAMLSize = 512 << 10
	// MaxJSONSize bounds the JSON encoding of a table, as distributed.
	MaxJSONSize = 512 << 10
)

//go:embed detectors.yaml
var builtinYAML []byte

// BuiltinYAML returns the built-in table as YAML, with its comments.
func BuiltinYAML() []byte { return bytes.Clone(builtinYAML) }

var builtin = sync.OnceValues(func() (*report.DetectorTable, string) {
	t, err := Parse(builtinYAML)
	if err != nil {
		panic("detectors: built-in table: " + err.Error())
	}
	d, err := Digest(t)
	if err != nil {
		panic("detectors: built-in table: " + err.Error())
	}
	return t, d
})

// Builtin returns a copy of the built-in table.
func Builtin() *report.DetectorTable {
	t, _ := builtin()
	return Clone(t)
}

// BuiltinDigest returns the digest of the built-in table.
func BuiltinDigest() string {
	_, d := builtin()
	return d
}

// builtinByID returns the built-in entry with id, or nil.
func builtinByID(id string) *report.DetectorSpec {
	t, _ := builtin()
	for i := range t.Detectors {
		if t.Detectors[i].ID == id {
			return &t.Detectors[i]
		}
	}
	return nil
}

// Parse reads a table in YAML (or JSON, which is YAML). Unknown fields and
// duplicate keys are errors; so is a schema version other than
// report.DetectorSchemaVersion. The entries are not validated (see Check).
func Parse(data []byte) (*report.DetectorTable, error) {
	if len(data) > MaxYAMLSize {
		return nil, fmt.Errorf("detectors: table larger than %d bytes", MaxYAMLSize)
	}
	var t report.DetectorTable
	if err := yaml.UnmarshalStrict(data, &t); err != nil {
		return nil, fmt.Errorf("detectors: %w", err)
	}
	if err := checkSchema(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Decode reads the JSON form of a table (Encode).
func Decode(data []byte) (*report.DetectorTable, error) {
	if len(data) > MaxJSONSize {
		return nil, fmt.Errorf("detectors: table larger than %d bytes", MaxJSONSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var t report.DetectorTable
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("detectors: %w", err)
	}
	if dec.More() {
		return nil, errors.New("detectors: trailing data after the table")
	}
	if err := checkSchema(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

func checkSchema(t *report.DetectorTable) error {
	if t.SchemaVersion != report.DetectorSchemaVersion {
		return fmt.Errorf("detectors: schema_version %d is not supported (want %d)", t.SchemaVersion, report.DetectorSchemaVersion)
	}
	return nil
}

// Encode returns the JSON form of t. It is canonical: Digest is the
// SHA-256 of these bytes, and decoding and encoding them again gives the
// same bytes.
func Encode(t *report.DetectorTable) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(t); err != nil {
		return nil, fmt.Errorf("detectors: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// Digest returns the hex SHA-256 of Encode(t). Comments and the layout of
// the YAML do not change it.
func Digest(t *report.DetectorTable) (string, error) {
	return report.Digest(t)
}

// Clone returns a deep copy of t.
func Clone(t *report.DetectorTable) *report.DetectorTable {
	if t == nil {
		return nil
	}
	b, err := json.Marshal(t)
	if err != nil {
		panic(err)
	}
	var out report.DetectorTable
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return &out
}
