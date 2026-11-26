// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package detectors

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/bomcensus/bomcensus/internal/report"
)

// Entry is one detector of a resolved table.
type Entry struct {
	// Spec is the entry as it is used: without its version command when
	// the command may not run.
	Spec report.DetectorSpec
	// Builtin is set when the entry is identical to an entry of the
	// built-in table. Other entries are constrained: their side files
	// avoid DeniedPath and are opened without following symbolic links,
	// and the versions and builds they capture must be ValidCaptured.
	Builtin bool
	// Exec is set when the version command may run: the entry has one and
	// its exec fields are those of the built-in entry with the same id.
	Exec bool
}

// Resolved is a table as a probe uses it.
type Resolved struct {
	Entries []Entry
	// Use is what the probe reports (report.Report.Detectors).
	Use report.DetectorUse
}

// ResolveBuiltin returns the built-in table, every entry trusted.
func ResolveBuiltin() Resolved {
	t := Builtin()
	r := Resolved{Use: report.DetectorUse{Digest: BuiltinDigest(), Source: report.DetectorsBuiltin}}
	for _, d := range t.Detectors {
		r.Entries = append(r.Entries, Entry{Spec: d, Builtin: true, Exec: len(d.Exec) > 0})
	}
	return r
}

// Resolve decides what a probe takes from t (SECURITY.md, detector tables):
//
//   - a nil table, or one that cannot be used as a whole (schema version,
//     size, number of entries), gives the built-in table; Use.Error says
//     why when t was not nil
//   - an entry identical to a built-in entry is used as it is
//   - the version command of any other entry runs only when its id, names,
//     paths, archive flag, exec arguments, environment and address space
//     limit equal those of the built-in entry with the same id; otherwise
//     the command and its parse rules are removed (Use.StaticOnly)
//   - every other entry is checked with the constrained rules (checkSpec);
//     an entry that fails, or repeats an id, is dropped (Use.Rejected)
//
// The order of the entries is kept.
func Resolve(t *report.DetectorTable) Resolved {
	if t == nil {
		return ResolveBuiltin()
	}
	digest, err := Digest(t)
	if err == nil {
		err = checkTable(t)
	}
	if err != nil {
		r := ResolveBuiltin()
		r.Use.Error = err.Error()
		return r
	}
	r := Resolved{Use: report.DetectorUse{Digest: digest, Source: report.DetectorsRequest}}
	seen := map[string]bool{}
	for i, d := range t.Detectors {
		reject := func(reason string) {
			r.Use.Rejected = append(r.Use.Rejected, report.DetectorRejection{Index: i, ID: clip(d.ID, MaxIDLen), Reason: reason})
		}
		if seen[d.ID] {
			reject("duplicate id")
			continue
		}
		seen[d.ID] = true
		base := builtinByID(d.ID)
		if base != nil && reflect.DeepEqual(normalize(d), normalize(*base)) {
			r.Entries = append(r.Entries, Entry{Spec: d, Builtin: true, Exec: len(d.Exec) > 0})
			continue
		}
		e := Entry{Spec: d}
		hasExec := len(d.Exec) > 0 || len(d.Env) > 0 || len(d.Parse) > 0 || d.AddressSpaceMB != 0
		switch {
		case base != nil && len(d.Exec) > 0 && sameExec(d, *base):
			e.Exec = true
		case hasExec:
			e.Spec.Exec, e.Spec.Env, e.Spec.Parse, e.Spec.AddressSpaceMB = nil, nil, nil, 0
		}
		// The entry as given is checked, so that limits apply to the
		// fields that were removed too.
		if err := checkSpec(&d, true); err != nil {
			reject(err.Error())
			continue
		}
		if !e.Exec && len(e.Spec.Static) == 0 {
			reject("its version command differs from the built-in detector with this id, so it may not run, and it has no static rules")
			continue
		}
		if !e.Exec && len(d.Exec) > 0 {
			r.Use.StaticOnly = append(r.Use.StaticOnly, d.ID)
		}
		r.Entries = append(r.Entries, e)
	}
	return r
}

func checkTable(t *report.DetectorTable) error {
	if t.SchemaVersion != report.DetectorSchemaVersion {
		return fmt.Errorf("schema_version %d is not supported (want %d)", t.SchemaVersion, report.DetectorSchemaVersion)
	}
	if len(t.Detectors) > MaxDetectors {
		return fmt.Errorf("%d detectors, at most %d", len(t.Detectors), MaxDetectors)
	}
	b, err := Encode(t)
	if err != nil {
		return err
	}
	if len(b) > MaxJSONSize {
		return fmt.Errorf("table of %d bytes, at most %d", len(b), MaxJSONSize)
	}
	return nil
}

// sameExec compares the fields that decide what a version command runs.
// Parse rules only read its output and are not compared.
func sameExec(a, b report.DetectorSpec) bool {
	return a.ID == b.ID && slices.Equal(a.Names, b.Names) && slices.Equal(a.Paths, b.Paths) &&
		a.Archive == b.Archive && slices.Equal(a.Exec, b.Exec) && slices.Equal(a.Env, b.Env) &&
		a.AddressSpaceMB == b.AddressSpaceMB
}

// normalize makes empty and nil slices compare equal.
func normalize(d report.DetectorSpec) report.DetectorSpec {
	nilIfEmpty := func(s []string) []string {
		if len(s) == 0 {
			return nil
		}
		return s
	}
	d.Names, d.Paths, d.Exec = nilIfEmpty(d.Names), nilIfEmpty(d.Paths), nilIfEmpty(d.Exec)
	if len(d.Env) == 0 {
		d.Env = nil
	}
	if len(d.Parse) == 0 {
		d.Parse = nil
	}
	if len(d.Static) == 0 {
		d.Static = nil
	}
	st := make([]report.DetectorStatic, len(d.Static))
	for i, s := range d.Static {
		if len(s.Rules) == 0 {
			s.Rules = nil
		}
		st[i] = s
	}
	if d.Static != nil {
		d.Static = st
	}
	return d
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Problem is a reason why an administrator's table is not saved, or a
// note about how probes will use it.
type Problem struct {
	// Index is the position of the entry, -1 for the whole table.
	Index int
	ID    string
	// Warning is set for notes that do not stop the table from being
	// saved.
	Warning bool
	Message string
}

// Check parses and checks a table as the server does before saving it: the
// errors are what Resolve would drop, the warnings the detectors whose
// version command will not run. The table is returned when it parses.
func Check(yamlText []byte) (*report.DetectorTable, []Problem) {
	t, err := Parse(yamlText)
	if err != nil {
		return nil, []Problem{{Index: -1, Message: err.Error()}}
	}
	if err := checkTable(t); err != nil {
		return t, []Problem{{Index: -1, Message: err.Error()}}
	}
	if len(t.Detectors) == 0 {
		return t, []Problem{{Index: -1, Message: "the table has no detectors"}}
	}
	r := Resolve(t)
	var out []Problem
	for _, rj := range r.Use.Rejected {
		out = append(out, Problem{Index: rj.Index, ID: rj.ID, Message: rj.Reason})
	}
	for _, id := range r.Use.StaticOnly {
		idx := slices.IndexFunc(t.Detectors, func(d report.DetectorSpec) bool { return d.ID == id })
		out = append(out, Problem{Index: idx, ID: id, Warning: true,
			Message: "the version command differs from the built-in detector with this id and will not run; static rules only"})
	}
	slices.SortStableFunc(out, func(a, b Problem) int { return a.Index - b.Index })
	return t, out
}
