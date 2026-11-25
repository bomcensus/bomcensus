// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package conformance

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/bomcensus/bomcensus/agentproto/dto"
)

// viaJSON is a lossless adapter: plain encoding/json.
func viaJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := reflect.New(reflect.TypeOf(v).Elem()).Interface()
	return out, json.Unmarshal(b, out)
}

func TestLosslessAdapterPasses(t *testing.T) {
	Run(t, viaJSON)
	if n := len(Samples()); n < 3*len(Types()) {
		t.Fatalf("%d samples for %d types", n, len(Types()))
	}
}

func TestLossyAdapterFails(t *testing.T) {
	// Drops the poll request's version, as an adapter missing a field
	// would.
	lossy := func(v any) (any, error) {
		out, err := viaJSON(v)
		if p, ok := out.(*dto.PollRequest); ok {
			p.Version = ""
		}
		return out, err
	}
	errs := Check(lossy)
	if len(errs) == 0 || !strings.Contains(errs[0].Error(), "PollRequest/full") {
		t.Fatalf("lossy adapter: %v", errs)
	}
}

func TestSamplesAreFull(t *testing.T) {
	for _, s := range Samples() {
		if !strings.HasSuffix(s.Name, "/full") {
			continue
		}
		b, _ := json.Marshal(s.Value)
		if strings.Contains(string(b), `""`) && !strings.Contains(s.Name, "Error") {
			// Every string field of a full sample is set.
			t.Errorf("%s has empty strings: %s", s.Name, b)
		}
	}
}
