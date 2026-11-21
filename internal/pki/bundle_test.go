// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func testBundle(t *testing.T) *TrustBundle {
	t.Helper()
	return &TrustBundle{
		Version: 7,
		Anchors: []*x509.Certificate{newTestCA(t).Cert, newTestCA(t).Cert},
		AgentCA: newTestCA(t).Cert,
	}
}

func equalBundle(t *testing.T, got, want *TrustBundle) {
	t.Helper()
	if got.Version != want.Version || len(got.Anchors) != len(want.Anchors) || !got.AgentCA.Equal(want.AgentCA) {
		t.Fatalf("bundle mismatch: %+v vs %+v", got, want)
	}
	for i := range want.Anchors {
		if !got.Anchors[i].Equal(want.Anchors[i]) {
			t.Fatalf("anchor %d differs", i)
		}
	}
}

func TestTrustBundleJSON(t *testing.T) {
	b := testBundle(t)
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version":7`) || !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatalf("unexpected JSON: %s", data)
	}
	var back TrustBundle
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	equalBundle(t, &back, b)
	if !back.HasAnchor(SPKIHash(b.Anchors[1])) || back.HasAnchor(SPKIHash(b.AgentCA)) {
		t.Fatal("HasAnchor")
	}

	bad := []string{
		`{"version":1,"anchors":[],"agent_ca":""}`,
		`{"version":1,"anchors":["x"],"agent_ca":""}`,
		`{"version":-1}`,
		`[]`,
	}
	for _, s := range bad {
		var v TrustBundle
		if err := json.Unmarshal([]byte(s), &v); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	// A leaf as Agent CA is refused.
	leafCA := *b
	c := newTestChain(t, chainOpts{})
	leafCA.AgentCA = c.leaf
	if _, err := json.Marshal(leafCA); err == nil {
		t.Fatal("leaf accepted as Agent CA")
	}
}

func TestTrustBundlePEM(t *testing.T) {
	b := testBundle(t)
	data, err := b.EncodePEM()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeTrustBundlePEM(data)
	if err != nil {
		t.Fatal(err)
	}
	equalBundle(t, back, b)

	block := func(role, ver string, der []byte) []byte {
		h := map[string]string{}
		if role != "" {
			h[bundleRoleHeader] = role
		}
		if ver != "" {
			h[bundleVersionHeader] = ver
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: h, Bytes: der})
	}
	a, ca := b.Anchors[0].Raw, b.AgentCA.Raw
	cases := map[string][]byte{
		"no anchor":            block(roleAgentCA, "1", ca),
		"no agent CA":          block(roleAnchor, "1", a),
		"two agent CAs":        bytes.Join([][]byte{block(roleAnchor, "1", a), block(roleAgentCA, "1", ca), block(roleAgentCA, "1", ca)}, nil),
		"inconsistent version": bytes.Join([][]byte{block(roleAnchor, "1", a), block(roleAgentCA, "2", ca)}, nil),
		"missing version":      bytes.Join([][]byte{block(roleAnchor, "", a), block(roleAgentCA, "", ca)}, nil),
		"unknown role":         bytes.Join([][]byte{block("other", "1", a), block(roleAgentCA, "1", ca)}, nil),
		"other block":          append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), data...),
		"trailing garbage":     append(append([]byte(nil), data...), "garbage"...),
		"empty":                nil,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTrustBundlePEM(in); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
