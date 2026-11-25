// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package scope

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestOf(t *testing.T) {
	s := Of("b", "a", "b", "", "bad id", "-x")
	if !slices.Equal(s.IDs(), []string{"a", "b"}) || s.IsAll() || s.IsEmpty() {
		t.Fatalf("Of = %+v", s)
	}
	if !s.Contains("a") || s.Contains("c") || !All().Contains("c") {
		t.Fatal("Contains")
	}
	if !(Scope{}).IsEmpty() || !Of().IsEmpty() || All().IsEmpty() {
		t.Fatal("IsEmpty")
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()
	if _, err := Require(ctx); !errors.Is(err, ErrNone) {
		t.Fatalf("Require without scope: %v", err)
	}
	if s, err := Require(System(ctx)); err != nil || !s.IsAll() {
		t.Fatalf("System: %v %v", s, err)
	}
	if s, ok := From(With(ctx, Of("t1"))); !ok || !slices.Equal(s.IDs(), []string{"t1"}) {
		t.Fatalf("With: %v %v", s, ok)
	}
}

func TestResolve(t *testing.T) {
	for _, c := range []struct {
		s         Scope
		requested string
		want      string
		err       error
	}{
		{All(), "", Default, nil},
		{All(), "t9", "t9", nil},
		{Of("t1"), "", "t1", nil},
		{Of("t1", "t2"), "t2", "t2", nil},
		{Of("t1", "t2"), "", "", ErrOutside},
		{Of("t1"), "t2", "", ErrOutside},
		{Of("t1"), "bad id", "", ErrInvalidID},
		{Scope{}, "", "", ErrOutside},
	} {
		got, err := Resolve(c.s, c.requested)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("Resolve(%v, %q) = %q, %v; want %q, %v", c.s, c.requested, got, err, c.want, c.err)
		}
	}
}
