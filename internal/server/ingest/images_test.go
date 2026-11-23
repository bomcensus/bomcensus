// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package ingest

import (
	"reflect"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/internal/report"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// The containers section replaces the image tags of the host only when its
// inventory was collected in full.
func TestHostImageTagsFollowCoverage(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	must(t, f.ingest(t, f.agent, hostReport(t0)))
	tags := func(what string, cur []string, prev []store.PreviousTag) {
		t.Helper()
		im, err := f.db.GetImage(ctx, img1)
		must(t, err)
		if prev == nil {
			prev = []store.PreviousTag{}
		}
		if !reflect.DeepEqual(im.Tags, cur) || !reflect.DeepEqual(im.PreviousTags, prev) {
			t.Fatalf("%s: tags %v previous %+v", what, im.Tags, im.PreviousTags)
		}
	}
	tags("first report", []string{"nginx:1.25-alpine"}, nil)

	moved := func(at time.Time, cov report.Coverage) *report.Report {
		r := hostReport(at)
		r.Containers = &report.ContainersSection{SectionMeta: meta(at, cov), Runtimes: []string{"docker"},
			Images: []report.Image{{Digest: img2, RepoTags: []string{"nginx:1.25-alpine"}}}}
		return r
	}
	t1, t2 := t0.Add(time.Hour), t0.Add(2*time.Hour)
	must(t, f.ingest(t, f.agent, moved(t1, report.CoveragePartial)))
	tags("partial report", []string{"nginx:1.25-alpine"}, nil)
	// Only the content scan fell short: the inventory is complete.
	r := moved(t2, report.CoveragePartial)
	r.Containers.InventoryCoverage = report.CoverageFull
	must(t, f.ingest(t, f.agent, r))
	tags("partial content scan", []string{}, []store.PreviousTag{{Tag: "nginx:1.25-alpine", LastSeen: t0}})
}

// A container's image reference is not a tag of its digest: the tag may
// have been pulled again and point elsewhere now.
func TestHostImageTagsFromImageList(t *testing.T) {
	f := newFixture(t)
	r := hostReport(t0)
	r.Containers.Images = []report.Image{{Digest: img2, RepoTags: []string{"nginx:1.25-alpine"}}}
	must(t, f.ingest(t, f.agent, r))
	for _, c := range []struct {
		digest string
		tags   []string
	}{{img1, []string{}}, {img2, []string{"nginx:1.25-alpine"}}} {
		im, err := f.db.GetImage(f.ctx, c.digest)
		must(t, err)
		if !reflect.DeepEqual(im.Tags, c.tags) || len(im.PreviousTags) != 0 {
			t.Errorf("%s: tags %v previous %+v", c.digest, im.Tags, im.PreviousTags)
		}
	}
}
