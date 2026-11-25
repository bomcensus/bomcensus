// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"testing"

	"github.com/bomcensus/bomcensus/agentproto/dto"
)

func TestFilterEvaluationOrder(t *testing.T) {
	lbl := map[string]string{"app": "web", "env": "prod"}
	ann := map[string]string{"bomcensus.io/scan": "true", "owner": "team-a"}
	cases := []struct {
		name string
		f    Filter
		ns   string
		want string
	}{
		{"empty filter includes", Filter{}, "app", ""},
		{"namespace include glob", Filter{NamespaceInclude: []string{"ap?", "other"}}, "app", ""},
		{"namespace include miss", Filter{NamespaceInclude: []string{"prod-*"}}, "app", "namespace_include: no pattern matched"},
		{"namespace exclude", Filter{NamespaceExclude: []string{"kube-*"}}, "kube-system", "namespace_exclude: kube-*"},
		{"namespace exclude wins over include", Filter{NamespaceInclude: []string{"*"}, NamespaceExclude: []string{"app"}}, "app", "namespace_exclude: app"},
		{"namespace include checked before exclude", Filter{NamespaceInclude: []string{"x"}, NamespaceExclude: []string{"app"}}, "app", "namespace_include: no pattern matched"},
		{"namespace exclude before label include", Filter{NamespaceExclude: []string{"app"}, LabelInclude: []string{"app=other"}}, "app", "namespace_exclude: app"},
		{"label include", Filter{LabelInclude: []string{"app=web"}}, "app", ""},
		{"label include set-based", Filter{LabelInclude: []string{"env in (prod,stage),app"}}, "app", ""},
		{"label include miss", Filter{LabelInclude: []string{"app=db", "!env"}}, "app", "label_include: no selector matched"},
		{"annotation include key only", Filter{AnnotationInclude: []string{"bomcensus.io/scan"}}, "app", ""},
		{"annotation include miss", Filter{AnnotationInclude: []string{"owner=team-b"}}, "app", "annotation_include: no condition matched"},
		{"label or annotation include", Filter{LabelInclude: []string{"app=db"}, AnnotationInclude: []string{"owner=team-a"}}, "app", ""},
		{"label and annotation include miss", Filter{LabelInclude: []string{"app=db"}, AnnotationInclude: []string{"owner=team-b"}}, "app", "label_include, annotation_include: no rule matched"},
		{"label exclude wins over include", Filter{LabelInclude: []string{"app=web"}, LabelExclude: []string{"env=prod"}}, "app", "label_exclude: env=prod"},
		{"annotation exclude wins over include", Filter{AnnotationInclude: []string{"owner"}, AnnotationExclude: []string{"bomcensus.io/scan=true"}}, "app", "annotation_exclude: bomcensus.io/scan=true"},
		{"annotation exclude value mismatch", Filter{AnnotationExclude: []string{"bomcensus.io/scan=false"}}, "app", ""},
		{"include miss reported before exclude", Filter{LabelInclude: []string{"app=db"}, LabelExclude: []string{"env=prod"}}, "app", "label_include: no selector matched"},
		{"blank rules ignored", Filter{NamespaceInclude: []string{" "}, LabelInclude: []string{""}}, "app", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cf, err := compileFilter(c.f)
			if err != nil {
				t.Fatal(err)
			}
			if got := cf.evaluate(c.ns, lbl, ann); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestFilterInvalid(t *testing.T) {
	for _, f := range []Filter{
		{NamespaceInclude: []string{"[a-"}},
		{LabelExclude: []string{"a in (b"}},
		{AnnotationInclude: []string{"=v"}},
	} {
		if _, err := compileFilter(f); err == nil {
			t.Errorf("%+v: no error", f)
		}
	}
}

func TestFilterFromAPI(t *testing.T) {
	f := FilterFromAPI(dto.K8sFilter{NamespaceInclude: []string{"a"}, NamespaceExclude: []string{"b"}, LabelInclude: []string{"c"},
		LabelExclude: []string{"d"}, AnnotationInclude: []string{"e"}, AnnotationExclude: []string{"f"}})
	if f.NamespaceInclude[0] != "a" || f.NamespaceExclude[0] != "b" || f.LabelInclude[0] != "c" ||
		f.LabelExclude[0] != "d" || f.AnnotationInclude[0] != "e" || f.AnnotationExclude[0] != "f" {
		t.Errorf("%+v", f)
	}
}
