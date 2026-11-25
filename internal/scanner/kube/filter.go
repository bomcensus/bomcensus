// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"fmt"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/bomcensus/bomcensus/agentproto/dto"
)

// Filter selects the workloads of a cluster (ARCH 4.3).
//
// Namespace rules are globs (path.Match syntax). Label rules are Kubernetes
// label selectors ("app=web", "tier", "!canary", "env in (prod,stage)"; a
// comma inside one rule means all of its terms). Annotation rules are
// "key=value" or "key" (present with any value).
//
// Evaluation order: namespace include, namespace exclude, label/annotation
// include, label/annotation exclude. The first step that fails decides the
// reason, so an exclude always wins over an include. An empty include list
// matches everything. Label and annotation includes form one step: when
// either list is non-empty the workload must match at least one rule of
// either list.
type Filter struct {
	NamespaceInclude  []string
	NamespaceExclude  []string
	LabelInclude      []string
	LabelExclude      []string
	AnnotationInclude []string
	AnnotationExclude []string
}

// FilterFromAPI converts the directive filter.
func FilterFromAPI(f dto.K8sFilter) Filter {
	return Filter{
		NamespaceInclude:  f.NamespaceInclude,
		NamespaceExclude:  f.NamespaceExclude,
		LabelInclude:      f.LabelInclude,
		LabelExclude:      f.LabelExclude,
		AnnotationInclude: f.AnnotationInclude,
		AnnotationExclude: f.AnnotationExclude,
	}
}

type labelRule struct {
	text string
	sel  labels.Selector
}

type annotationRule struct {
	text       string
	key, value string
	anyValue   bool
}

func (r annotationRule) matches(a map[string]string) bool {
	v, ok := a[r.key]
	return ok && (r.anyValue || v == r.value)
}

type compiledFilter struct {
	nsInclude, nsExclude []string
	labelInclude         []labelRule
	labelExclude         []labelRule
	annotationInclude    []annotationRule
	annotationExclude    []annotationRule
}

func compileFilter(f Filter) (*compiledFilter, error) {
	c := &compiledFilter{}
	for _, list := range []struct {
		in  []string
		out *[]string
	}{{f.NamespaceInclude, &c.nsInclude}, {f.NamespaceExclude, &c.nsExclude}} {
		for _, p := range list.in {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, err := path.Match(p, ""); err != nil {
				return nil, fmt.Errorf("kube: filter: namespace pattern %q: %w", p, err)
			}
			*list.out = append(*list.out, p)
		}
	}
	var err error
	if c.labelInclude, err = compileLabels(f.LabelInclude); err != nil {
		return nil, err
	}
	if c.labelExclude, err = compileLabels(f.LabelExclude); err != nil {
		return nil, err
	}
	if c.annotationInclude, err = compileAnnotations(f.AnnotationInclude); err != nil {
		return nil, err
	}
	if c.annotationExclude, err = compileAnnotations(f.AnnotationExclude); err != nil {
		return nil, err
	}
	return c, nil
}

func compileLabels(in []string) ([]labelRule, error) {
	var out []labelRule
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		sel, err := labels.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("kube: filter: label selector %q: %w", s, err)
		}
		out = append(out, labelRule{text: s, sel: sel})
	}
	return out, nil
}

func compileAnnotations(in []string) ([]annotationRule, error) {
	var out []annotationRule
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		r := annotationRule{text: s}
		if k, v, ok := strings.Cut(s, "="); ok {
			r.key, r.value = strings.TrimSpace(k), strings.TrimSpace(v)
		} else {
			r.key, r.anyValue = s, true
		}
		if r.key == "" {
			return nil, fmt.Errorf("kube: filter: annotation condition %q has no key", s)
		}
		out = append(out, r)
	}
	return out, nil
}

// evaluate returns "" when the workload is included, otherwise the rule that
// excluded it.
func (c *compiledFilter) evaluate(namespace string, lbls, annotations map[string]string) string {
	if len(c.nsInclude) > 0 {
		matched := false
		for _, p := range c.nsInclude {
			if ok, _ := path.Match(p, namespace); ok {
				matched = true
				break
			}
		}
		if !matched {
			return "namespace_include: no pattern matched"
		}
	}
	for _, p := range c.nsExclude {
		if ok, _ := path.Match(p, namespace); ok {
			return "namespace_exclude: " + p
		}
	}
	set := labels.Set(lbls)
	if len(c.labelInclude) > 0 || len(c.annotationInclude) > 0 {
		matched := false
		for _, r := range c.labelInclude {
			if r.sel.Matches(set) {
				matched = true
				break
			}
		}
		for _, r := range c.annotationInclude {
			if matched {
				break
			}
			matched = r.matches(annotations)
		}
		if !matched {
			switch {
			case len(c.annotationInclude) == 0:
				return "label_include: no selector matched"
			case len(c.labelInclude) == 0:
				return "annotation_include: no condition matched"
			default:
				return "label_include, annotation_include: no rule matched"
			}
		}
	}
	for _, r := range c.labelExclude {
		if r.sel.Matches(set) {
			return "label_exclude: " + r.text
		}
	}
	for _, r := range c.annotationExclude {
		if r.matches(annotations) {
			return "annotation_exclude: " + r.text
		}
	}
	return ""
}
