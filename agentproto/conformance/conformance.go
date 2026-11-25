// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package conformance checks a channel adapter that converts the DTOs of
// the agent protocol to its own form (for example protobuf messages).
//
// An adapter is correct when converting a DTO to its form and back gives a
// value with the same JSON encoding, the form the built-in HTTP channel
// carries. Run builds samples of every DTO the operations of agentproto.API
// carry, with every field set and with boundary values, and checks that.
// Run it in the adapter's tests; when the DTOs gain fields, the samples do
// too, and an adapter that drops them fails.
//
//	func TestAdapter(t *testing.T) {
//		conformance.Run(t, func(v any) (any, error) {
//			msg, err := toProto(v)
//			if err != nil {
//				return nil, err
//			}
//			b, err := proto.Marshal(msg)
//			...
//			return fromProto(b)
//		})
//	}
package conformance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bomcensus/bomcensus/agentproto"
	"github.com/bomcensus/bomcensus/agentproto/dto"
)

// RoundTrip converts a DTO (a pointer to it) to
// the channel's form and back, returning a new pointer of the same type.
type RoundTrip func(v any) (any, error)

// Sample is one value Run checks.
type Sample struct {
	// Name describes the sample ("PollRequest/full").
	Name  string
	Value any
}

// Samples returns the values Run checks: for every DTO type used by an
// operation (and dto.Error), a full value with every field set, the zero
// value, and a value whose optional fields point to zero values.
func Samples() []Sample {
	var out []Sample
	for _, t := range Types() {
		name := t.Name()
		out = append(out,
			Sample{Name: name + "/full", Value: fill(t, fullValues).Addr().Interface()},
			Sample{Name: name + "/zero", Value: reflect.New(t).Interface()},
			Sample{Name: name + "/present-zero", Value: fill(t, presentZeroValues).Addr().Interface()},
		)
		for i, v := range unionVariants(t) {
			out = append(out, Sample{Name: fmt.Sprintf("%s/variant-%d", name, i), Value: v})
		}
	}
	return out
}

// Types returns the DTO types the operations of agentproto.API carry, and
// dto.Error, sorted by name.
func Types() []reflect.Type {
	dtoPkg := reflect.TypeFor[dto.Error]().PkgPath()
	seen := map[reflect.Type]bool{reflect.TypeFor[dto.Error](): true}
	add := func(t reflect.Type) {
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() == reflect.Struct && t.PkgPath() == dtoPkg {
			seen[t] = true
		}
	}
	api := reflect.TypeFor[agentproto.API]()
	for i := range api.NumMethod() {
		m := api.Method(i).Type
		for j := range m.NumIn() {
			add(m.In(j))
		}
		for j := range m.NumOut() {
			add(m.Out(j))
		}
	}
	var out []reflect.Type
	for t := range seen {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b reflect.Type) int { return strings.Compare(a.Name(), b.Name()) })
	return out
}

// Check runs rt on every sample and returns the samples that failed.
func Check(rt RoundTrip) []error {
	var errs []error
	for _, s := range Samples() {
		if err := checkOne(rt, s); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, err))
		}
	}
	return errs
}

// Run checks rt and reports every failing sample.
func Run(t testing.TB, rt RoundTrip) {
	t.Helper()
	for _, err := range Check(rt) {
		t.Error(err)
	}
}

func checkOne(rt RoundTrip, s Sample) error {
	want, err := json.Marshal(s.Value)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	back, err := rt(s.Value)
	if err != nil {
		return fmt.Errorf("round trip: %w", err)
	}
	if reflect.TypeOf(back) != reflect.TypeOf(s.Value) {
		return fmt.Errorf("round trip returned %T, want %T", back, s.Value)
	}
	got, err := json.Marshal(back)
	if err != nil {
		return fmt.Errorf("encode after round trip: %w", err)
	}
	if string(got) != string(want) {
		return fmt.Errorf("value changed\n got %s\nwant %s", got, want)
	}
	return nil
}

type mode int

const (
	fullValues mode = iota
	presentZeroValues
)

var (
	timeType      = reflect.TypeFor[time.Time]()
	marshalerType = reflect.TypeFor[json.Marshaler]()
	sampleTime    = time.Date(2026, 11, 26, 1, 2, 3, 456789000, time.UTC)
)

// fill returns a value of t with every field set (fullValues) or with
// pointers to zero values and empty slices and maps (presentZeroValues).
func fill(t reflect.Type, m mode) reflect.Value {
	v := reflect.New(t).Elem()
	fillValue(v, m, 0)
	return v
}

func fillValue(v reflect.Value, m mode, depth int) {
	t := v.Type()
	if depth > 8 {
		return
	}
	if t == timeType {
		if m == fullValues {
			v.Set(reflect.ValueOf(sampleTime))
		}
		return
	}
	if variants := unionVariants(t); len(variants) > 0 {
		if m == fullValues {
			v.Set(reflect.ValueOf(variants[0]).Elem())
		}
		return
	}
	switch t.Kind() {
	case reflect.Pointer:
		p := reflect.New(t.Elem())
		switch {
		case m == fullValues || t.Elem().Kind() == reflect.Struct:
			fillValue(p.Elem(), m, depth+1)
		case t.Elem().Kind() == reflect.Slice:
			// A pointer to a nil slice is null in JSON, which decodes
			// to a nil pointer; present means empty.
			p.Elem().Set(reflect.MakeSlice(t.Elem(), 0, 0))
		case t.Elem().Kind() == reflect.Map:
			p.Elem().Set(reflect.MakeMap(t.Elem()))
		}
		v.Set(p)
	case reflect.Struct:
		for i := range t.NumField() {
			if t.Field(i).IsExported() {
				fillValue(v.Field(i), m, depth+1)
			}
		}
	case reflect.Slice:
		if m != fullValues {
			return
		}
		s := reflect.MakeSlice(t, 2, 2)
		for i := range 2 {
			fillValue(s.Index(i), m, depth+1)
		}
		if t.Elem().Kind() == reflect.Uint8 {
			s.Index(0).SetUint(0xfe)
			s.Index(1).SetUint(0x01)
		}
		v.Set(s)
	case reflect.Map:
		if m != fullValues {
			return
		}
		mp := reflect.MakeMap(t)
		for _, k := range []string{"k1", "k2"} {
			e := reflect.New(t.Elem()).Elem()
			fillValue(e, m, depth+1)
			mp.SetMapIndex(reflect.ValueOf(k).Convert(t.Key()), e)
		}
		v.Set(mp)
	case reflect.String:
		if m == fullValues {
			v.SetString(enumOr(t, "s<&>é"))
		}
	case reflect.Bool:
		if m == fullValues {
			v.SetBool(true)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if m == fullValues {
			v.SetInt(-7)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if m == fullValues {
			v.SetUint(7)
		}
	case reflect.Float32, reflect.Float64:
		if m == fullValues {
			v.SetFloat(0.25)
		}
	}
}

// enumOr returns the first value of a string enum type from dto (types
// with constants of the same type), or def.
func enumOr(t reflect.Type, def string) string {
	if e, ok := enums[t]; ok && len(e) > 0 {
		return e[0]
	}
	return def
}

// unionVariants returns one value of t per oneOf variant, for the dto
// union types (FromXxx methods), each built from a full variant value.
func unionVariants(t reflect.Type) []any {
	if t.Kind() != reflect.Struct || !reflect.PointerTo(t).Implements(marshalerType) {
		return nil
	}
	pt := reflect.PointerTo(t)
	var out []any
	for i := range pt.NumMethod() {
		mth := pt.Method(i)
		if !strings.HasPrefix(mth.Name, "From") || mth.Type.NumIn() != 2 || mth.Type.NumOut() != 1 {
			continue
		}
		arg := fill(mth.Type.In(1), fullValues)
		p := reflect.New(t)
		res := mth.Func.Call([]reflect.Value{p, arg})
		if !res[0].IsNil() {
			continue
		}
		out = append(out, p.Interface())
	}
	return out
}
