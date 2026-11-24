// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package gosymbol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const libSrc = `package lib

func Small(x int) int { return x + 1 }

//go:noinline
func Big() int {
	s := 0
	for i := 0; i < 10; i++ {
		s += i
	}
	return s
}

type T struct{ n int }

//go:noinline
func (t *T) Method() { t.n++ }

//go:noinline
func Map[E any](s []E) []E { return append(s[:0:0], s...) }

func Unused() int { return 42 }

func Closure() func() int {
	n := 0
	return func() int { n++; return n }
}
`

const mainSrc = `package main

import (
	"fmt"
	"os"

	"example.com/app/lib"
)

func main() {
	var t lib.T
	t.Method()
	// A constant argument would fold the inlined call away entirely.
	fmt.Println(lib.Small(len(os.Args)), lib.Big(), lib.Map([]int{1}), lib.Closure()())
}
`

// build compiles the test program with a toolchain ("" for the local one)
// for goos with a build mode and linker flags.
func build(t *testing.T, toolchain, goos, mode, ldflags string) string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain")
	}
	dir := t.TempDir()
	for name, src := range map[string]string{
		"go.mod":     "module example.com/app\n\ngo 1.18\n",
		"main.go":    mainSrc,
		"lib/lib.go": libSrc,
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "app")
	cmd := exec.Command(gobin, "build", "-trimpath", "-buildmode="+mode, "-ldflags="+ldflags, "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off")
	if toolchain != "" {
		cmd.Env = append(cmd.Env, "GOTOOLCHAIN="+toolchain)
	}
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	return out
}

func open(t *testing.T, path string) *Binary {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestLookup builds with the local toolchain. The table layout differs for
// Go 1.18-1.19, 1.20-1.21 and later; GOSYMBOL_TOOLCHAINS adds toolchains to
// build with, for example "go1.18.10 go1.20.14" (downloaded by the go command).
func TestLookup(t *testing.T) {
	toolchains := append([]string{""}, strings.Fields(os.Getenv("GOSYMBOL_TOOLCHAINS"))...)
	for _, toolchain := range toolchains {
		// Stripped binaries have no go:func.* symbol; position-independent
		// ones keep the module data pointers in relocations (ELF) or at
		// their preferred addresses (PE).
		for _, tc := range []struct{ goos, mode, ldflags string }{
			{"linux", "exe", ""},
			{"linux", "exe", "-s -w"},
			{"linux", "pie", ""},
			{"linux", "pie", "-s -w"},
			{"windows", "exe", ""},
			{"windows", "exe", "-s -w"},
			{"windows", "pie", "-s -w"},
		} {
			t.Run(strings.TrimSpace(toolchain+" "+tc.goos+" "+tc.mode+" "+tc.ldflags), func(t *testing.T) {
				testLookup(t, open(t, build(t, toolchain, tc.goos, tc.mode, tc.ldflags)), true)
			})
		}
	}
}

func testLookup(t *testing.T, b *Binary, inline bool) {
	const lib = "example.com/app/lib."
	if b.InlineKnown() != inline {
		t.Fatalf("inline known %v, want %v", b.InlineKnown(), inline)
	}
	missing := Absent
	if !inline {
		missing = NotChecked
	}
	for name, want := range map[string]Result{
		lib + "Big":          Present,
		lib + "T.Method":     Present, // as the vulnerability database writes it
		lib + "(*T).Method":  Present,
		lib + "Map":          Present, // generic, instantiated
		"runtime.main":       Present,
		lib + "Unused":       missing, // dead code, eliminated
		"net/http.Serve":     missing,
		"example.com/app.no": missing,
	} {
		if got := b.Lookup(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
	// Inlined calls are only visible through the inline trees. Without
	// them they must never be reported absent.
	for _, name := range []string{lib + "Small", lib + "Closure", "fmt.Println"} {
		got := b.Lookup(name)
		if got != Present && (inline || got != NotChecked) {
			t.Errorf("%s: %s", name, got)
		}
	}
	if inline && b.Lookup(lib+"Small") != Present {
		t.Errorf("inlined %sSmall not found", lib)
	}
}

// Without the inline trees a name missing from the table is not checked.
func TestInlineUnknown(t *testing.T) {
	b := &Binary{funcs: map[string]bool{"pkg.F": true}}
	if b.Lookup("pkg.F") != Present || b.Lookup("pkg.(*T).G") != NotChecked {
		t.Error("lookup without inline trees")
	}
	b.inlineKnown = true
	if b.Lookup("pkg.(*T).G") != Absent {
		t.Error("lookup with inline trees")
	}
}

func TestNotGo(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("hello"), []byte("\x7fELFgarbage-garbage-garbage-garbage"), []byte("MZ\x00\x00")} {
		if _, err := Open(bytes.NewReader(data)); err == nil {
			t.Errorf("%q: opened", data)
		}
	}
	// A C-like ELF without a Go table: the test binary of this package is
	// Go, so use /bin/sh when present.
	if f, err := os.Open("/bin/sh"); err == nil {
		defer f.Close()
		if _, err := Open(f); !errors.Is(err, ErrNotGo) {
			t.Errorf("/bin/sh: %v", err)
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"net/http.(*Server).Serve":         "net/http.Server.Serve",
		"pkg.Map[...]":                     "pkg.Map",
		"pkg.(*List[...]).Push":            "pkg.List.Push",
		"vendor/golang.org/x/net/http2.F":  "golang.org/x/net/http2.F",
		"cmd/vendor/golang.org/x/mod/a.F":  "golang.org/x/mod/a.F",
		"golang.org/x/net/http2.Server.Do": "golang.org/x/net/http2.Server.Do",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"pkg.F.func1":     "pkg.F",
		"pkg.F.func1.2":   "pkg.F",
		"pkg.F.gowrap3":   "pkg.F",
		"pkg.T.M-fm":      "pkg.T.M",
		"pkg.function1":   "pkg.function1",
		"pkg.F":           "pkg.F",
		"pkg.F.deferwrap": "pkg.F.deferwrap",
	} {
		if got := closureBase(in); got != want {
			t.Errorf("closure %s: %s, want %s", in, got, want)
		}
	}
}

func FuzzOpen(f *testing.F) {
	f.Add([]byte("\x7fELF"))
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Open(bytes.NewReader(data))
		if err == nil {
			b.Lookup("main.main")
		}
	})
}

// FuzzTable feeds the table and inline tree parser directly.
func FuzzTable(f *testing.F) {
	hdr := func(m uint32) []byte {
		b := make([]byte, 8+8*8+64)
		binary.LittleEndian.PutUint32(b, m)
		b[6], b[7] = 1, 8
		binary.LittleEndian.PutUint64(b[8:], 1)
		return b
	}
	f.Add(hdr(magic120))
	f.Add(hdr(magic118))
	f.Fuzz(func(t *testing.T, data []byte) {
		img := &image{order: binary.LittleEndian, gofunc: 1, read: func(addr uint64, n int) ([]byte, error) {
			if addr >= uint64(len(data)) {
				return nil, ErrNotGo
			}
			return data[addr:min(uint64(len(data)), addr+uint64(n))], nil
		}}
		if b, err := parse(img, data); err == nil {
			b.Lookup("main.main")
		}
	})
}
