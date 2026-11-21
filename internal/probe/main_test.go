// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package probe

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bomcensus/bomcensus/internal/collect/artifact"
)

// sandboxChildEnv makes the test binary run one sandbox check program
// instead of the tests (see sandbox_test.go).
const sandboxChildEnv = "BOMCENSUS_PROBE_SANDBOX_CHILD"

func TestMain(m *testing.M) {
	artifact.MaybeRunExecHelper()
	if name := os.Getenv(sandboxChildEnv); name != "" {
		os.Exit(runSandboxChild(name))
	}
	os.Exit(m.Run())
}

var (
	goBinOnce sync.Once
	goBinPath string
	goBinErr  error
)

const goToolSource = `package main

import "fmt"

func main() { fmt.Println("gotool 1.0") }
`

// buildGoTool builds a small Go program once. It needs no module downloads.
func buildGoTool(t *testing.T) string {
	t.Helper()
	goBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "probe-gotool-")
		if err != nil {
			goBinErr = err
			return
		}
		for name, content := range map[string]string{"main.go": goToolSource, "go.mod": "module example.com/gotool\n\ngo 1.22\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				goBinErr = err
				return
			}
		}
		goBinPath = filepath.Join(dir, "gotool")
		cmd := exec.Command("go", "build", "-o", goBinPath, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			goBinErr = &buildError{out: string(out), err: err}
		}
	})
	if goBinErr != nil {
		t.Skipf("cannot build Go test binary: %v", goBinErr)
	}
	return goBinPath
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + ": " + e.out }
