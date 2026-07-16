//go:build !unix && !windows

package compose

import "os/exec"

// This file is the pkg/compose twin of pkg/discover/mcptools_other.go: it
// covers platforms that are neither unix nor windows, wasip1 being the one
// that matters in v0.1. The CI wasip1 build check compiles the whole pkg tree
// under GOOS=wasip1, so every package must compile there, including this one.
// wasip1 has no process group model and no process spawning at runtime, so
// these are compile only stubs: v0.1 never runs forgeseal on Wasm.

// prepareProcessGroup is a no-op where no process group model exists.
func prepareProcessGroup(_ *exec.Cmd) {}

// killProcessTree falls back to killing the immediate process. On a platform
// without process spawning this path is compiled but never exercised.
func killProcessTree(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
