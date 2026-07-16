//go:build !unix && !windows

package discover

import "os/exec"

// This file covers platforms that are neither unix nor windows, the one that
// matters in v0.1 being wasip1. sigstore-go pins signing to native builds
// (spec 2.1), and the CI wasip1 build check compiles the whole pkg tree under
// GOOS=wasip1 to prove that isolation holds; for that check to pass, every
// package must compile there, including this one. wasip1 has no process group
// model and no process spawning at runtime, so these are compile only stubs:
// v0.1 never runs ExtractTools on Wasm.

// prepareProcessGroup is a no-op where no process group model exists.
func prepareProcessGroup(_ *exec.Cmd) {}

// killProcessTree falls back to killing the immediate process. On a platform
// without process spawning this path is compiled but never exercised.
func killProcessTree(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
