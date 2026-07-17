//go:build unix

package compose

import (
	"os/exec"
	"syscall"
)

// This file is the pkg/compose twin of pkg/discover/mcptools_unix.go: the two
// use the identical process group teardown pattern, kept as a mirror rather
// than a shared helper because exporting three lines across a package boundary
// buys nothing. runForgeseal in forgeseal.go is the sole caller.

// prepareProcessGroup puts cmd's future process in its own process group
// before it starts, so killProcessTree can signal the whole tree at once. A
// forgeseal invocation may itself fork children (a language toolchain it
// shells out to, for instance); killing only the immediate process would
// leave those orphaned.
func prepareProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree kills cmd's entire process group with SIGKILL. cmd must
// already have an assigned Process (Start must have succeeded) and must have
// been prepared with prepareProcessGroup before starting.
func killProcessTree(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
