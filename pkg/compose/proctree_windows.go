//go:build windows

package compose

import (
	"os/exec"
	"strconv"
	"syscall"
)

// This file is the pkg/compose twin of pkg/discover/mcptools_windows.go: same
// process group teardown pattern, mirrored rather than shared. runForgeseal in
// forgeseal.go is the sole caller.

// prepareProcessGroup puts cmd's future process in a new process group before
// it starts (CREATE_NEW_PROCESS_GROUP), the Windows analogue of the unix
// Setpgid, so killProcessTree can target the launched command's descendants
// precisely rather than this process's own group.
func prepareProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// killProcessTree terminates cmd's process and every descendant it spawned.
// Process.Kill alone only terminates the immediate process; taskkill /T
// recurses the whole tree and ships with every supported Windows version.
func killProcessTree(cmd *exec.Cmd) error {
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
}
