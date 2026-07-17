//go:build windows

package discover

import (
	"os/exec"
	"strconv"
	"syscall"
)

// prepareProcessGroup puts cmd's future process in a new process group
// before it starts (CREATE_NEW_PROCESS_GROUP), the Windows analogue of the
// unix build's Setpgid: it isolates the launched command's descendants from
// this process's own group so killProcessTree can target them precisely.
func prepareProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// killProcessTree terminates cmd's process and every descendant it spawned,
// for example "npx" or "go run" launching the real server as their own
// child. Process.Kill alone only terminates the immediate process, leaving
// such a child running, orphaned. taskkill /T recurses the whole tree and
// ships with every supported Windows version, so no extra dependency is
// needed to reach it.
func killProcessTree(cmd *exec.Cmd) error {
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
}
