//go:build !windows

package discover

import (
	"os/exec"
	"syscall"
)

// prepareProcessGroup puts cmd's future process in its own process group
// before it starts. The command a maker configures (for example "npx
// some-server" or, as this package's own test fixture does, "go run
// ./testdata/fakemcp") commonly forks a real child process distinct from the
// process ExtractTools started directly; killing only that immediate
// process would leave the real MCP server running, orphaned. Putting it in
// its own group lets killProcessTree target the whole tree with one signal.
func prepareProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree kills cmd's entire process group with SIGKILL. cmd must
// already have an assigned Process (Start must have succeeded) and must have
// been prepared with prepareProcessGroup before starting.
func killProcessTree(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
