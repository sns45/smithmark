package arch_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// Spec §2.1: pkg/core is pure. Direct imports of any pkg/core package must
// never include I/O packages. This test is the enforcement mechanism the
// spec calls the lint/test guard.
var forbidden = []string{"os", "os/exec", "io/fs", "path/filepath", "syscall", "net"}

type pkgInfo struct {
	ImportPath string
	Imports    []string
	GoFiles    []string
	Dir        string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("finding repo root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func corePackages(t *testing.T) []pkgInfo {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "./pkg/core/...")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list ./pkg/core/...: %v", err)
	}
	var pkgs []pkgInfo
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkgInfo
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("no packages under pkg/core; the core must exist")
	}
	return pkgs
}

func TestCoreImportsArePure(t *testing.T) {
	for _, p := range corePackages(t) {
		for _, imp := range p.Imports {
			// net/netip is pure address parsing with no sockets; explicitly allowed.
			if imp == "net/netip" {
				continue
			}
			for _, f := range forbidden {
				if imp == f || strings.HasPrefix(imp, f+"/") ||
					(f == "net" && strings.HasPrefix(imp, "net")) {
					t.Errorf("%s imports %s; pkg/core must stay pure (spec 2.1)", p.ImportPath, imp)
				}
			}
		}
	}
}

func TestCoreNeverReadsTheClock(t *testing.T) {
	cmd := exec.Command("grep", "-rn", "time.Now", "pkg/core")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("time.Now found in pkg/core; the clock must be injected (spec 2.1):\n%s", out)
		return
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("running grep for time.Now in pkg/core: %v", err)
	}
}
