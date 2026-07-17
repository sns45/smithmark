// This file tests `smithmark registry check` (Task 3.6, spec 5, decision
// D5): the demo surface for the MCP Registry provenance RFC. It reuses
// verify_test.go's own fixture transport, deps builder, and report helpers
// (verifyDeps, newVerifyTransport, decodeReport, findCheck, decodeErrLine),
// since both commands share the same discovery and verification core (see
// discoverForVerification and verifyDiscovered in verify.go). The two entry
// fixtures are real MCP Registry API response snapshots (see
// testdata/README.md for provenance); no test here touches a real socket.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/sns45/smithmark/pkg/core/codes"
)

const (
	registryEntryNPMPath     = "../../testdata/registry/entry_npm.json"
	registryEntryRemotePath  = "../../testdata/registry/entry_remote.json"
	registryNPMPackumentPath = "../../testdata/registry/sentry_packument.json"

	registryNPMServerName     = "io.github.getsentry/sentry-mcp"
	registryRemoteServerName  = "com.notion/mcp"
	registryNPMPackageName    = "@sentry/mcp-server"
	registryNPMPackageVersion = "0.25.0"
)

// readRegistryFixture reads a committed fixture file, failing the test loudly
// rather than silently serving an empty body on a typo'd path.
func readRegistryFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return data
}

// TestRegistryCheckRemoteOnlyExitsZero drives `registry check` over the real
// com.notion/mcp snapshot (remotes only, no npm package): the report carries
// only the two registry specific checks, no verification stage ran at all,
// and the command exits 0 (D5: informational, never an error).
func TestRegistryCheckRemoteOnlyExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)
	tr := newVerifyTransport(t)
	tr.serve(http.MethodGet, "/v0/servers/"+registryRemoteServerName+"/versions/latest", http.StatusOK, readRegistryFixture(t, registryEntryRemotePath))
	d.Transport = tr

	code := runMain(d, []string{"registry", "check", registryRemoteServerName, "--output", "json"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}

	report := decodeReport(t, stdout.Bytes())
	if len(report.Checks) != 2 {
		t.Fatalf("report carries %d checks, want exactly 2 (registry specific only, no verification stage): %v", len(report.Checks), report.Checks)
	}
	if findCheck(t, report, codes.RegistryAttestationRefPresent).Passed {
		t.Error("REGISTRY_ATTESTATION_REF_PRESENT passed; no real registry entry carries this field today")
	}
	hosted := findCheck(t, report, codes.HostedEndpointUnsupported)
	if hosted.Passed {
		t.Error("HOSTED_ENDPOINT_UNSUPPORTED passed for a remote only entry, want failed")
	}
	if !strings.Contains(hosted.Detail, "mcp.notion.com") {
		t.Errorf("HOSTED_ENDPOINT_UNSUPPORTED detail %q does not name the remote endpoint", hosted.Detail)
	}
	if s := strings.TrimSpace(string(report.Evidence)); s != "null" {
		t.Errorf("evidence must be null for a remote only entry, got: %s", report.Evidence)
	}
	if report.Subject.Name != registryRemoteServerName {
		t.Errorf("Subject.Name = %q, want %q", report.Subject.Name, registryRemoteServerName)
	}
}

// TestRegistryCheckNPMBackedMissingAttestationExitsOne drives `registry
// check` over the real io.github.getsentry/sentry-mcp snapshot (one npm
// package, @sentry/mcp-server@0.25.0). The npm continuation runs discovery
// against an empty OCI store and a 404 npm attestations response, so
// verification's own ATTESTATION_MISSING check fails exactly as
// TestVerifyMissingAttestationExitsOne asserts for a plain npm argument
// (verify_test.go); this proves discovery and check merging work end to end
// without fabricating a passing chain the committed fixtures cannot support.
func TestRegistryCheckNPMBackedMissingAttestationExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)
	tr := newVerifyTransport(t)
	tr.serve(http.MethodGet, "/v0/servers/"+registryNPMServerName+"/versions/latest", http.StatusOK, readRegistryFixture(t, registryEntryNPMPath))
	tr.serve(http.MethodGet, "/"+registryNPMPackageName, http.StatusOK, readRegistryFixture(t, registryNPMPackumentPath))
	tr.serve(http.MethodGet, fmt.Sprintf("/-/npm/v1/attestations/%s@%s", registryNPMPackageName, registryNPMPackageVersion), http.StatusNotFound, nil)
	d.Transport = tr
	store := memory.New()
	d.ReadTarget = func(_ context.Context, _ string) (oras.ReadOnlyGraphTarget, error) { return store, nil }

	code := runMain(d, []string{
		"registry", "check", registryNPMServerName,
		"--attestation-base", verifyTestAttestBase,
		"--output", "json",
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}

	report := decodeReport(t, stdout.Bytes())
	if findCheck(t, report, codes.AttestationMissing).Passed {
		t.Error("ATTESTATION_MISSING passed with an empty store; it must fail")
	}
	if findCheck(t, report, codes.RegistryAttestationRefPresent).Passed {
		t.Error("REGISTRY_ATTESTATION_REF_PRESENT passed; no real registry entry carries this field today")
	}
	if !findCheck(t, report, codes.HostedEndpointUnsupported).Passed {
		t.Error("HOSTED_ENDPOINT_UNSUPPORTED failed for an npm backed entry, want passed (not blocked by any declared remotes)")
	}
	if report.Subject.Name != registryNPMPackageName {
		t.Errorf("Subject.Name = %q, want %q", report.Subject.Name, registryNPMPackageName)
	}
	for i := 1; i < len(report.Checks); i++ {
		if report.Checks[i-1].Code > report.Checks[i].Code {
			t.Errorf("checks not sorted by code after the registry checks were merged in: %s before %s", report.Checks[i-1].Code, report.Checks[i].Code)
		}
	}
}

// TestRegistryCheckServerNotFoundExitsThree proves an unknown server name (a
// 404 from the registry) is an operational failure, exit 3 with the single
// DISCOVERY_FAILED stderr line, never a report.
func TestRegistryCheckServerNotFoundExitsThree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)
	tr := newVerifyTransport(t)
	tr.serve(http.MethodGet, "/v0/servers/does.not/exist/versions/latest", http.StatusNotFound, nil)
	d.Transport = tr

	code := runMain(d, []string{"registry", "check", "does.not/exist"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.DiscoveryFailed {
		t.Errorf("code = %q, want %q", line.Code, codes.DiscoveryFailed)
	}
}

// TestRegistryCheckSummaryMode smoke tests the human summary surface for a
// remote only entry: one line per check plus a verdict line, asserted
// loosely (contains codes and verdict), never goldened, matching how
// TestVerifySummaryMode asserts verify's own summary output.
func TestRegistryCheckSummaryMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)
	tr := newVerifyTransport(t)
	tr.serve(http.MethodGet, "/v0/servers/"+registryRemoteServerName+"/versions/latest", http.StatusOK, readRegistryFixture(t, registryEntryRemotePath))
	d.Transport = tr

	code := runMain(d, []string{"registry", "check", registryRemoteServerName, "--output", "summary"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{codes.RegistryAttestationRefPresent, codes.HostedEndpointUnsupported, "VERIFIED"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary output does not contain %q:\n%s", want, out)
		}
	}
}
