// This file tests FetchRegistryEntry (Task 3.6, spec 5, decision D5): the
// discovery side of `smithmark registry check`. Every case is driven through
// the same fixtureTransport resolve_test.go already defines, so no test here
// touches a real socket either; the two committed fixtures,
// testdata/registry/entry_npm.json and entry_remote.json, are real MCP
// Registry API response snapshots (see testdata/README.md for provenance).
package discover_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/discover"
)

const (
	registryEntryNPMPath    = "../../testdata/registry/entry_npm.json"
	registryEntryRemotePath = "../../testdata/registry/entry_remote.json"

	registryNPMServerName    = "io.github.getsentry/sentry-mcp"
	registryRemoteServerName = "com.notion/mcp"
)

// registryTransport serves a canned "versions/latest" response for exactly
// one server name, failing the test loudly on any other request, mirroring
// fixtureTransport's contract for every other discovery path in this package.
func registryTransport(t *testing.T, serverName string, status int, body []byte) *fixtureTransport {
	t.Helper()
	tr := newFixtureTransport(t)
	tr.serve(http.MethodGet, "/v0/servers/"+serverName+"/versions/latest", status, body)
	return tr
}

// TestFetchRegistryEntryNPMBacked drives FetchRegistryEntry over the real
// io.github.getsentry/sentry-mcp snapshot: one npm package, no remotes, and
// (matching every real registry entry today) no attestation reference field.
func TestFetchRegistryEntryNPMBacked(t *testing.T) {
	tr := registryTransport(t, registryNPMServerName, http.StatusOK, readFile(t, registryEntryNPMPath))

	entry, err := discover.FetchRegistryEntry(context.Background(), registryNPMServerName, discover.ResolveOptions{
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("FetchRegistryEntry: %v", err)
	}

	if entry.Name != registryNPMServerName {
		t.Errorf("Name = %q, want %q", entry.Name, registryNPMServerName)
	}
	if len(entry.Remotes) != 0 {
		t.Errorf("Remotes = %v, want none", entry.Remotes)
	}
	if entry.HasAttRef {
		t.Error("HasAttRef = true; no real registry entry carries this field today")
	}
	if len(entry.Raw) == 0 {
		t.Error("Raw is empty; it must carry the server object's own JSON")
	}

	pkg, ok := entry.NPMPackage()
	if !ok {
		t.Fatalf("NPMPackage found none; entry.Packages = %+v", entry.Packages)
	}
	if pkg.Type != "npm" {
		t.Errorf("Type = %q, want npm", pkg.Type)
	}
	if pkg.Name != "@sentry/mcp-server" {
		t.Errorf("Name = %q, want @sentry/mcp-server", pkg.Name)
	}
	if pkg.Version != "0.25.0" {
		t.Errorf("Version = %q, want 0.25.0", pkg.Version)
	}
}

// TestFetchRegistryEntryRemoteOnly drives FetchRegistryEntry over the real
// com.notion/mcp snapshot: no packages at all, two remotes, and no NPMPackage
// match.
func TestFetchRegistryEntryRemoteOnly(t *testing.T) {
	tr := registryTransport(t, registryRemoteServerName, http.StatusOK, readFile(t, registryEntryRemotePath))

	entry, err := discover.FetchRegistryEntry(context.Background(), registryRemoteServerName, discover.ResolveOptions{
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("FetchRegistryEntry: %v", err)
	}

	if entry.Name != registryRemoteServerName {
		t.Errorf("Name = %q, want %q", entry.Name, registryRemoteServerName)
	}
	if len(entry.Packages) != 0 {
		t.Errorf("Packages = %v, want none", entry.Packages)
	}
	if entry.HasAttRef {
		t.Error("HasAttRef = true; no real registry entry carries this field today")
	}
	if _, ok := entry.NPMPackage(); ok {
		t.Error("NPMPackage found one; this entry carries no packages at all")
	}

	if len(entry.Remotes) != 2 {
		t.Fatalf("Remotes has %d entries, want 2: %+v", len(entry.Remotes), entry.Remotes)
	}
	want := []discover.RegistryRemote{
		{Transport: "streamable-http", URL: "https://mcp.notion.com/mcp"},
		{Transport: "sse", URL: "https://mcp.notion.com/sse"},
	}
	for i, w := range want {
		if entry.Remotes[i] != w {
			t.Errorf("Remotes[%d] = %+v, want %+v", i, entry.Remotes[i], w)
		}
	}
}

// TestFetchRegistryEntryNotFoundIsDiscoveryFailed proves a 404 (a server name
// the registry does not carry) is DISCOVERY_FAILED with a detail naming the
// server, not a tolerated absence: unlike an npm package's own provenance
// attestation, the registry entry itself is metadata discovery needs to
// proceed at all.
func TestFetchRegistryEntryNotFoundIsDiscoveryFailed(t *testing.T) {
	tr := registryTransport(t, "does.not/exist", http.StatusNotFound, nil)

	_, err := discover.FetchRegistryEntry(context.Background(), "does.not/exist", discover.ResolveOptions{
		Transport: tr,
	})
	assertCode(t, err, codes.DiscoveryFailed)
	if !strings.Contains(err.Error(), "does.not/exist") {
		t.Errorf("error %v does not name the server", err)
	}
}

// TestFetchRegistryEntryUnexpectedStatusIsDiscoveryFailed proves any other
// non 200 status is also DISCOVERY_FAILED.
func TestFetchRegistryEntryUnexpectedStatusIsDiscoveryFailed(t *testing.T) {
	tr := registryTransport(t, registryNPMServerName, http.StatusInternalServerError, nil)

	_, err := discover.FetchRegistryEntry(context.Background(), registryNPMServerName, discover.ResolveOptions{
		Transport: tr,
	})
	assertCode(t, err, codes.DiscoveryFailed)
}

// TestFetchRegistryEntryMalformedBodyIsDiscoveryFailed proves a 200 response
// whose body is not valid JSON at all fails loudly rather than silently
// producing a zero valued entry.
func TestFetchRegistryEntryMalformedBodyIsDiscoveryFailed(t *testing.T) {
	tr := registryTransport(t, registryNPMServerName, http.StatusOK, []byte("not json"))

	_, err := discover.FetchRegistryEntry(context.Background(), registryNPMServerName, discover.ResolveOptions{
		Transport: tr,
	})
	assertCode(t, err, codes.DiscoveryFailed)
}

// TestFetchRegistryEntryHasAttRefWhenFieldPresent proves HasAttRef is real
// logic driven by the entry's own JSON, not a hardcoded false: a synthetic
// response (no real registry entry carries this today) that adds an
// "attestations" array to the server object decodes with HasAttRef true.
func TestFetchRegistryEntryHasAttRefWhenFieldPresent(t *testing.T) {
	const body = `{
		"server": {
			"name": "example.com/future-server",
			"packages": [],
			"remotes": [],
			"attestations": [{"predicateType": "https://in8.sh/attestation/agent-capability/v1"}]
		}
	}`
	tr := registryTransport(t, "example.com/future-server", http.StatusOK, []byte(body))

	entry, err := discover.FetchRegistryEntry(context.Background(), "example.com/future-server", discover.ResolveOptions{
		Transport: tr,
	})
	if err != nil {
		t.Fatalf("FetchRegistryEntry: %v", err)
	}
	if !entry.HasAttRef {
		t.Error("HasAttRef = false with an attestations array present, want true")
	}
}
