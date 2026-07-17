// This file implements the MCP Registry discovery side of Task 3.6
// (`smithmark registry check`, spec 5, decision D5): resolving one server
// entry by name from the real MCP Registry API. It is the demonstration
// surface for the MCP Registry provenance RFC (Task 6.4): the registry's own
// schema, verified against its published OpenAPI description during this
// task's development, carries no attestation reference field at all today,
// so RegistryEntry.HasAttRef is false for every real entry this package has
// ever fetched. See testdata/README.md for the exact snapshot fixtures and
// the requests that produced them.
package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// defaultRegistryAPI is the base URL FetchRegistryEntry talks to when
// ResolveOptions.RegistryAPI is left empty.
const defaultRegistryAPI = "https://registry.modelcontextprotocol.io"

// RegistryPackage is one entry of a registry server's packages array: the
// distribution ecosystem (Type, for example "npm", "pypi", or "oci"), the
// package identifier within that ecosystem (Name), and its pinned Version.
// Only these three fields are read; the real schema carries several more per
// package (runtimeHint, environmentVariables, runtimeArguments, and more),
// all ignored under the same lenient, foreign format posture this package
// already uses for npm's packument and attestations responses (npm.go).
type RegistryPackage struct {
	Type    string
	Name    string
	Version string
}

// RegistryRemote is one entry of a registry server's remotes array: a hosted
// endpoint's transport and URL. `registry check` never calls a hosted
// endpoint (D5); it only names them in HOSTED_ENDPOINT_UNSUPPORTED's detail.
type RegistryRemote struct {
	Transport string
	URL       string
}

// RegistryEntry is what FetchRegistryEntry produces: the fields
// `smithmark registry check` needs from one MCP Registry server entry.
// HasAttRef is the whole point of the command (spec 5, D5): true only when
// the entry's own JSON carries an attestation reference field, which the
// real registry schema does not define today (that field is what the MCP
// Registry provenance RFC, Task 6.4, proposes to add), so it is false for
// every real entry. Raw is the server object's own undecoded JSON, so a
// caller can inspect fields this trimmed type does not model.
type RegistryEntry struct {
	Name      string
	Packages  []RegistryPackage
	Remotes   []RegistryRemote
	HasAttRef bool
	Raw       json.RawMessage
}

// NPMPackage returns the first package in e.Packages whose Type is "npm", and
// whether one was found. A registry entry may carry several distribution
// shapes at once (npm, pypi, oci, and more); v0.1's discovery only
// understands npm identity resolution (spec 6), so `registry check` uses this
// to decide whether it can continue into the shared verification pipeline at
// all.
func (e *RegistryEntry) NPMPackage() (RegistryPackage, bool) {
	for _, p := range e.Packages {
		if p.Type == "npm" {
			return p, true
		}
	}
	return RegistryPackage{}, false
}

// registryEnvelope captures a "get specific MCP server version" response body
// with Server left as raw JSON, so RegistryEntry.Raw preserves the server
// object's exact original bytes rather than bytes produced by marshaling it
// again. Decoded leniently (a plain json.Unmarshal, not DisallowUnknownFields): the
// registry's response, like npm's packument and attestations responses, is a
// foreign, community owned format this package does not control the schema
// of; the response's own _meta block (publish status, timestamps) is ignored
// entirely.
type registryEnvelope struct {
	Server json.RawMessage `json:"server"`
}

// registryServer is the "server" object of a registry response: only the
// fields RegistryEntry needs. Attestations anticipates the field name the
// MCP Registry provenance RFC (Task 6.4) is expected to add, as a sibling
// array to Packages and Remotes; it does not exist in the real schema today,
// so every real response decodes it as a nil json.RawMessage, which is
// exactly what makes RegistryEntry.HasAttRef false for every real entry.
type registryServer struct {
	Name         string                `json:"name"`
	Packages     []registryPackageWire `json:"packages"`
	Remotes      []registryRemoteWire  `json:"remotes"`
	Attestations json.RawMessage       `json:"attestations,omitempty"`
}

type registryPackageWire struct {
	RegistryType string `json:"registryType"`
	Identifier   string `json:"identifier"`
	Version      string `json:"version"`
}

type registryRemoteWire struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// registryAPIBase returns opts.RegistryAPI with any trailing slash trimmed,
// or defaultRegistryAPI when opts.RegistryAPI is empty, mirroring
// registryBase's identical role for the npm registry base URL.
func registryAPIBase(opts ResolveOptions) string {
	if opts.RegistryAPI != "" {
		return strings.TrimSuffix(opts.RegistryAPI, "/")
	}
	return defaultRegistryAPI
}

// FetchRegistryEntry resolves serverName against the MCP Registry's
// "GET /v0/servers/{serverName}/versions/{version}" endpoint (the "get
// specific MCP server version" operation), requesting the special "latest"
// version. serverName is percent encoded before it is placed in the request
// path, since the registry's own OpenAPI description documents this
// parameter as a URL-encoded server name (a real server name such as
// "io.github.getsentry/sentry-mcp" would otherwise be split across path
// segments and never match the route).
//
// Every failure, including serverName not being found (a 404), is
// DISCOVERY_FAILED naming the server: unlike an npm package's own optional
// provenance attestation, the registry entry itself is metadata discovery
// needs to proceed at all, so there is no tolerated absence here.
func FetchRegistryEntry(ctx context.Context, serverName string, opts ResolveOptions) (*RegistryEntry, error) {
	reqURL := fmt.Sprintf("%s/v0/servers/%s/versions/latest", registryAPIBase(opts), url.PathEscape(serverName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "building registry request for %s: %v", serverName, err)
	}
	resp, err := httpClient(opts).Do(req)
	if err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "fetching registry entry for %s: %v", serverName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, codes.E(codes.DiscoveryFailed, "no MCP Registry entry found for server %q", serverName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, codes.E(codes.DiscoveryFailed, "fetching registry entry for %s: unexpected status %s", serverName, resp.Status)
	}

	body, err := readCapped(resp.Body, fmt.Sprintf("registry entry body for %s", serverName))
	if err != nil {
		return nil, err
	}

	var env registryEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "decoding registry entry for %s: %v", serverName, err)
	}
	var srv registryServer
	if err := json.Unmarshal(env.Server, &srv); err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "decoding registry server object for %s: %v", serverName, err)
	}

	packages := make([]RegistryPackage, 0, len(srv.Packages))
	for _, p := range srv.Packages {
		packages = append(packages, RegistryPackage{Type: p.RegistryType, Name: p.Identifier, Version: p.Version})
	}
	remotes := make([]RegistryRemote, 0, len(srv.Remotes))
	for _, r := range srv.Remotes {
		remotes = append(remotes, RegistryRemote{Transport: r.Type, URL: r.URL})
	}

	return &RegistryEntry{
		Name:      srv.Name,
		Packages:  packages,
		Remotes:   remotes,
		HasAttRef: hasAttestationRef(srv.Attestations),
		Raw:       env.Server,
	}, nil
}

// hasAttestationRef reports whether raw is a present, non empty, non null
// JSON value. The registry schema has no attestation reference field today,
// so every real response decodes Attestations as a nil json.RawMessage and
// this returns false; a null literal or an empty array or object are treated
// the same way, as "no reference," rather than merely "not absent."
func hasAttestationRef(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "[]", "{}":
		return false
	default:
		return true
	}
}
