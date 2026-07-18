// Command gen (testdata/servers/gen) generates and checks the Task 6.1 dogfood
// server attestations: the signed capability bundles committed at
// testdata/servers/<name>/attestation.sigstore.json for the two real first
// party MCP servers (better-call-claude, dear-claude) and the deliberately
// misdeclared fixture server. It is the sibling of testdata/gen (the Phase 3
// verification fixture kit): the same "commit a signed bundle plus a checker"
// pattern, but signed with the separate throwaway dogfood key and exercising the
// real attest pipeline pieces (LoadDeclared, ToolsFromFile, NewStatement,
// compose signing) rather than a hand assembled statement.
//
// It lives under testdata/ so the Go toolchain excludes it from `go build ./...`,
// `go vet ./...`, and `go test ./...`. Invoke it explicitly from the repo root:
//
//	go run ./testdata/servers/gen            # regenerate every dogfood attestation (requires the committed dogfood key)
//	go run ./testdata/servers/gen --check    # verify the committed dogfood attestations stay honest
//
// DETERMINISM: the statement payloads are fully deterministic (fixed clock, fixed
// generator identity, declarations and tool listings read from committed files,
// and fabricated fixed npm sha512 subject digests). The ECDSA signature bytes are
// not byte reproducible, because ECDSA draws a per signature nonce from
// crypto/rand; that is expected and documented in testdata/README.md. --check is
// the guard that the committed bundles still verify against the committed public
// key and carry the payloads each subject promises, not a byte for byte diff.
//
// THROWAWAY KEY: testdata/servers/dogfood-signing-key.pem is a test only,
// throwaway key. It must never sign a real published artifact. See
// testdata/README.md.
//
// SUBJECT DIGEST: the two real servers are vendored source snapshots, not
// published npm tarballs, so no real tarball integrity digest exists. Each
// subject carries a fabricated fixed 128 hex sha512 digest standing in for the
// published tarball integrity, exactly the pattern testdata/gen uses for its
// fake npm subject. The real release attestation, run with `smithmark attest`
// over the published tarball, would carry that tarball's true sha512 and would
// extract the tool listing live from the running server (U2) rather than reading
// the committed tools.json transcription.
package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// Committed paths, relative to the repository root that `go run` executes in.
const (
	serversDir         = "testdata/servers"
	dogfoodPrivKeyPath = serversDir + "/dogfood-signing-key.pem"
	dogfoodPubKeyPath  = serversDir + "/dogfood-signing-key-pub.pem"
	attestationFile    = "attestation.sigstore.json"
	declFile           = "smithmark.yaml"
)

// Fixed generator identity and clock stamped onto every generated manifest, so
// the statement payloads never depend on the wall clock or the build.
const (
	generatorName    = "smithmark"
	generatorVersion = "test"
)

// fixedGeneratedAt is the pinned generatedAt for every dogfood manifest
// (2026-07-16T00:00:00Z), matching testdata/gen so the two kits agree.
var fixedGeneratedAt = time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)

// serverSpec is one dogfood attestation subject.
type serverSpec struct {
	name string // subdirectory under serversDir holding smithmark.yaml
	// toolsFile is the --tools-from listing beside the declaration (transcribed
	// from the server src's inline JSON Schemas), or "" for a server with no
	// tools. It completes the mcp surface the declaration leaves for extraction.
	toolsFile string
	// digestHex is the fabricated fixed npm sha512 subject digest (128 lowercase
	// hex characters), standing in for the real published tarball integrity.
	digestHex string
	// expectFinding is the lint code smithmark lint must flag over this server's
	// src, or "" for an honestly declared server that lints clean. It is asserted
	// by cmd/smithmark's dogfood test, not here; it is recorded on the spec so the
	// two stay in one place.
	expectFinding string
}

// specs is the committed dogfood subject set. The fabricated digests are visibly
// synthetic repeating patterns so no reader mistakes one for a real integrity
// digest. Each is 4 hex characters repeated 32 times, i.e. 128 hex, the shape of
// an npm sha512.
var specs = []serverSpec{
	{name: "better-call-claude", toolsFile: "tools.json", digestHex: strings.Repeat("bcc0", 32)},
	{name: "dear-claude", toolsFile: "tools.json", digestHex: strings.Repeat("dc1a", 32)},
	{name: "misdeclared-server", toolsFile: "", digestHex: strings.Repeat("bad0", 32), expectFinding: codes.UndeclaredNetworkEgress},
}

func main() {
	log.SetFlags(0)
	check := flag.Bool("check", false, "verify the committed dogfood attestations still verify and carry the expected payloads, instead of regenerating them")
	flag.Parse()

	if *check {
		runCheck()
		return
	}
	runGenerate()
}

// runGenerate rebuilds and re signs every dogfood attestation with the committed
// throwaway key. It refuses to run when the key is absent, so a missing key never
// silently produces unsigned or differently keyed fixtures.
func runGenerate() {
	if _, err := os.Stat(dogfoodPrivKeyPath); err != nil {
		log.Fatalf("dogfood signing key %s is not present: %v; it is a committed throwaway demo key (see testdata/README.md)", dogfoodPrivKeyPath, err)
	}
	ctx := context.Background()
	signer := compose.NewSigner()
	for _, spec := range specs {
		m, digest := buildManifest(spec)
		stmt, err := manifest.NewStatement(refFor(m, digest), m)
		must(spec.name+": assembling statement", err)
		canonical, err := stmt.Canonical()
		must(spec.name+": canonicalizing statement", err)
		signed, err := signer.SignStatement(ctx, canonical, compose.SignOptions{KeyPath: dogfoodPrivKeyPath})
		must(spec.name+": signing statement", err)
		out := filepath.Join(serversDir, spec.name, attestationFile)
		must("writing "+out, os.WriteFile(out, append(bytes.Clone(signed.Bundle), '\n'), 0o644))
		log.Printf("wrote %s", out)
	}
	log.Printf("note: ECDSA signatures are randomized, so bundle bytes differ each run; payloads are identical. Run `go run ./testdata/servers/gen --check` to verify.")
}

// buildManifest loads a server's declaration, completes its mcp surface from the
// committed tool listing, stamps the fixed clock and generator, validates it, and
// returns it alongside the fabricated subject digest. It mirrors the attest
// pipeline's completeMCPSurface step, minus the live tarball digest.
func buildManifest(spec serverSpec) (*manifest.CapabilityManifest, manifest.DigestSet) {
	decl, err := discover.LoadDeclared(filepath.Join(serversDir, spec.name, declFile))
	must("loading "+spec.name+" declaration", err)
	m := decl.Manifest

	tools := []manifest.ToolDecl{}
	if spec.toolsFile != "" {
		tools, err = discover.ToolsFromFile(filepath.Join(serversDir, spec.name, spec.toolsFile))
		must("reading "+spec.name+" tools", err)
	}
	m.MCP.Tools = tools
	m.MCP.Resources = []string{}
	m.MCP.Prompts = []string{}
	m.GeneratedAt = fixedGeneratedAt
	m.Generator = manifest.GeneratorInfo{Name: generatorName, Version: generatorVersion}

	// No dependency SBOM block: forgeseal is not required to be on PATH for this
	// offline fixture kit, so the dogfood attestations omit the dependencies
	// block (equivalent to --skip-sbom). The real release attestation composes
	// the forgeseal SBOM. Recorded in testdata/README.md and docs/decisions.md.
	if issues := m.Validate(); len(issues) > 0 {
		log.Fatalf("%s manifest did not validate: %v", spec.name, issues)
	}
	return m, manifest.DigestSet{"sha512": spec.digestHex}
}

// refFor builds the artifact reference the statement subject is derived from.
func refFor(m *manifest.CapabilityManifest, digest manifest.DigestSet) manifest.ArtifactRef {
	return manifest.ArtifactRef{
		Kind:    m.Artifact.Kind,
		Name:    m.Artifact.Name,
		Version: m.Artifact.Version,
		Digest:  digest,
		Source:  m.Artifact.Source,
	}
}

// runCheck verifies every committed dogfood attestation against the committed
// public key and asserts each carries the payload its subject promises. It exits
// non zero on the first failure so CI and a maintainer see a clear signal.
func runCheck() {
	pub, err := os.ReadFile(dogfoodPubKeyPath)
	must("reading committed dogfood public key", err)
	verifier := compose.NewVerifier()
	for _, spec := range specs {
		if err := checkSpec(spec, verifier, pub); err != nil {
			log.Fatalf("dogfood attestation check failed: %v", err)
		}
		log.Printf("ok: %s attestation verifies and carries the expected payload", spec.name)
	}
	log.Printf("all committed dogfood attestations are honest")
}

// checkSpec verifies one committed attestation offline against the dogfood public
// key, parses its statement, validates its predicate, and confirms its subject
// digest is the fabricated digest this subject was built with.
func checkSpec(spec serverSpec, verifier compose.Verifier, pub []byte) error {
	path := filepath.Join(serversDir, spec.name, attestationFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	stmtBytes, _, err := verifier.VerifyBundle(raw, pub, fixedGeneratedAt)
	if err != nil {
		return &checkError{spec.name, "signature did not verify against the committed dogfood public key: " + err.Error()}
	}
	stmt, err := manifest.ParseStatement(stmtBytes)
	if err != nil {
		return &checkError{spec.name, "statement did not parse: " + err.Error()}
	}
	if issues := stmt.Predicate.Validate(); len(issues) > 0 {
		return &checkError{spec.name, "predicate is not valid"}
	}
	want := manifest.DigestSet{"sha512": spec.digestHex}
	if !digestSetEqual(stmt.Subject[0].Digest, want) {
		return &checkError{spec.name, "subject digest is not the fabricated fixture digest this subject was built with"}
	}
	return nil
}

// checkError is a small typed error naming the failing subject.
type checkError struct {
	subject string
	detail  string
}

func (e *checkError) Error() string { return e.subject + ": " + e.detail }

// digestSetEqual reports whether two digest sets carry the same keys and values.
func digestSetEqual(a, b manifest.DigestSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// must fatals with context when err is non nil.
func must(what string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
