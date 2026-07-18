# Live OCI Discovery Repository Scoping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `smithmark verify` discover OCI backed attestations in the per artifact repository the D3 scheme computes, so a live registry lookup queries the right path instead of the bare attestation base.

**Architecture:** Replace `ResolveOptions.Target` (a single pre built oras target scoped to the base) with `ResolveOptions.NewTarget func(ctx, repo string) (oras.ReadOnlyGraphTarget, error)`, a factory called at the two discovery sites where the per artifact repository is known: the D3 tag mapped path (`discoverByTag`) and the OCI referrers path (`resolveOCIIdentity` plus `discoverReferrers`).

**Tech Stack:** Go 1.25, `oras.land/oras-go/v2` (v2.6.2), `oras.land/oras-go/v2/registry` (`ParseReference`, `Referrers`), `oras.land/oras-go/v2/content/memory` (test stores), `net/http/httptest` (the live round trip test).

**Spec:** `docs/superpowers/specs/2026-07-18-live-oci-discovery-scoping-design.md`. **Issue:** https://github.com/sns45/smithmark/issues/4.

## Global Constraints

- Module `github.com/sns45/smithmark`; Go 1.25; the change lives entirely in `pkg/discover` and `cmd/smithmark`, no `pkg/core` change.
- `pkg/core` stays pure; the purity guard (`internal/arch`) must stay green. This work does not touch it.
- Strict schema and reuse conventions unchanged; no new dependency (oras-go and httptest are already available).
- Every check and error keeps its existing stable code: `DISCOVERY_FAILED`, `ATTESTATION_BASE_UNKNOWN`, `REF_UNMAPPABLE`. No new codes.
- Prose in comments and commit messages avoids hyphens and dashes; identifiers, flags, and paths are exempt.
- No network in any test: OCI targets are injected factories returning memory stores or a local `httptest` server.
- The whole suite, `go vet ./...`, `gofmt -l`, and `GOOS=wasip1 GOARCH=wasm go build ./pkg/...` stay green at every task boundary.

## File Structure

```
pkg/discover/resolve.go        # ResolveOptions.NewTarget field; discoverByTag threads AttestationRef's repo;
                               # the identity struct carries the scoped oci target; the Resolve dispatch
                               # passes it to discoverReferrers
pkg/discover/oci.go            # resolveOCIIdentity parses the image repo and builds the scoped target;
                               # discoverReferrers receives the scoped target
pkg/discover/resolve_test.go   # migrate ~9 Target: sites to NewTarget:; add the two threading tests
pkg/discover/oci_scoping_test.go  # NEW: the httptest OCI registry round trip test
cmd/smithmark/verify.go        # discoverForVerification sets opts.NewTarget = d.ReadTarget; stale comment removed
cmd/smithmark/main.go          # production ReadTarget factory comment reworded (guard is now a backstop)
```

## Task Right Sizing note

The field rename is atomic in Go: renaming `Target` breaks compilation across producers, consumers, and tests at once, so Task 1 does the full rename plus all migrations in one commit. Task 1 deliberately leaves `discoverByTag` passing the bare `base` (today's buggy behavior, invisible to memory store tests) so Task 2 can write a RED first test and then thread the correct repository. The OCI path is threaded correctly in Task 1 because it has no behavior preserving intermediate (its current base scoping is simply wrong), and its scoping is locked in by a mutation proven test in Task 3.

---

### Task 1: Rename the target field to a factory and migrate every site

**Files:**
- Modify: `pkg/discover/resolve.go` (the `ResolveOptions` struct, the `identity` struct, `Resolve` dispatch, `discoverByTag`)
- Modify: `pkg/discover/oci.go` (`resolveOCIIdentity`, `discoverReferrers`)
- Modify: `cmd/smithmark/verify.go` (`discoverForVerification`)
- Modify: `cmd/smithmark/main.go` (the production `ReadTarget` factory comment)
- Test: `pkg/discover/resolve_test.go` (migrate every `Target:` site)

**Interfaces:**
- Produces: `ResolveOptions.NewTarget func(ctx context.Context, repo string) (oras.ReadOnlyGraphTarget, error)` replacing `ResolveOptions.Target oras.ReadOnlyGraphTarget`. Later tasks call it with the per artifact repository.
- Consumes: `AttestationRef(base string, ref manifest.ArtifactRef) (repo, tag string, err error)` (unchanged, already returns the repository); `registry.ParseReference(artifact string) (registry.Reference, error)` from oras-go; `d.ReadTarget func(ctx, repo string) (oras.ReadOnlyGraphTarget, error)` in `cmd/smithmark` (unchanged shape).

- [ ] **Step 1: Confirm the baseline is green**

Run: `go test ./pkg/discover/ ./cmd/smithmark/`
Expected: PASS (this is the safety net Task 1 must preserve).

- [ ] **Step 2: Rename the `ResolveOptions` field to `NewTarget`**

In `pkg/discover/resolve.go`, replace the `Target` field and its doc comment:

```go
	// NewTarget constructs a read only OCI target scoped to a single
	// repository. Discovery computes the per artifact repository, the D3
	// <base>/<ecosystem>/<encoded-name> for the tag mapped path or the image
	// reference's own repository for the referrers path, and calls NewTarget
	// with it so the client queries the right path. A nil NewTarget means OCI
	// backed discovery is skipped with a note, not an error, exactly as a nil
	// target did before.
	NewTarget func(ctx context.Context, repo string) (oras.ReadOnlyGraphTarget, error)
```

- [ ] **Step 3: Thread the OCI referrers path (the fix, no valid preserve)**

In `pkg/discover/oci.go`, change `resolveOCIIdentity` to build a target scoped to the image repository and return it, and add `"oras.land/oras-go/v2/registry"` if not already imported (it is):

```go
func resolveOCIIdentity(ctx context.Context, arg string, opts ResolveOptions) (manifest.ArtifactRef, ocispec.Descriptor, oras.ReadOnlyGraphTarget, []string, error) {
	if opts.NewTarget == nil {
		return manifest.ArtifactRef{}, ocispec.Descriptor{}, nil, nil,
			codes.E(codes.DiscoveryFailed, "oci reference %q given but no OCI target factory was configured", arg)
	}
	parsed, err := registry.ParseReference(ociReference(arg))
	if err != nil {
		return manifest.ArtifactRef{}, ocispec.Descriptor{}, nil, nil,
			codes.E(codes.DiscoveryFailed, "parsing oci reference %q: %v", arg, err)
	}
	repo := parsed.Registry + "/" + parsed.Repository
	target, err := opts.NewTarget(ctx, repo)
	if err != nil {
		return manifest.ArtifactRef{}, ocispec.Descriptor{}, nil, nil,
			codes.E(codes.DiscoveryFailed, "scoping oci target to %q: %v", repo, err)
	}
	desc, err := target.Resolve(ctx, parsed.Reference)
	if err != nil {
		return manifest.ArtifactRef{}, ocispec.Descriptor{}, nil, nil,
			codes.E(codes.DiscoveryFailed, "resolving oci reference %q: %v", arg, err)
	}
	ref := manifest.ArtifactRef{
		Kind:   manifest.KindMCPServer,
		Name:   arg,
		Source: manifest.SourceOCI,
		Digest: manifest.DigestSet{desc.Digest.Algorithm().String(): desc.Digest.Encoded()},
	}
	notes := []string{notef(NoteOCIResolved, "resolved oci reference %q to digest %s via the scoped target", arg, desc.Digest)}
	return ref, desc, target, notes, nil
}
```

- [ ] **Step 4: Carry the scoped OCI target on the identity struct and use it in the dispatch**

In `pkg/discover/resolve.go`, add the field to `identity`:

```go
type identity struct {
	ref          manifest.ArtifactRef
	artifactRoot string
	ociSubject   *ocispec.Descriptor
	ociTarget    oras.ReadOnlyGraphTarget
	notes        []string
}
```

Update the `resolveIdentity` oci branch to capture and store the target:

```go
		ref, subject, target, notes, err := resolveOCIIdentity(ctx, arg, opts)
		if err != nil {
			return nil, err
		}
		return &identity{ref: ref, ociSubject: &subject, ociTarget: target, notes: notes}, nil
```

Update the `Resolve` dispatch to pass the scoped target:

```go
	if ident.ociSubject != nil {
		bundles, notes, err := discoverReferrers(ctx, ident.ociTarget, *ident.ociSubject)
```

`discoverReferrers`'s signature already takes `target oras.ReadOnlyGraphTarget`; no change to it.

- [ ] **Step 5: In `discoverByTag`, call the factory but keep passing `base` for now**

This preserves today's tag path behavior so Task 2 can drive a RED first test. In `pkg/discover/resolve.go`, `discoverByTag`, after the `AttestationRef` call, replace the `opts.Target` uses:

```go
	repo, tag, err := AttestationRef(base, ref)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "mapping attestation ref for %s %q: %v", ref.Kind, ref.Name, err)
	}
	_ = repo // Task 2 threads this; Task 1 preserves the base scoped behavior below.

	if opts.NewTarget == nil {
		return nil, []string{notef(NoteNoOCITarget, "no OCI target factory configured; skipping tag based attestation discovery")}, nil
	}
	target, err := opts.NewTarget(ctx, base)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "scoping attestation target to %q: %v", base, err)
	}

	desc, err := target.Resolve(ctx, tag)
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, []string{notef(NoteNoAttestationTag, "no attestation tag %s found", tag)}, nil
		}
		return nil, nil, codes.E(codes.DiscoveryFailed, "resolving attestation tag %s: %v", tag, err)
	}

	bundles, err := fetchManifestLayers(ctx, target, desc)
```

- [ ] **Step 6: Wire the CLI producer to pass the factory**

In `cmd/smithmark/verify.go`, `discoverForVerification`, delete the pre build block and the stale comment, and set the factory. Replace the `if bundlePath == "" { ... }` block with:

```go
	// Attestation discovery needs a factory that scopes a read only OCI target
	// to the per artifact repository discovery computes. An explicit --bundle
	// short circuits discovery, so the factory is only consulted when
	// discovering. Base resolution and repository scoping both live inside
	// discovery now, so the CLI passes the factory straight through.
	if bundlePath == "" {
		opts.NewTarget = d.ReadTarget
	}
	return discover.Resolve(ctx, arg, opts)
```

- [ ] **Step 7: Reword the production factory comment**

In `cmd/smithmark/main.go`, the `ReadTarget` factory keeps its empty repo guard but the comment loses the stale milestone reference:

```go
		ReadTarget: func(_ context.Context, repo string) (oras.ReadOnlyGraphTarget, error) {
			if repo == "" {
				// Discovery scopes the client to the per artifact repository
				// AttestationRef computes, which is never empty (AttestationRef
				// errors on an unresolved base before this factory is called).
				// This guard is a defensive backstop: an empty repository would
				// make remote.NewRepository fail with an uncoded error surfaced
				// as INTERNAL_ERROR, so fail closed with a coded DISCOVERY_FAILED
				// instead.
				return nil, codes.E(codes.DiscoveryFailed,
					"no OCI repository resolved for live attestation discovery; pass --bundle to verify an explicit bundle")
			}
			return remote.NewRepository(repo)
		},
```

- [ ] **Step 8: Migrate every test site in `resolve_test.go`**

Change every `Target: <x>,` in `pkg/discover/resolve_test.go` to a factory. For memory stores and the referrers targets:

```go
		NewTarget: func(_ context.Context, _ string) (oras.ReadOnlyGraphTarget, error) { return target, nil },
```

For the `poisonTarget` case (which proves discovery is skipped when `--bundle` is set), make the factory itself the poison so an unexpected discovery attempt fails the test:

```go
		NewTarget: func(_ context.Context, _ string) (oras.ReadOnlyGraphTarget, error) {
			t.Fatal("NewTarget called; discovery should have been skipped entirely")
			return nil, nil
		},
```

Add `"context"` to the test imports if any factory literal needs it (it is already imported). If `mustResolveOptions` references the old field, update it too.

- [ ] **Step 9: Build and run the full discover and cmd suites**

Run: `go build ./... && go test ./pkg/discover/ ./cmd/smithmark/ -count=1`
Expected: PASS. This is a behavior preserving refactor for the memory store tests (the tag path still scopes to base, the oci path scopes to the image repo but memory stores ignore the repo argument and are tagged with the bare reference the tests already use).

- [ ] **Step 10: Commit**

```bash
git add pkg/discover/resolve.go pkg/discover/oci.go cmd/smithmark/verify.go cmd/smithmark/main.go pkg/discover/resolve_test.go
git commit -m "Replace the pre built OCI target with a per repository factory"
```

---

### Task 2: Thread the D3 repository through the tag path (the headline fix, RED first)

**Files:**
- Modify: `pkg/discover/resolve.go` (`discoverByTag`)
- Test: `pkg/discover/resolve_test.go` (new `TestDiscoverByTagScopesToPerArtifactRepository`)

**Interfaces:**
- Consumes: `ResolveOptions.NewTarget` (Task 1); `AttestationRef` returning `(repo, tag, err)`; the npm fixture constants already in `resolve_test.go` (`fixtureNPMName`, `fixtureNPMVersion`, `testBase`) and the fixture transport helper that serves the packument so the ref resolves to an npm digest.

- [ ] **Step 1: Write the failing threading test**

Add to `pkg/discover/resolve_test.go`. It records the repo passed to the factory and asserts it is the per artifact repository, not the base. Use the existing npm packument fixture transport so `Resolve` gets a real npm digest, and a memory store so the tag is simply absent (an empty result is fine; the assertion is on the recorded repo):

```go
func TestDiscoverByTagScopesToPerArtifactRepository(t *testing.T) {
	tr := npmFixtureTransport(t) // the existing helper that serves the trimmed packument
	var gotRepo string
	store := memory.New()

	_, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, discover.ResolveOptions{
		Base:      testBase,
		Transport: tr,
		NewTarget: func(_ context.Context, repo string) (oras.ReadOnlyGraphTarget, error) {
			gotRepo = repo
			return store, nil
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := testBase + "/npm/" + fixtureNPMName
	if gotRepo != want {
		t.Errorf("NewTarget scoped to %q, want the per artifact repository %q (not the bare base %q)", gotRepo, want, testBase)
	}
}
```

If the exact npm fixture helper name differs, read the top of `resolve_test.go` and reuse whatever the existing npm round trip tests use (`TestResolveNPMArgFullRoundTrip` is the reference); do not invent a new transport.

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./pkg/discover/ -run TestDiscoverByTagScopesToPerArtifactRepository -v`
Expected: FAIL, `NewTarget scoped to "<testBase>", want the per artifact repository "<testBase>/npm/<name>"` (Task 1 still passes the bare base).

- [ ] **Step 3: Thread the repository in `discoverByTag`**

In `pkg/discover/resolve.go`, `discoverByTag`, replace the placeholder from Task 1 step 5 so the factory receives the computed repository:

```go
	repo, tag, err := AttestationRef(base, ref)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "mapping attestation ref for %s %q: %v", ref.Kind, ref.Name, err)
	}

	if opts.NewTarget == nil {
		return nil, []string{notef(NoteNoOCITarget, "no OCI target factory configured; skipping tag based attestation discovery")}, nil
	}
	target, err := opts.NewTarget(ctx, repo)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "scoping attestation target to %q: %v", repo, err)
	}
```

(The `_ = repo` line from Task 1 is removed; the rest of `discoverByTag` is unchanged.)

- [ ] **Step 4: Run the test and the suite**

Run: `go test ./pkg/discover/ -run TestDiscoverByTagScopesToPerArtifactRepository -v && go test ./pkg/discover/ ./cmd/smithmark/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/discover/resolve.go pkg/discover/resolve_test.go
git commit -m "Scope tag based attestation discovery to the per artifact repository"
```

---

### Task 3: Lock in the OCI referrers path scoping with a mutation proven test

**Files:**
- Test: `pkg/discover/resolve_test.go` (new `TestResolveOCIRefScopesToImageRepository`)

**Interfaces:**
- Consumes: `ResolveOptions.NewTarget` (Task 1); the oci fixture setup already in `resolve_test.go` (`emptyOCIManifestBytes`, the `target.Tag(ctx, subjectDesc, "v1.0.0")` pattern from `TestResolveOCIRefUsesReferrers`).

- [ ] **Step 1: Write the test asserting the image repository reaches the factory**

Model it on `TestResolveOCIRefUsesReferrers` (read that test for the exact subject descriptor and tag setup), but record the repo the factory receives. Use an oci reference argument whose repository is unambiguous, for example `registry.example.com/team/server:v1.0.0`:

```go
func TestResolveOCIRefScopesToImageRepository(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	// push and tag the subject exactly as TestResolveOCIRefUsesReferrers does,
	// tagging with the bare reference "v1.0.0" so the scoped target resolves it
	subjectDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes([]byte(emptyOCIManifestBytes)),
		Size:      int64(len(emptyOCIManifestBytes)),
	}
	if err := store.Push(ctx, subjectDesc, bytes.NewReader([]byte(emptyOCIManifestBytes))); err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, subjectDesc, "v1.0.0"); err != nil {
		t.Fatal(err)
	}

	var gotRepo string
	_, err := discover.Resolve(ctx, "registry.example.com/team/server:v1.0.0", discover.ResolveOptions{
		NewTarget: func(_ context.Context, repo string) (oras.ReadOnlyGraphTarget, error) {
			gotRepo = repo
			return store, nil
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "registry.example.com/team/server"; gotRepo != want {
		t.Errorf("NewTarget scoped to %q, want the image repository %q", gotRepo, want)
	}
}
```

Match the exact imports and subject construction used by `TestResolveOCIRefUsesReferrers` (`digest`, `bytes`); reuse its helpers rather than reconstructing them if it factors the push and tag out.

- [ ] **Step 2: Run it and confirm it passes (the fix is already in from Task 1)**

Run: `go test ./pkg/discover/ -run TestResolveOCIRefScopesToImageRepository -v`
Expected: PASS.

- [ ] **Step 3: Mutation check that the test really catches the bug**

Temporarily change `resolveOCIIdentity` in `pkg/discover/oci.go` to pass the wrong repo, for example `target, err := opts.NewTarget(ctx, "")` or the bare registry host, and rerun:

Run: `go test ./pkg/discover/ -run TestResolveOCIRefScopesToImageRepository -v`
Expected: FAIL (the recorded repo is no longer `registry.example.com/team/server`). Then revert the mutation and rerun; expected PASS. Paste both outcomes in the task report.

- [ ] **Step 4: Run the suite**

Run: `go test ./pkg/discover/ ./cmd/smithmark/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/discover/resolve_test.go
git commit -m "Pin OCI referrers discovery to the image repository with a mutation proven test"
```

---

### Task 4: Prove real client scoping with a local httptest OCI registry round trip

**Files:**
- Test: `pkg/discover/oci_scoping_test.go` (new)

**Interfaces:**
- Consumes: `ResolveOptions.NewTarget`; `remote.NewRepository(repo)` and `remote.Repository.PlainHTTP` from `oras.land/oras-go/v2/registry/remote`; `net/http/httptest`; the same npm packument fixture transport used in Task 2 so the ref resolves to a digest whose D3 tag the registry serves.

This is the test that would have caught the live bug: it stands up a local registry, pushes an attestation to the per artifact repository, and asserts discovery finds it there and finds nothing when the same tag sits only at the bare base.

- [ ] **Step 1: Write the round trip test**

Create `pkg/discover/oci_scoping_test.go`. Build a minimal OCI distribution handler with `httptest.NewServer` that serves manifests and blobs out of an in process map keyed by `<repo>` and by tag or digest, so a real `remote.Repository` can resolve and fetch. Push a sigstore bundle attestation manifest to the per artifact repository path (`<base>/npm/<name>`) under the D3 tag, and run `discover.Resolve` with a `NewTarget` that builds a real `remote.Repository` (PlainHTTP true) against the httptest host. Assert:

```go
// pseudocode shape; fill in the handler and manifest bytes concretely
func TestLiveDiscoveryFindsAttestationInPerArtifactRepo(t *testing.T) {
	reg := newFakeOCIRegistry(t)            // httptest server + per repo storage
	tr := npmFixtureTransport(t)            // resolves the npm digest so the D3 tag is deterministic
	base := reg.host                        // e.g. 127.0.0.1:PORT from the httptest server

	// compute the D3 (repo, tag) the same way production does
	ref := /* the resolved npm ArtifactRef for fixtureNPMName@fixtureNPMVersion */
	repo, tag, err := discover.AttestationRef(base, ref)
	if err != nil { t.Fatal(err) }
	reg.pushAttestation(t, repo, tag)       // a manifest with one sigstore bundle layer

	disc, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, discover.ResolveOptions{
		Base:      base,
		Transport: tr,
		NewTarget: func(_ context.Context, r string) (oras.ReadOnlyGraphTarget, error) {
			repository, err := remote.NewRepository(r)
			if err != nil { return nil, err }
			repository.PlainHTTP = true
			return repository, nil
		},
	})
	if err != nil { t.Fatalf("Resolve: %v", err) }
	if len(disc.Bundles) != 1 {
		t.Fatalf("found %d bundles, want 1 at the per artifact repository %q", len(disc.Bundles), repo)
	}
}
```

Add a sibling assertion, `TestLiveDiscoveryDoesNotFindAttestationAtBareBase`, that pushes the same manifest and tag to the bare `<base>` repository only (never to `<base>/npm/<name>`), runs the same discovery, and asserts `len(disc.Bundles) == 0` with a `NoteNoAttestationTag` style note. This is the assertion that fails against the pre Task 2 code and proves the client is scoped to the per artifact repository.

The fake registry only needs the endpoints `remote.Repository` calls for `Resolve` and `FetchAll` on a manifest plus one blob: `HEAD`/`GET /v2/<repo>/manifests/<ref>` and `GET /v2/<repo>/blobs/<digest>`, plus a `GET /v2/` ping returning 200. Key storage by the `<repo>` path segment so pushing to `<base>/npm/<name>` versus `<base>` is distinguishable. Keep the handler in this test file; it is test only infrastructure.

- [ ] **Step 2: Run the round trip tests**

Run: `go test ./pkg/discover/ -run TestLiveDiscovery -v`
Expected: both PASS.

- [ ] **Step 3: Mutation check against the scoping bug**

Temporarily revert `discoverByTag` to `opts.NewTarget(ctx, base)` and rerun:

Run: `go test ./pkg/discover/ -run TestLiveDiscovery -v`
Expected: `TestLiveDiscoveryFindsAttestationInPerArtifactRepo` FAILS (0 bundles, the client queried the bare base which has nothing). Revert and rerun; both PASS. Paste both outcomes in the task report. This is the demonstration that the round trip test is the one that would have caught the original live bug.

- [ ] **Step 4: Commit**

```bash
git add pkg/discover/oci_scoping_test.go
git commit -m "Add a local httptest OCI registry round trip proving per repository discovery"
```

---

### Task 5: Final gate and issue closure note

**Files:**
- Modify: none required beyond confirmation; only touch a file if the gate surfaces a gap.

- [ ] **Step 1: Run the full gate**

Run each and confirm the expected result:
- `gofmt -l cmd/ pkg/` -> no output
- `go vet ./...` -> clean
- `go test ./... -count=1` -> all packages ok
- `go test -race ./pkg/discover/ ./cmd/smithmark/ -count=1` -> ok
- `GOOS=wasip1 GOARCH=wasm go build ./pkg/...` -> exit 0

- [ ] **Step 2: Confirm the success criteria from the spec**

Verify by reading the final code: `discoverByTag` and `resolveOCIIdentity` build their target from the per artifact repository via `opts.NewTarget`, never from the bare base; the CLI passes `d.ReadTarget` as the factory and no longer pre resolves the base; the threading tests and the httptest round trip are present and green; no stale milestone comment remains in the touched files.

Run: `grep -rn "opts.Target\b\|Target:" pkg/discover/*.go cmd/smithmark/verify.go | grep -v _test.go | grep -v NewTarget`
Expected: no output (the pre built target field is fully gone from production code).

- [ ] **Step 3: Commit any gate fixes, otherwise proceed to the PR**

If steps 1 and 2 required a change, commit it with a message describing the fix. Otherwise there is nothing to commit; the milestone is the PR itself, opened at the checkpoint, which references sns45/smithmark#4 so merging closes it.

---

## Self Review Notes

- **Spec coverage:** the factory API change (spec Architecture) is Task 1; the tag path threading (spec component 1, the headline) is Task 2; the referrers path threading (spec component 3) is Task 1 plus the Task 3 test; the CLI wiring and the base resolution moving into discovery (spec components 4 and the issue's point 2) are Task 1 step 6; the production factory comment cleanup (spec) is Task 1 step 7; both test levels (spec Testing) are Tasks 2 to 4; the migration (spec Testing 3) is Task 1 step 8. registry.go is correctly out of scope (spec: reuses `discoverForVerification`).
- **Placeholder scan:** the Task 4 handler and manifest bytes are described as concrete endpoints to implement, not left vague; the one intentional flexibility (hand rolled handler versus an oras test double) is bounded by fixed assertions, matching the spec.
- **Type consistency:** `NewTarget func(ctx context.Context, repo string) (oras.ReadOnlyGraphTarget, error)` is used identically in the struct, the CLI (`d.ReadTarget`), and every test factory; `resolveOCIIdentity` returns the scoped target threaded via `identity.ociTarget`; `AttestationRef`'s `(repo, tag, err)` return is consumed the same way in `discoverByTag` and Task 4.
- **Out of scope, reaffirmed:** the offline mcp-server-through-the-hook subject digest path is not touched.
