# Live OCI discovery repository scoping (smithmark#4)

**Issue:** https://github.com/sns45/smithmark/issues/4
**Status:** design approved 2026-07-18, pending spec review.
**Scope decision:** live discovery scoping only. Closing the offline mcp-server-through-the-hook demo (a separate subject digest path) is explicitly out of scope.

## Problem

`smithmark verify` discovers OCI backed attestations by mapping an artifact onto its D3 deterministic `(repository, tag)` pair and resolving the tag against an oras target. Two things are mis wired so that a live registry lookup queries the wrong repository:

1. `discoverByTag` (`pkg/discover/resolve.go`) computes `_, tag, err := AttestationRef(base, ref)`, discarding the repository half. The deterministic per artifact repository the D3 scheme computes (`<base>/<ecosystem>/<encoded-name>`) never reaches the target.
2. The CLI (`cmd/smithmark/verify.go`, `registry.go`) pre builds a single `oras.ReadOnlyGraphTarget` from the raw `--attestation-base` value and passes it as `ResolveOptions.Target`. An oras `remote.Repository` is bound to one repository path, so resolving the D3 tag against a base scoped client queries `<base>:<tag>` instead of `<base>/<ecosystem>/<encoded-name>:<tag>`.
3. The same mis scoping affects the OCI referrers path (`resolveOCIIdentity` and `discoverReferrers` in `pkg/discover/oci.go`), which resolves an oci reference argument and lists its referrers against the same base scoped `opts.Target` rather than the image's own repository.

The repository cannot be pre built in the CLI because it depends on the resolved artifact ref, which is only known partway through `Resolve`. So target construction must move to the two discovery sites where the repository is known.

This is invisible today because every test injects a pre built in memory target and never exercises repository scoping. The first live consumer (the M6 dogfood, and any real `smithmark verify <npm-server>@<version>`) is the first to scope a real registry client, and it must land this wiring.

## Design

### Architecture change

Replace the pre built target field with a factory:

```
// before
type ResolveOptions struct {
    ...
    Target oras.ReadOnlyGraphTarget
}

// after
type ResolveOptions struct {
    ...
    // NewTarget constructs a read only OCI target scoped to a specific
    // repository. Discovery computes the per artifact repository (the D3
    // <base>/<ecosystem>/<encoded-name> for the tag mapped path, or the image
    // reference's own repository for the referrers path) and calls NewTarget
    // with it, so the client queries the right path. A nil NewTarget means OCI
    // backed discovery is skipped with a note, not an error, exactly as a nil
    // Target did before.
    NewTarget func(ctx context.Context, repo string) (oras.ReadOnlyGraphTarget, error)
}
```

Target construction moves from the CLI into discovery, where the repository is known.

### Components touched

- **`pkg/discover/resolve.go`**
  - `discoverByTag`: keep the existing `base, err := ResolveAttestationBase(opts.Base, artifactRoot)` (already correct), change `_, tag` to `repo, tag`, then, when `opts.NewTarget != nil`, build `t, err := opts.NewTarget(ctx, repo)` and resolve/fetch against `t` instead of `opts.Target`. A nil `NewTarget` returns the existing `NoteNoOCITarget` skip note. A factory error is `DISCOVERY_FAILED`.
  - `ResolveOptions` doc comments rewritten to describe `NewTarget` and the two repository contexts.
  - The `Resolve` dispatch that calls `discoverReferrers(ctx, opts.Target, ...)` (resolve.go around line 194) is updated to route through the factory (see oci.go below).

- **`pkg/discover/oci.go`**
  - `resolveOCIIdentity`: parse the image repository from the oci reference argument, build the target with `opts.NewTarget(ctx, imageRepo)`, and resolve the reference against it. A nil `NewTarget` keeps today's skip behavior.
  - `discoverReferrers`: receives the already scoped target (constructed by `resolveOCIIdentity` for the same image repository) rather than a base scoped one, so the referrers query runs against the image's own repository.
  - Signatures adjusted so the scoped target threads from identity resolution into the referrers query for one artifact.

- **`cmd/smithmark/verify.go`**
  - `discoverForVerification`: set `opts.NewTarget = d.ReadTarget` (already the `func(ctx, repo) (oras.ReadOnlyGraphTarget, error)` shape) instead of pre resolving the base and setting `opts.Target`. Delete the pre build block and the stale "best effort hint ... refined when M6" comment.

- **`cmd/smithmark/registry.go`**
  - No change needed. `registry check`'s npm continuation reuses `discoverForVerification` (verified: `registry.go` calls it directly), so the verify.go change covers it. Its own `FetchRegistryEntry` options literal sets only `Transport`, never the OCI target field, so the rename does not touch it.

- **`cmd/smithmark/main.go`**
  - The production `ReadTarget` factory keeps its empty repository fail closed guard as defense in depth (now practically unreachable, since `AttestationRef` errors on an unresolved base before the factory is ever called) and drops its stale "#4 / lands with M6" comment. Reword to state the guard is a defensive backstop.

### Error handling (unchanged, already correct)

- Unresolvable base: `ResolveAttestationBase` returns `ATTESTATION_BASE_UNKNOWN` before any target is built.
- Ref that cannot be mapped: `AttestationRef` returns `REF_UNMAPPABLE` before the factory is called.
- Absent tag in the scoped repository: a discovery note (`NoteNoAttestationTag`), not an error (U3).
- Any other target resolve or fetch error, and any factory construction error: `DISCOVERY_FAILED`.

### Determinism and purity

No change to the pure core. `pkg/discover` remains the I/O layer; the factory is an injected function, so tests stay offline. The D3 ref scheme (`AttestationRef`) is unchanged; this only stops discarding its repository return.

## Testing (both levels, no network)

1. **Threading unit test** (`pkg/discover`, new): inject a `NewTarget` that records the `repo` string it is called with and returns an in memory store. Assert the recorded repo equals `<base>/npm/<encoded-name>` for an npm ref and the image reference's own repository for an oci ref. This is the test that pins the exact bug the issue says nothing catches today: the per artifact repository reaches target construction.

2. **Live-ish HTTP round trip** (`pkg/discover`, new): stand up a local `httptest` server implementing the minimal OCI distribution endpoints oras `remote.Repository` needs (manifest and tag resolve, blob and manifest fetch). Push an attestation manifest and its bundle layer to the per artifact repository path. Run discovery through a `NewTarget` that builds a real `remote.Repository` against the httptest server. Assert:
   - discovery finds the attestation at `<base>/<ecosystem>/<name>` and returns the bundle candidate;
   - discovery returns zero candidates (an absent tag note) when the same tag sits only at the bare `<base>` repository, proving the client is scoped to the per artifact repository and not the base.
   The exact construction (a hand rolled httptest handler versus an oras provided registry test double) is chosen during implementation for whichever is honest and cheap; the assertion is the fixed requirement. No real network.

3. **Migration**: the only production site that sets the target field is `discoverForVerification` in `cmd/smithmark/verify.go`; it moves to `opts.NewTarget = d.ReadTarget`. The roughly nine test sites in `pkg/discover/resolve_test.go` that set `Target: store` switch to `NewTarget: func(ctx, repo) (oras.ReadOnlyGraphTarget, error) { return store, nil }` (the `poisonTarget` case wraps the same way). Behavior is unchanged because the injected memory store is itself the single repository; the factory ignoring the repo argument preserves the prior semantics while the two new tests cover scoping.

## Scope boundary

- **In scope:** threading the per artifact repository through both discovery paths (tag mapped and referrers), the factory API change, the CLI and registry wiring, the production factory comment cleanup, and the two new tests plus the migration.
- **Out of scope:** the offline mcp-server-through-the-hook capability block, which needs a separate subject digest path (a caller provided or locally computed mcp-server digest) rather than a discovery scoping fix. Left for a distinct item.
- **Referrers path depth:** the referrers path gets the threading fix and the threading unit test; the full httptest round trip targets the npm tag mapped path, since that is the dogfood's real case. A referrers httptest round trip may be added if it is cheap, but is not required.

## Success criteria

- `discoverByTag` and `resolveOCIIdentity` build their target from the per artifact repository via `opts.NewTarget`, never from the bare base.
- The CLI passes `d.ReadTarget` as the factory and no longer pre resolves the base.
- The threading unit test fails against the current code (repo discarded) and passes after the change.
- The httptest round trip finds the attestation at the per artifact repository and not at the base.
- The full suite, `go vet`, `gofmt`, and the wasip1 `./pkg/...` build stay green; existing memory store tests pass after the mechanical migration.
