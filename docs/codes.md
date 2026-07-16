# smithmark: Machine Readable Codes

Every check, finding, and operational condition smithmark reports carries a stable, machine readable code. Codes are API: once documented here, a code is never renamed, never repurposed for a different meaning, and never removed, even if it becomes unreachable. New codes are added by appending a row to this table and a constant to `pkg/core/codes`; `pkg/core/codes.All()` and this table are kept in sync by `TestEveryCodeIsDocumented`.

**Kind** distinguishes how a code is used:
- `validation`: a semantic issue found in a capability manifest or skill bundle at parse or digest time.
- `check`: a pass or fail outcome recorded in a `VerificationReport` during `smithmark verify`.
- `finding`: a declared versus detected capability gap recorded by the capability lint.
- `operational`: a condition outside the pure core, such as a missing external tool or an unresolved configuration value.

**Introduced** is the milestone the constant first landed in this registry. A meaning that says "reserved for" a later milestone means the code is defined now but only produced once that milestone's feature ships.

| Code | Kind | Meaning | Introduced |
|------|------|---------|------------|
| `MANIFEST_SCHEMA_VERSION_UNSUPPORTED` | validation | The manifest declares a schemaVersion other than the one this build understands. | M1 |
| `MANIFEST_KIND_SURFACE_MISMATCH` | validation | The mcp or skill surface present on the manifest does not match the declared artifact kind. | M1 |
| `MANIFEST_ENUM_INVALID` | validation | The artifact kind or source is not one of the known enum values. | M1 |
| `MANIFEST_VERSION_REQUIRED` | validation | The artifact version is missing where one is required, meaning every kind except skill. | M1 |
| `MANIFEST_CAPABILITIES_KEY_MISSING` | validation | One of the five capability keys is absent instead of declared as an empty list. | M1 |
| `EGRESS_HOST_INVALID` | validation | A network egress host does not match the allowed host grammar of an exact name, an IP literal, a single leftmost wildcard label, or a bare wildcard. | M1 |
| `EGRESS_PORT_INVALID` | validation | A network egress port falls outside the range 1 to 65535. | M1 |
| `FS_ACCESS_INVALID` | validation | A filesystem access mode is not read, write, or readwrite. | M1 |
| `FS_PATH_INVALID` | validation | A filesystem path does not match the allowed path grammar of a portability token, a relative path, or an escape hatch wildcard. | M1 |
| `ENV_NAME_INVALID` | validation | An environment variable entry does not match the allowed name grammar. | M1 |
| `SECRET_FORMAT_INVALID` | validation | A secret entry is not a kind and provider pair matching the allowed grammar. | M1 |
| `TRANSPORT_INVALID` | validation | An MCP transport is not stdio, http, or sse. | M1 |
| `MODE_INVALID` | validation | A file mode is not regular or executable. | M1 |
| `DIGEST_INVALID` | validation | A digest set is empty, has an empty key, or has a value that is not lowercase hex of even length. | M1 |
| `BUNDLE_EMPTY` | validation | A skill bundle was given no files to digest. | M1 |
| `BUNDLE_PATH_INVALID` | validation | A bundle file path is not a clean relative path using forward slashes. | M1 |
| `BUNDLE_DUPLICATE_PATH` | validation | Two entries in a bundle share the same path. | M1 |
| `BUNDLE_MODE_INVALID` | validation | A bundle file mode is not regular or executable. | M1 |
| `BUNDLE_DIGEST_INVALID` | validation | A bundle file sha256 is not lowercase hex of the expected length. | M1 |
| `BUNDLE_SYMLINK_REJECTED` | validation | A symlink was found while walking a skill root; reserved for M2, since the pure core defined here never touches the filesystem itself. | M1 |
| `SIGNATURE_VALID` | check | The DSSE envelope signature verified successfully; reserved for M3. | M1 |
| `REKOR_INCLUSION_VALID` | check | The signature's transparency log inclusion proof verified successfully; reserved for M3. | M1 |
| `SUBJECT_DIGEST_MATCH` | check | The attested subject digest matches the digest of the artifact being verified; reserved for M3. | M1 |
| `MANIFEST_SCHEMA_VALID` | check | The capability manifest carried by the attestation passed semantic validation; reserved for M3. | M1 |
| `PROVENANCE_PRESENT` | check | A provenance attestation was found alongside the artifact; reserved for M3. | M1 |
| `NPM_PROVENANCE_VERIFIED` | check | An npm package's own provenance attestation verified successfully; reserved for M3. | M1 |
| `ATTESTATION_MISSING` | check | No attestation bundle was found for the artifact, so verification fails outright; reserved for M3. | M1 |
| `DEPENDENCY_SBOM_MISSING` | check | The manifest carries no dependency SBOM reference, reported informationally rather than as a failure; reserved for M3. | M1 |
| `PREDICATE_VERSION_UNSUPPORTED` | check | The predicate version inside the attestation statement is not one this build understands; reserved for M3. | M1 |
| `HOSTED_ENDPOINT_UNSUPPORTED` | check | A registry entry points only at a remote endpoint, reported informationally since this build does not attest hosted servers; reserved for M3. | M1 |
| `UNDECLARED_NETWORK_EGRESS` | finding | Detected code performs network egress the manifest does not declare; reserved for M4. | M1 |
| `UNDECLARED_FILESYSTEM` | finding | Detected code accesses the filesystem in a way the manifest does not declare; reserved for M4. | M1 |
| `UNDECLARED_EXEC` | finding | Detected code executes a binary the manifest does not declare; reserved for M4. | M1 |
| `UNDECLARED_ENV` | finding | Detected code reads an environment variable the manifest does not declare; reserved for M4. | M1 |
| `TOOL_LISTING_MISMATCH` | finding | The declared MCP tool listing disagrees with the tools extracted from the live server; reserved for M4. | M1 |
| `SIGNING_UNAVAILABLE_PLATFORM` | operational | Signing could not proceed because the current platform lacks a required signing capability; reserved for M2. | M1 |
| `SBOM_FORGESEAL_MISSING` | operational | The forgeseal binary required to generate a dependency SBOM could not be found; reserved for M2. | M1 |
| `SBOM_FORGESEAL_VERSION_UNSUPPORTED` | operational | The installed forgeseal binary is older than the minimum version this build requires; reserved for M2. | M1 |
| `REF_UNMAPPABLE` | operational | An artifact name could not be mapped to a valid OCI repository path segment; reserved for M2 and M3. | M1 |
| `ATTESTATION_BASE_UNKNOWN` | operational | No attestation base registry could be resolved from the flag, the environment variable, or the package.json key; reserved for M2 and M3. | M1 |
