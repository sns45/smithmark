// Package codes holds the stable identifiers smithmark attaches to
// diagnostics, errors, and reports. This file is the complete code registry:
// every constant here has a matching row in docs/codes.md, and later phases
// extend the registry by appending new constants and rows rather than starting
// a fresh list. The tests in this package keep the two in sync in both
// directions.
package codes

import "fmt"

// Error is a coded error: a stable, machine readable Code paired with a human
// readable Detail. Every documented failure the pure core returns is an
// *Error, so callers extract the Code with errors.As instead of matching on
// message text.
type Error struct {
	Code   string
	Detail string
}

// Error renders the coded error as "CODE: detail", the same prefix the core
// used before typed errors, so existing substring checks keep working.
func (e *Error) Error() string {
	return e.Code + ": " + e.Detail
}

// E builds a coded error, formatting Detail with fmt.Sprintf.
func E(code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// SigningUnavailablePlatform reports that signing could not proceed because
// the current platform lacks a required signing capability.
const SigningUnavailablePlatform = "SIGNING_UNAVAILABLE_PLATFORM"

// Manifest semantic validation codes (spec 3, decision D1).
const (
	// ManifestSchemaVersionUnsupported reports a schemaVersion other than the
	// one this build understands.
	ManifestSchemaVersionUnsupported = "MANIFEST_SCHEMA_VERSION_UNSUPPORTED"
	// ManifestKindSurfaceMismatch reports that the mcp or skill surface does
	// not match artifact.kind (mcp-server requires mcp and no skill, skill
	// requires skill and no mcp).
	ManifestKindSurfaceMismatch = "MANIFEST_KIND_SURFACE_MISMATCH"
	// ManifestEnumInvalid reports an artifact kind or source that is not one
	// of the known enum values.
	ManifestEnumInvalid = "MANIFEST_ENUM_INVALID"
	// ManifestVersionRequired reports a missing artifact version where one is
	// required (every kind except skill, per U4).
	ManifestVersionRequired = "MANIFEST_VERSION_REQUIRED"
	// ManifestCapabilitiesKeyMissing reports that one of the five capability
	// keys was absent (a nil slice) rather than declared empty.
	ManifestCapabilitiesKeyMissing = "MANIFEST_CAPABILITIES_KEY_MISSING"
	// EgressHostInvalid reports a network egress host that does not match the
	// D1 host grammar.
	EgressHostInvalid = "EGRESS_HOST_INVALID"
	// EgressPortInvalid reports a network egress port outside 1 to 65535.
	EgressPortInvalid = "EGRESS_PORT_INVALID"
	// FSAccessInvalid reports a filesystem access mode other than read,
	// write, or readwrite.
	FSAccessInvalid = "FS_ACCESS_INVALID"
	// FSPathInvalid reports a filesystem path that does not match the D1
	// path grammar.
	FSPathInvalid = "FS_PATH_INVALID"
	// EnvNameInvalid reports an env entry that does not match the D1 env
	// name grammar.
	EnvNameInvalid = "ENV_NAME_INVALID"
	// SecretFormatInvalid reports a secret entry that is not a kind:provider
	// pair matching the D1 grammar.
	SecretFormatInvalid = "SECRET_FORMAT_INVALID"
	// TransportInvalid reports an MCP transport other than stdio, http, or
	// sse.
	TransportInvalid = "TRANSPORT_INVALID"
	// ModeInvalid reports a file mode other than regular or executable.
	ModeInvalid = "MODE_INVALID"
	// DigestInvalid reports a digest set that is empty, has an empty key, or
	// has a value that is not lowercase hex of even length.
	DigestInvalid = "DIGEST_INVALID"
	// StatementSubjectMismatch reports that the artifact reference handed to
	// statement assembly disagrees with the predicate artifact block on name,
	// version, or source. Kind disagreements keep using
	// ManifestKindSurfaceMismatch, since kind is what selects the surface.
	StatementSubjectMismatch = "STATEMENT_SUBJECT_MISMATCH"
	// ExecBinaryInvalid reports an exec rule binary that is empty or contains
	// a slash or backslash; only basename patterns are allowed (D1).
	ExecBinaryInvalid = "EXEC_BINARY_INVALID"
	// ManifestSurfaceKeyMissing reports that a required surface array key was
	// absent (a nil slice) rather than declared empty: mcp requires tools,
	// resources, prompts, and transports; skill requires scripts and
	// invokesTools.
	ManifestSurfaceKeyMissing = "MANIFEST_SURFACE_KEY_MISSING"
	// GeneratedAtInvalid reports a generatedAt timestamp that is zero, not in
	// UTC, or carries sub second precision.
	GeneratedAtInvalid = "GENERATED_AT_INVALID"
	// ManifestFieldRequired reports a required identity string that is empty,
	// such as artifact.name, a generator field, an mcp tool name, or a
	// dependency SBOM field when the dependencies block is present. It is also
	// raised by the skill walker when a bundle is missing its required
	// SKILL.md entry file.
	ManifestFieldRequired = "MANIFEST_FIELD_REQUIRED"
	// SkillScriptPathInvalid reports a skill script path that is not a clean
	// relative path with forward slashes, or a duplicate script path.
	SkillScriptPathInvalid = "SKILL_SCRIPT_PATH_INVALID"
	// StatementSubjectInvalid reports a parsed statement that does not carry
	// exactly one subject with a non empty name (D6 binds one artifact).
	StatementSubjectInvalid = "STATEMENT_SUBJECT_INVALID"
)

// Skill bundle digest codes (spec 4).
const (
	// BundleEmpty reports that a skill bundle was given no files to digest.
	BundleEmpty = "BUNDLE_EMPTY"
	// BundlePathInvalid reports a file path that is not a clean relative path
	// with forward slashes, for example an absolute path, a backslash, or a
	// dotdot segment.
	BundlePathInvalid = "BUNDLE_PATH_INVALID"
	// BundleDuplicatePath reports two entries in a bundle with the same path.
	BundleDuplicatePath = "BUNDLE_DUPLICATE_PATH"
	// BundleModeInvalid reports a file mode other than regular or executable.
	BundleModeInvalid = "BUNDLE_MODE_INVALID"
	// BundleDigestInvalid reports a file sha256 that is not lowercase hex of
	// the expected length.
	BundleDigestInvalid = "BUNDLE_DIGEST_INVALID"
	// BundleSymlinkRejected reports that a symlink was found while walking a
	// skill root. Defined here for the registry; it is returned only by the
	// Phase 2 filesystem walker, not by this pure package, since pkg/core
	// never touches the filesystem.
	BundleSymlinkRejected = "BUNDLE_SYMLINK_REJECTED"
)

// Verification check codes (spec 3; decisions D2, D4, D5; open item U3).
// AttestationMissing traces to U3, DependencySBOMMissing to D2, and
// HostedEndpointUnsupported to D5; D4 fixes the exit code contract the
// checks feed. Phase 3 (M3) is the first consumer of these; they are
// defined here now so the registry stays complete ahead of that work.
const (
	// SignatureValid reports that the DSSE envelope signature verified
	// successfully.
	SignatureValid = "SIGNATURE_VALID"
	// RekorInclusionValid reports that the signature's Rekor transparency
	// log inclusion proof verified successfully.
	RekorInclusionValid = "REKOR_INCLUSION_VALID"
	// SubjectDigestMatch reports that the attested subject digest matches
	// the digest of the artifact being verified.
	SubjectDigestMatch = "SUBJECT_DIGEST_MATCH"
	// ManifestSchemaValid reports that the capability manifest carried by
	// the attestation passed semantic validation.
	ManifestSchemaValid = "MANIFEST_SCHEMA_VALID"
	// ProvenancePresent reports that a provenance attestation was found
	// alongside the artifact.
	ProvenancePresent = "PROVENANCE_PRESENT"
	// NPMProvenanceVerified reports that an npm package's own provenance
	// attestation verified successfully.
	NPMProvenanceVerified = "NPM_PROVENANCE_VERIFIED"
	// AttestationMissing reports that no attestation bundle was found for
	// the artifact, so verification fails outright.
	AttestationMissing = "ATTESTATION_MISSING"
	// DependencySBOMMissing reports, informationally, that the manifest
	// carries no dependency SBOM reference.
	DependencySBOMMissing = "DEPENDENCY_SBOM_MISSING"
	// PredicateVersionUnsupported reports that the attestation statement's
	// predicate version is not one this build understands.
	PredicateVersionUnsupported = "PREDICATE_VERSION_UNSUPPORTED"
	// HostedEndpointUnsupported reports, informationally, that a registry
	// entry points only at a remote endpoint this build does not attest.
	HostedEndpointUnsupported = "HOSTED_ENDPOINT_UNSUPPORTED"
)

// Lint finding codes (spec 3). Phase 4 (M4) is the first consumer of these;
// they are defined here now so the registry stays complete ahead of that
// work.
const (
	// UndeclaredNetworkEgress reports detected code performing network
	// egress the manifest does not declare.
	UndeclaredNetworkEgress = "UNDECLARED_NETWORK_EGRESS"
	// UndeclaredFilesystem reports detected code accessing the filesystem
	// in a way the manifest does not declare.
	UndeclaredFilesystem = "UNDECLARED_FILESYSTEM"
	// UndeclaredExec reports detected code executing a binary the manifest
	// does not declare.
	UndeclaredExec = "UNDECLARED_EXEC"
	// UndeclaredEnv reports detected code reading an environment variable
	// the manifest does not declare.
	UndeclaredEnv = "UNDECLARED_ENV"
	// ToolListingMismatch reports that the declared MCP tool listing
	// disagrees with the tools extracted from the live server.
	ToolListingMismatch = "TOOL_LISTING_MISMATCH"
)

// Operational codes (spec 2.2, decisions D2 and D3). SigningUnavailablePlatform
// above predates this registry; the codes in this block belong to Phase 2
// (M2) and Phase 3 (M3) work, landing incrementally as each task ships.
const (
	// SBOMForgesealMissing reports that the forgeseal binary required to
	// generate a dependency SBOM could not be found.
	SBOMForgesealMissing = "SBOM_FORGESEAL_MISSING"
	// SBOMForgesealVersionUnsupported reports that the installed forgeseal
	// binary is older than the minimum version this build requires, or that
	// its reported version string could not be parsed as semver at all;
	// "dev" (a maintainer's own local build) is always accepted.
	SBOMForgesealVersionUnsupported = "SBOM_FORGESEAL_VERSION_UNSUPPORTED"
	// SBOMForgesealOutputInvalid reports that the forgeseal sbom output was
	// not a valid CycloneDX document: it failed strict parsing, or it
	// decoded but lacked the CycloneDX bomFormat marker or a specVersion.
	// A semantically empty document must never reach a signed manifest.
	SBOMForgesealOutputInvalid = "SBOM_FORGESEAL_OUTPUT_INVALID"
	// RefUnmappable reports that an artifact name could not be mapped to a
	// valid OCI repository path segment.
	RefUnmappable = "REF_UNMAPPABLE"
	// AttestationBaseUnknown reports that no attestation base registry
	// could be resolved from the flag, environment variable, or package.json
	// key.
	AttestationBaseUnknown = "ATTESTATION_BASE_UNKNOWN"
	// ToolExtractionFailed reports that extracting the MCP tool listing from
	// a running stdio server failed: the declaration carried no launch command
	// to run, the process could not be started or exited unexpectedly, the
	// protocol handshake did not match, or the context deadline was exceeded
	// before tools/list returned.
	ToolExtractionFailed = "TOOL_EXTRACTION_FAILED"
	// SigningConfigInvalid reports that a signing request carried no usable
	// signing configuration: neither a key path for key based signing nor the
	// full set of keyless inputs (Fulcio, Rekor, an OIDC issuer, and an
	// identity token). It is distinct from SigningUnavailablePlatform, which
	// means the platform itself cannot sign; this code means the platform can
	// sign but the caller told it nothing to sign with.
	SigningConfigInvalid = "SIGNING_CONFIG_INVALID"
	// PublishBundleInvalid reports that PushAttestation or AttachReferrer was
	// given a nil signed bundle, one carrying no bundle bytes, or one carrying
	// an empty MediaType, to push.
	PublishBundleInvalid = "PUBLISH_BUNDLE_INVALID"
	// PublishTagInvalid reports that a tag handed to PushAttestation does not
	// match the OCI distribution spec tag grammar. pkg/discover.AttestationRef
	// is the normative producer of push tags and already builds them in a
	// provably safe shape (Task 2.6); this code fires only when a caller
	// supplies some other tag by hand, and it is checked before any push is
	// attempted.
	PublishTagInvalid = "PUBLISH_TAG_INVALID"
	// AttestSubjectUnresolved reports that attest could not resolve exactly one
	// subject artifact to attest. For an mcp-server it means no --tarball was
	// supplied and the artifact root held zero, or more than one, *.tgz tarball
	// to digest, so the subject is ambiguous; or the chosen tarball is not a
	// gzip stream, cannot be read as a tar, or carries no package/package.json,
	// so it is not an npm package tarball at all. attest fails closed rather
	// than guessing which one to attest.
	AttestSubjectUnresolved = "ATTEST_SUBJECT_UNRESOLVED"
	// InternalError reports that an error carrying no registry code reached the
	// command boundary. The CLI maps every failure to a single machine readable
	// stderr line (decision D4); an error the pure core did not tag with a code
	// is surfaced under this operational code rather than an empty one.
	InternalError = "INTERNAL_ERROR"
)

// All returns every registered code.
func All() []string {
	return []string{
		SigningUnavailablePlatform,
		ManifestSchemaVersionUnsupported,
		ManifestKindSurfaceMismatch,
		ManifestEnumInvalid,
		ManifestVersionRequired,
		ManifestCapabilitiesKeyMissing,
		EgressHostInvalid,
		EgressPortInvalid,
		FSAccessInvalid,
		FSPathInvalid,
		EnvNameInvalid,
		SecretFormatInvalid,
		TransportInvalid,
		ModeInvalid,
		DigestInvalid,
		StatementSubjectMismatch,
		ExecBinaryInvalid,
		ManifestSurfaceKeyMissing,
		GeneratedAtInvalid,
		ManifestFieldRequired,
		SkillScriptPathInvalid,
		StatementSubjectInvalid,
		BundleEmpty,
		BundlePathInvalid,
		BundleDuplicatePath,
		BundleModeInvalid,
		BundleDigestInvalid,
		BundleSymlinkRejected,
		SignatureValid,
		RekorInclusionValid,
		SubjectDigestMatch,
		ManifestSchemaValid,
		ProvenancePresent,
		NPMProvenanceVerified,
		AttestationMissing,
		DependencySBOMMissing,
		PredicateVersionUnsupported,
		HostedEndpointUnsupported,
		UndeclaredNetworkEgress,
		UndeclaredFilesystem,
		UndeclaredExec,
		UndeclaredEnv,
		ToolListingMismatch,
		SBOMForgesealMissing,
		SBOMForgesealVersionUnsupported,
		SBOMForgesealOutputInvalid,
		RefUnmappable,
		AttestationBaseUnknown,
		ToolExtractionFailed,
		SigningConfigInvalid,
		PublishBundleInvalid,
		PublishTagInvalid,
		AttestSubjectUnresolved,
		InternalError,
	}
}
