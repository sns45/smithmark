// Package codes holds the stable identifiers smithmark attaches to
// diagnostics, errors, and reports. Task 1.5 completes the registry; this
// file stays deliberately minimal until then.
package codes

// SigningUnavailablePlatform reports that signing could not proceed because
// the current platform lacks a required signing capability.
const SigningUnavailablePlatform = "SIGNING_UNAVAILABLE_PLATFORM"

// Manifest semantic validation codes (spec 3, decision D1). Task 1.3 defines
// these ahead of the full registry in Task 1.5.
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
)

// Skill bundle digest codes (spec 4). Task 1.4 defines these ahead of the
// full registry in Task 1.5.
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

// Verification check codes (spec 3, decision D4). Phase 3 (M3) is the first
// consumer of these; they are defined here now so the registry stays
// complete ahead of that work.
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
// above predates this registry; the codes in this block are reserved for
// Phase 2 (M2) and Phase 3 (M3) work that has not landed yet.
const (
	// SBOMForgesealMissing reports that the forgeseal binary required to
	// generate a dependency SBOM could not be found.
	SBOMForgesealMissing = "SBOM_FORGESEAL_MISSING"
	// SBOMForgesealVersionUnsupported reports that the installed forgeseal
	// binary is older than the minimum version this build requires.
	SBOMForgesealVersionUnsupported = "SBOM_FORGESEAL_VERSION_UNSUPPORTED"
	// RefUnmappable reports that an artifact name could not be mapped to a
	// valid OCI repository path segment.
	RefUnmappable = "REF_UNMAPPABLE"
	// AttestationBaseUnknown reports that no attestation base registry
	// could be resolved from the flag, environment variable, or package.json
	// key.
	AttestationBaseUnknown = "ATTESTATION_BASE_UNKNOWN"
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
		RefUnmappable,
		AttestationBaseUnknown,
	}
}
