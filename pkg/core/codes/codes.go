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
	}
}
