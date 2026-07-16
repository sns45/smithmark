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
	}
}
