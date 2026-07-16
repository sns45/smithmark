package discover

// This file is pure by contract even though the rest of pkg/discover is the
// I/O adapter layer: AttestationRef does no filesystem, network, or clock
// work, and its only imports are "strings" and pkg/core packages. Unlike
// pkg/core, pkg/discover is not covered by the internal/arch import guard
// (spec 2.1's automated check only scans ./pkg/core/...), so this header
// comment is the enforcement mechanism here: keep this file's import list
// exactly as narrow as it is today, and do not add "regexp" or anything with
// an I/O footprint without revisiting that guard first. "fmt" is allowed by
// the same resolution; this file simply has not needed it. The grammar
// checks below are written as manual byte scans specifically so this file
// never needs to import "regexp".

import (
	"strings"

	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// bundleDigestKey is the DigestSet key a skill's bundle digest is carried
// under (decision D6, U4): bundle.Prefix without its trailing colon. Reusing
// the exported constant from pkg/core/bundle keeps this file from hard coding
// the string a second time.
var bundleDigestKey = strings.TrimSuffix(bundle.Prefix, ":")

// npmDigestHexLen is the exact hex length an npm artifact's sha512 digest
// value must carry: 64 bytes encoded as hex is 128 characters. Only the
// first sha256DigestHexLen of these characters go into the tag (decision D3).
const npmDigestHexLen = 128

// sha256DigestHexLen is the exact hex length a sha256 style digest value
// must carry when the mapping uses it directly and in full: a skill bundle
// digest and a pypi sha256 digest are both 32 bytes encoded as hex, 64
// characters (decision D3).
const sha256DigestHexLen = 64

// npmSegment, pypiSegment, and skillSegment are the fixed ecosystem path
// segments D3 places between base and the encoded name.
const (
	npmSegment   = "npm"
	pypiSegment  = "pypi"
	skillSegment = "skill"
)

// AttestationRef returns the deterministic (repository, tag) pair under base
// for ref, per docs/decisions.md D3. Pure and total: the only errors it
// returns are coded ATTESTATION_BASE_UNKNOWN (base could not be resolved) and
// REF_UNMAPPABLE (ref cannot be expressed as an OCI ref under this scheme).
// It never panics and performs no I/O.
//
// Dispatch: kind skill always uses the skill mapping regardless of Source,
// since a skill's canonical home is its bundle digest, not where it was
// fetched from. Every other kind dispatches on Source: npm and pypi map to
// their ecosystem specific repository and tag; oci is rejected in favor of
// the native OCI referrers API on the image digest, which needs no ref
// mapping; local and mcp-registry are rejected because they have no
// canonical attestation home yet (the registry RFC's own attestation
// reference field is the eventual answer, decision D3).
func AttestationRef(base string, ref manifest.ArtifactRef) (repo string, tag string, err error) {
	host, basePath, err := splitBase(base)
	if err != nil {
		return "", "", err
	}
	for _, seg := range basePath {
		if !isOCIPathSegment(seg) {
			return "", "", codes.E(codes.RefUnmappable,
				"base path segment %q does not match the OCI repository path grammar", seg)
		}
	}

	var ecosystem string
	var encodedName string

	if ref.Kind == manifest.KindSkill {
		if !isSkillName(ref.Name) {
			return "", "", codes.E(codes.RefUnmappable,
				"skill name %q must match [a-z0-9-]+, no coercion is applied", ref.Name)
		}
		v, derr := requiredDigestHex(ref.Digest, bundleDigestKey, sha256DigestHexLen)
		if derr != nil {
			return "", "", derr
		}
		ecosystem = skillSegment
		encodedName = ref.Name
		tag = "bundle-v1-" + v + ".att"
	} else {
		switch ref.Source {
		case manifest.SourceNPM:
			v, derr := requiredDigestHex(ref.Digest, "sha512", npmDigestHexLen)
			if derr != nil {
				return "", "", derr
			}
			ecosystem = npmSegment
			encodedName = encodeNPMName(ref.Name)
			tag = "sha512-" + v[:sha256DigestHexLen] + ".att"
		case manifest.SourcePyPI:
			v, derr := requiredDigestHex(ref.Digest, "sha256", sha256DigestHexLen)
			if derr != nil {
				return "", "", derr
			}
			ecosystem = pypiSegment
			encodedName = normalizePyPIName(ref.Name)
			tag = "sha256-" + v + ".att"
		case manifest.SourceOCI:
			return "", "", codes.E(codes.RefUnmappable,
				"oci sourced artifacts have no attestation ref mapping; use the native OCI referrers API on the image digest instead")
		case manifest.SourceLocal, manifest.SourceMCPRegistry:
			return "", "", codes.E(codes.RefUnmappable,
				"source %q has no canonical attestation home yet; the registry RFC attestation reference field is the eventual answer", ref.Source)
		default:
			return "", "", codes.E(codes.RefUnmappable,
				"source %q is not mapped to an attestation ref", ref.Source)
		}
	}

	nameSegs := strings.Split(encodedName, "/")
	for _, seg := range nameSegs {
		if !isOCIPathSegment(seg) {
			return "", "", codes.E(codes.RefUnmappable,
				"encoded name segment %q does not match the OCI repository path grammar", seg)
		}
	}

	segs := make([]string, 0, 2+len(basePath)+len(nameSegs))
	segs = append(segs, host)
	segs = append(segs, basePath...)
	segs = append(segs, ecosystem)
	segs = append(segs, nameSegs...)
	repo = strings.Join(segs, "/")
	return repo, tag, nil
}

// splitBase validates and decomposes base into its registry host (exempt
// from the OCI path segment grammar; hosts may carry dots, colons for ports,
// and get lowercased) and the remaining path segments, which the caller
// grammar checks. A base that is empty, all whitespace, or reduces to nothing
// once a single trailing slash is stripped errors ATTESTATION_BASE_UNKNOWN.
func splitBase(base string) (host string, path []string, err error) {
	trimmed := strings.TrimSpace(base)
	if trimmed == "" {
		return "", nil, codes.E(codes.AttestationBaseUnknown, "attestation base is empty")
	}
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" {
		return "", nil, codes.E(codes.AttestationBaseUnknown, "attestation base is empty")
	}
	segs := strings.Split(trimmed, "/")
	return strings.ToLower(segs[0]), segs[1:], nil
}

// requiredDigestHex looks up key in ds and returns its value, requiring the
// value to be exactly wantLen hex characters, naming the key and the
// observed length otherwise. The manifest layer already validated every
// DigestSet value as hex (decisions D6, U6); this function checks presence
// and exact length only. Exactness matters because an npm sha512 hex value
// is always 128 characters, of which only the first 64 go into the tag,
// while a skill bundle digest and a pypi sha256 digest are always exactly 64
// characters used in full; any other observed length signals a digest that
// does not belong to the algorithm this mapping expects, so it is rejected
// rather than silently truncated or padded.
func requiredDigestHex(ds manifest.DigestSet, key string, wantLen int) (string, error) {
	v := ds[key]
	if len(v) != wantLen {
		return "", codes.E(codes.RefUnmappable,
			"digest key %q must be exactly %d hex characters, got %d", key, wantLen, len(v))
	}
	return v, nil
}

// encodeNPMName maps npm @scope/name to scope/name (stripping the leading at
// sign; npm has no unscoped name containing a slash, so this is injective)
// and lowercases the result, scoped or not (decision D3).
func encodeNPMName(name string) string {
	return strings.ToLower(strings.TrimPrefix(name, "@"))
}

// normalizePyPIName applies the PEP 503 normalization decision D3 requires:
// lowercase, with every run of hyphens, underscores, and dots collapsed to a
// single hyphen.
func normalizePyPIName(name string) string {
	lower := strings.ToLower(name)
	var b strings.Builder
	inRun := false
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c == '-' || c == '_' || c == '.' {
			if !inRun {
				b.WriteByte('-')
				inRun = true
			}
			continue
		}
		inRun = false
		b.WriteByte(c)
	}
	return b.String()
}

// isLowerAlnum reports whether b is an ASCII lowercase letter or digit.
func isLowerAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// isSkillName reports whether s matches [a-z0-9-]+ exactly: skill names are
// taken verbatim from SKILL.md frontmatter and never coerced (decision D3).
func isSkillName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !isLowerAlnum(b) && b != '-' {
			return false
		}
	}
	return true
}

// isOCIPathSegment reports whether s matches the OCI distribution spec
// repository path component grammar,
// [a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*, hand written rather than built on
// "regexp" so this file's import list stays as narrow as its header
// documents. It requires an initial run of lowercase alphanumerics, then zero
// or more (separator, alphanumeric run) pairs where a separator is a single
// dot, a single or double underscore, or one or more hyphens; a segment may
// not start or end with a separator.
func isOCIPathSegment(s string) bool {
	i, n := 0, len(s)
	consumeAlnum := func() bool {
		start := i
		for i < n && isLowerAlnum(s[i]) {
			i++
		}
		return i > start
	}
	if !consumeAlnum() {
		return false
	}
	for i < n {
		switch s[i] {
		case '.':
			i++
		case '_':
			i++
			if i < n && s[i] == '_' {
				i++
			}
		case '-':
			for i < n && s[i] == '-' {
				i++
			}
		default:
			return false
		}
		if !consumeAlnum() {
			return false
		}
	}
	return true
}
