// Package codes holds the stable identifiers smithmark attaches to
// diagnostics, errors, and reports. Task 1.5 completes the registry; this
// file stays deliberately minimal until then.
package codes

// SigningUnavailablePlatform reports that signing could not proceed because
// the current platform lacks a required signing capability.
const SigningUnavailablePlatform = "SIGNING_UNAVAILABLE_PLATFORM"

// All returns every registered code.
func All() []string {
	return []string{SigningUnavailablePlatform}
}
