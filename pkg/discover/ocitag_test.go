package discover

import (
	"strings"
	"testing"
)

// TestValidOCITag exercises ValidOCITag directly, ahead of and independent of
// pkg/compose's use of it as a push time last line of defense (Task 2.7).
// AttestationRef's own tags (asserted valid by assertValidOCITag in
// refmap_test.go) exercise the accepting side of this same function; these
// cases add the shapes a hand built tag might get wrong.
func TestValidOCITag(t *testing.T) {
	cases := []struct {
		name string
		tag  string
		want bool
	}{
		{name: "typical att tag", tag: "sha512-" + strings.Repeat("a", 64) + ".att", want: true},
		{name: "single char", tag: "a", want: true},
		{name: "leading underscore allowed", tag: "_leading", want: true},
		{name: "max length 128", tag: strings.Repeat("a", 128), want: true},
		{name: "empty", tag: "", want: false},
		{name: "leading hyphen rejected", tag: "-leading", want: false},
		{name: "leading dot rejected", tag: "." + strings.Repeat("a", 10), want: false},
		{name: "over max length", tag: strings.Repeat("a", 129), want: false},
		{name: "contains slash", tag: "not/a/tag", want: false},
		{name: "contains space", tag: "has space", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidOCITag(tc.tag); got != tc.want {
				t.Errorf("ValidOCITag(%q) = %v, want %v", tc.tag, got, tc.want)
			}
		})
	}
}
