package bundle

import (
	"strings"
	"testing"
)

func sampleFiles() []File {
	return []File{
		{Path: "scripts/fetch.py", Mode: ModeExecutable, SHA256: strings.Repeat("bb", 32)},
		{Path: "SKILL.md", Mode: ModeRegular, SHA256: strings.Repeat("aa", 32)},
		{Path: "references/notes.md", Mode: ModeRegular, SHA256: strings.Repeat("cc", 32)},
	}
}

// The pinned vector: computed once at implementation time, then frozen.
// Recompute by hand only if you believe the implementation is wrong, never
// to make a failing test pass.
const pinnedDigest = "smithmark-bundle-v1:e6b4a76c5a1ab47ea96100b15c6b287b4680ba93827e69d664ac99749d4a8395"

func TestDigestMatchesPinnedVector(t *testing.T) {
	got, err := Digest(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	if got != pinnedDigest {
		t.Errorf("digest drifted from the normative vector\n got: %s\nwant: %s", got, pinnedDigest)
	}
}

func TestDigestIsOrderIndependent(t *testing.T) {
	files := sampleFiles()
	reversed := []File{files[2], files[0], files[1]}
	a, _ := Digest(files)
	b, _ := Digest(reversed)
	if a != b {
		t.Error("input order changed the digest; entries must be sorted bytewise by path")
	}
}

func TestDigestIsModeSensitive(t *testing.T) {
	files := sampleFiles()
	a, _ := Digest(files)
	files[0].Mode = ModeRegular
	b, _ := Digest(files)
	if a == b {
		t.Error("mode change did not change the digest")
	}
}

func TestDigestRejectsBadInput(t *testing.T) {
	h := strings.Repeat("aa", 32)
	cases := []struct {
		name  string
		files []File
	}{
		{"empty set", nil},
		{"backslash path", []File{{Path: `scripts\x.py`, Mode: ModeRegular, SHA256: h}}},
		{"absolute path", []File{{Path: "/etc/x", Mode: ModeRegular, SHA256: h}}},
		{"dotdot segment", []File{{Path: "a/../b", Mode: ModeRegular, SHA256: h}}},
		{"dot segment", []File{{Path: "a/./b", Mode: ModeRegular, SHA256: h}}},
		{"double slash", []File{{Path: "a//b", Mode: ModeRegular, SHA256: h}}},
		{"duplicate path", []File{{Path: "a", Mode: ModeRegular, SHA256: h}, {Path: "a", Mode: ModeExecutable, SHA256: h}}},
		{"bad mode", []File{{Path: "a", Mode: "setuid", SHA256: h}}},
		{"short hash", []File{{Path: "a", Mode: ModeRegular, SHA256: "abcd"}}},
		{"uppercase hash", []File{{Path: "a", Mode: ModeRegular, SHA256: strings.ToUpper(h)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Digest(tc.files); err == nil {
				t.Error("expected error, got none")
			}
		})
	}
}
