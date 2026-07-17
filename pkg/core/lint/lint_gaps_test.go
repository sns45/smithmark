package lint_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/lint"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// TestGapsClassMatrix is the declared times detected grid the brief demands
// for network, filesystem, and exec: none declared and detected fires; a
// specific declaration and detected stays silent; a star declaration and
// detected stays silent; a declaration with nothing ever detected produces
// nothing at all, since over declaration is policy's business, not lint's
// (spec 1.3).
func TestGapsClassMatrix(t *testing.T) {
	cases := []struct {
		name       string
		declared   manifest.CapabilitySet
		detections []lint.Detection
		wantCode   string // empty means no Finding at all
	}{
		{
			name:       "network none declared fires",
			detections: []lint.Detection{{Class: "network", Symbol: "fetch", Location: "a.ts:1"}},
			wantCode:   codes.UndeclaredNetworkEgress,
		},
		{
			name: "network specific host declared suppresses",
			declared: manifest.CapabilitySet{
				NetworkEgress: []manifest.EgressRule{{Host: "api.example.com"}},
			},
			detections: []lint.Detection{{Class: "network", Symbol: "fetch", Location: "a.ts:1"}},
		},
		{
			name: "network star host declared suppresses",
			declared: manifest.CapabilitySet{
				NetworkEgress: []manifest.EgressRule{{Host: "*"}},
			},
			detections: []lint.Detection{{Class: "network", Symbol: "fetch", Location: "a.ts:1"}},
		},
		{
			name: "network declared but never detected produces nothing",
			declared: manifest.CapabilitySet{
				NetworkEgress: []manifest.EgressRule{{Host: "api.example.com"}},
			},
			detections: nil,
		},
		{
			name:       "filesystem none declared fires",
			detections: []lint.Detection{{Class: "filesystem", Symbol: "fs", Location: "a.ts:1"}},
			wantCode:   codes.UndeclaredFilesystem,
		},
		{
			name: "filesystem specific path declared suppresses",
			declared: manifest.CapabilitySet{
				Filesystem: []manifest.FSRule{{Path: "${home}/data", Access: "read"}},
			},
			detections: []lint.Detection{{Class: "filesystem", Symbol: "fs", Location: "a.ts:1"}},
		},
		{
			name: "filesystem star path declared suppresses",
			declared: manifest.CapabilitySet{
				Filesystem: []manifest.FSRule{{Path: "**", Access: "readwrite"}},
			},
			detections: []lint.Detection{{Class: "filesystem", Symbol: "fs", Location: "a.ts:1"}},
		},
		{
			name: "filesystem declared but never detected produces nothing",
			declared: manifest.CapabilitySet{
				Filesystem: []manifest.FSRule{{Path: "${home}/data", Access: "read"}},
			},
			detections: nil,
		},
		{
			name:       "exec none declared fires",
			detections: []lint.Detection{{Class: "exec", Symbol: "child_process", Location: "a.ts:1"}},
			wantCode:   codes.UndeclaredExec,
		},
		{
			name: "exec specific binary declared suppresses",
			declared: manifest.CapabilitySet{
				Exec: []manifest.ExecRule{{Binary: "git"}},
			},
			detections: []lint.Detection{{Class: "exec", Symbol: "child_process", Location: "a.ts:1"}},
		},
		{
			name: "exec star binary declared suppresses",
			declared: manifest.CapabilitySet{
				Exec: []manifest.ExecRule{{Binary: "*"}},
			},
			detections: []lint.Detection{{Class: "exec", Symbol: "child_process", Location: "a.ts:1"}},
		},
		{
			name: "exec declared but never detected produces nothing",
			declared: manifest.CapabilitySet{
				Exec: []manifest.ExecRule{{Binary: "git"}},
			},
			detections: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := lint.Gaps(c.declared, c.detections)
			if c.wantCode == "" {
				if len(findings) != 0 {
					t.Fatalf("Gaps() = %+v, want none", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("Gaps() = %+v, want exactly 1 finding", findings)
			}
			if findings[0].Code != c.wantCode {
				t.Errorf("Code = %q, want %q", findings[0].Code, c.wantCode)
			}
			if findings[0].Location != "a.ts:1" {
				t.Errorf("Location = %q, want a.ts:1", findings[0].Location)
			}
		})
	}
}

// TestGapsSeverities pins the fixed per class severities: network and exec
// are high, filesystem is medium.
func TestGapsSeverities(t *testing.T) {
	dets := []lint.Detection{
		{Class: "network", Symbol: "fetch", Location: "a.ts:1"},
		{Class: "filesystem", Symbol: "fs", Location: "a.ts:2"},
		{Class: "exec", Symbol: "child_process", Location: "a.ts:3"},
	}
	findings := lint.Gaps(manifest.CapabilitySet{}, dets)
	want := map[string]string{
		codes.UndeclaredNetworkEgress: "high",
		codes.UndeclaredFilesystem:    "medium",
		codes.UndeclaredExec:          "high",
	}
	if len(findings) != 3 {
		t.Fatalf("Gaps() = %+v, want 3 findings", findings)
	}
	for _, f := range findings {
		if want[f.Code] != f.Severity {
			t.Errorf("code %s severity = %q, want %q", f.Code, f.Severity, want[f.Code])
		}
	}
}

// TestGapsEnvNameMatrix is the env name matrix the brief demands: an exact
// declared match suppresses, a declared trailing star prefix match
// suppresses, a non matching declaration still fires (medium severity, the
// named case), no declaration at all fires (medium), a bare access with no
// declaration fires at low severity, any declaration at all (even one that
// names an unrelated variable) suppresses a bare access, and a bare
// declared "*" suppresses everything, named or not, since the same trailing
// star prefix rule that matches "AWS_*" against "AWS_KEY" also matches the
// empty prefix "*" leaves against any name.
func TestGapsEnvNameMatrix(t *testing.T) {
	cases := []struct {
		name         string
		declared     []string
		symbol       string
		wantFinding  bool
		wantSeverity string
	}{
		{name: "exact match declared suppresses", declared: []string{"AWS_KEY"}, symbol: "env:AWS_KEY"},
		{name: "trailing star prefix match suppresses", declared: []string{"AWS_*"}, symbol: "env:AWS_KEY"},
		{name: "non matching declaration still fires named", declared: []string{"OTHER_VAR"}, symbol: "env:AWS_KEY", wantFinding: true, wantSeverity: "medium"},
		{name: "no declarations fires named", symbol: "env:AWS_KEY", wantFinding: true, wantSeverity: "medium"},
		{name: "bare access with no declarations fires low", symbol: "process.env", wantFinding: true, wantSeverity: "low"},
		{name: "bare js access with any declaration suppressed", declared: []string{"UNRELATED"}, symbol: "process.env"},
		{name: "bare python os.environ with any declaration suppressed", declared: []string{"UNRELATED"}, symbol: "os.environ"},
		{name: "bare python os.getenv without declaration fires low", symbol: "os.getenv", wantFinding: true, wantSeverity: "low"},
		{name: "bare star declared suppresses named too", declared: []string{"*"}, symbol: "env:ANYTHING"},
		{name: "bare star declared suppresses bare too", declared: []string{"*"}, symbol: "process.env"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			declared := manifest.CapabilitySet{Env: c.declared}
			dets := []lint.Detection{{Class: "env", Symbol: c.symbol, Location: "a.ts:1"}}
			findings := lint.Gaps(declared, dets)
			if !c.wantFinding {
				if len(findings) != 0 {
					t.Fatalf("Gaps() = %+v, want none", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("Gaps() = %+v, want exactly 1 finding", findings)
			}
			if findings[0].Code != codes.UndeclaredEnv {
				t.Errorf("Code = %q, want %q", findings[0].Code, codes.UndeclaredEnv)
			}
			if findings[0].Severity != c.wantSeverity {
				t.Errorf("Severity = %q, want %q", findings[0].Severity, c.wantSeverity)
			}
		})
	}
}

// TestGapsEnvNamedDetailNamesVariable proves a named finding's Detail names
// the specific variable, not just a generic message.
func TestGapsEnvNamedDetailNamesVariable(t *testing.T) {
	dets := []lint.Detection{{Class: "env", Symbol: "env:AWS_KEY", Location: "a.ts:1"}}
	findings := lint.Gaps(manifest.CapabilitySet{}, dets)
	if len(findings) != 1 {
		t.Fatalf("Gaps() = %+v, want 1", findings)
	}
	if !strings.Contains(findings[0].Detail, "AWS_KEY") {
		t.Errorf("Detail = %q, want it to name AWS_KEY", findings[0].Detail)
	}
}

// TestGapsOverDeclaredCapabilityIsNotAFinding pins spec 1.3 directly: a
// declaration for a capability class that no Detection ever matches
// produces no Finding at all, across all three non env classes plus env,
// even when the declared set is large.
func TestGapsOverDeclaredCapabilityIsNotAFinding(t *testing.T) {
	declared := manifest.CapabilitySet{
		NetworkEgress: []manifest.EgressRule{{Host: "api.example.com"}},
		Filesystem:    []manifest.FSRule{{Path: "${home}/data", Access: "read"}},
		Exec:          []manifest.ExecRule{{Binary: "git"}},
		Env:           []string{"AWS_KEY", "DEBUG"},
	}
	findings := lint.Gaps(declared, nil)
	if len(findings) != 0 {
		t.Fatalf("Gaps() = %+v, want none (declared but never detected is not lint's business)", findings)
	}
}

// TestGapsDedupByCodeAndLocation proves two detections that would otherwise
// produce the same Code at the same Location collapse into a single
// Finding.
func TestGapsDedupByCodeAndLocation(t *testing.T) {
	dets := []lint.Detection{
		{Class: "network", Symbol: "fetch", Location: "a.ts:1"},
		{Class: "network", Symbol: "axios", Location: "a.ts:1"},
	}
	findings := lint.Gaps(manifest.CapabilitySet{}, dets)
	if len(findings) != 1 {
		t.Fatalf("Gaps() = %+v, want deduped to 1", findings)
	}
}

// TestGapsSortedByCodeThenNumericLocation proves the sort order: Code
// first, then Location with the same numeric line awareness DetectJS and
// DetectPython use, not a flat string compare (which would sort "a.ts:10"
// before "a.ts:7").
func TestGapsSortedByCodeThenNumericLocation(t *testing.T) {
	dets := []lint.Detection{
		{Class: "exec", Symbol: "child_process", Location: "z.ts:1"},
		{Class: "network", Symbol: "fetch", Location: "a.ts:10"},
		{Class: "network", Symbol: "axios", Location: "a.ts:7"},
	}
	findings := lint.Gaps(manifest.CapabilitySet{}, dets)
	if len(findings) != 3 {
		t.Fatalf("Gaps() = %+v, want 3", findings)
	}
	if findings[0].Code != codes.UndeclaredExec {
		t.Errorf("findings[0].Code = %q, want %q (UNDECLARED_EXEC sorts before UNDECLARED_NETWORK_EGRESS)", findings[0].Code, codes.UndeclaredExec)
	}
	if findings[1].Location != "a.ts:7" || findings[2].Location != "a.ts:10" {
		t.Errorf("findings[1:] = %+v, want a.ts:7 then a.ts:10 (numeric line order, not lexicographic)", findings[1:])
	}
}

// TestGapsDeterministic proves the same input produces byte identical
// output across repeated calls, and that the result is a non nil empty
// slice rather than nil when there is nothing to report, the same
// convention manifest.Validate uses so a JSON encoding renders [] rather
// than null.
func TestGapsDeterministic(t *testing.T) {
	dets := []lint.Detection{
		{Class: "network", Symbol: "fetch", Location: "a.ts:1"},
		{Class: "env", Symbol: "env:FOO", Location: "a.ts:2"},
	}
	first := lint.Gaps(manifest.CapabilitySet{}, dets)
	second := lint.Gaps(manifest.CapabilitySet{}, dets)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("Gaps is not deterministic:\nfirst  = %+v\nsecond = %+v", first, second)
	}

	empty := lint.Gaps(manifest.CapabilitySet{}, nil)
	if empty == nil {
		t.Errorf("Gaps(nil detections) = nil, want a non nil empty slice")
	}
	if len(empty) != 0 {
		t.Errorf("Gaps(nil detections) = %+v, want empty", empty)
	}
}

// TestGapsIntegratesWithDetectJS is a small end to end check that Gaps
// wires correctly against real DetectJS output, not just hand built
// Detection literals.
func TestGapsIntegratesWithDetectJS(t *testing.T) {
	src := lint.Source{
		Path:    "app.mjs",
		Content: []byte(`fetch("http://x"); const key = process.env.API_KEY;` + "\n"),
	}
	dets := lint.DetectJS([]lint.Source{src})
	findings := lint.Gaps(manifest.CapabilitySet{}, dets)
	if len(findings) != 2 {
		t.Fatalf("Gaps() = %+v, want 2 (network fetch, env API_KEY)", findings)
	}
	var gotNetwork, gotEnv bool
	for _, f := range findings {
		switch f.Code {
		case codes.UndeclaredNetworkEgress:
			gotNetwork = true
		case codes.UndeclaredEnv:
			gotEnv = true
			if !strings.Contains(f.Detail, "API_KEY") {
				t.Errorf("env Detail = %q, want it to name API_KEY", f.Detail)
			}
		}
	}
	if !gotNetwork || !gotEnv {
		t.Errorf("findings = %+v, want both network and env codes", findings)
	}
}
