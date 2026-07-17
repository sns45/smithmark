// Package lint holds the capability lint domain types and detection
// heuristics (spec 3, spec 5 `smithmark lint`). The Finding type, defined in
// Task 3.3, is the single shape a lint result takes, so pkg/core/verify's
// VerificationReport can embed a Findings slice from M3 onward. Task 4.1
// adds the first detection heuristics, DetectJS, plus the Source and
// Detection shapes it reads and produces; the declared versus detected gap
// engine that turns a Detection into a Finding lands in Task 4.3. This
// package stays pure and never touches a filesystem itself, exactly like the
// rest of pkg/core: sources always arrive pre read as bytes.
package lint

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Finding is one capability lint result: a stable machine readable Code, a
// Severity, a human readable Detail, and the source Location it was found at.
// Its field set and JSON encoding are fixed here in M3 so a VerificationReport
// serialized today carries the same finding shape a Phase 4 build will emit.
type Finding struct {
	Code     string `json:"code"`     // stable, from pkg/core/codes
	Severity string `json:"severity"` // low | medium | high
	Detail   string `json:"detail"`
	Location string `json:"location"` // file:line
}

// Source is one pre read source file handed to a detector. Path drives
// extension based routing and becomes the file half of a Detection's
// Location; Content is the file's raw bytes. Callers read files themselves
// and pass the bytes in here, so the detectors, like the rest of pkg/core,
// never touch the filesystem.
type Source struct {
	Path    string
	Content []byte
}

// Detection is one capability class match a detector found in a Source, at a
// specific line. Class is one of network, filesystem, exec, or env. Symbol
// names the matched construct, such as fetch or child_process. Location is
// file:line, one based, matching a Finding's Location shape.
type Detection struct {
	Class    string
	Symbol   string
	Location string
}

// jsExtensions are the file extensions DetectJS scans; every other Source is
// skipped silently. DetectPython owns .py starting Task 4.2.
var jsExtensions = []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

// jsPattern pairs one compiled regexp with the Class and Symbol DetectJS
// reports when it matches a line.
type jsPattern struct {
	class   string
	symbol  string
	pattern *regexp.Regexp
}

// jsPatterns is the JS and TS capability detection table (spec 9): package
// level, compiled once, case sensitive. Patterns match anywhere within a
// line rather than requiring the whole line, since real call sites carry
// arbitrary leading indentation and surrounding code. Both single and double
// quoted module strings are accepted, since either is ordinary, obvious JS
// style and restricting to one would create an unrecorded false negative.
//
// The five bare identifier and call patterns (fetch, axios, undici, execa,
// child_process) carry \b word boundary anchors so a real identifier that
// merely contains one as a substring, such as customfetch( or
// myaxioswrapper, does not match; a quoted module string such as "axios"
// still matches, since the surrounding quotes are themselves boundaries.
// Bun.spawn, process.env, and fs/promises stay unanchored on purpose: each
// already carries a structural dot or slash a bare identifier collision
// would rarely reproduce, and, like the comment and string literal case
// documented on DetectJS, an occasional stray substring match there is an
// accepted heuristic tradeoff, not a defect.
//
// Order matters only for which Symbol is reported when two patterns of the
// same class both match one line: the first match in this order wins, and
// DetectJS still emits only one Detection for that line and class either
// way (see the DetectJS doc comment).
var jsPatterns = []jsPattern{
	// network
	{"network", "fetch", regexp.MustCompile(`\bfetch\(`)},
	{"network", "http", regexp.MustCompile(`require\(\s*["']http["']\s*\)`)},
	{"network", "https", regexp.MustCompile(`require\(\s*["']https["']\s*\)`)},
	{"network", "net", regexp.MustCompile(`require\(\s*["']net["']\s*\)`)},
	{"network", "http", regexp.MustCompile(`from\s*["']http["']`)},
	{"network", "https", regexp.MustCompile(`from\s*["']https["']`)},
	{"network", "net", regexp.MustCompile(`from\s*["']net["']`)},
	{"network", "axios", regexp.MustCompile(`\baxios\b`)},
	{"network", "undici", regexp.MustCompile(`\bundici\b`)},
	// filesystem
	{"filesystem", "fs", regexp.MustCompile(`require\(\s*["']fs["']\s*\)`)},
	{"filesystem", "fs", regexp.MustCompile(`from\s*["']fs["']`)},
	{"filesystem", "fs/promises", regexp.MustCompile(`fs/promises`)},
	// exec
	{"exec", "child_process", regexp.MustCompile(`\bchild_process\b`)},
	{"exec", "execa", regexp.MustCompile(`\bexeca\b`)},
	{"exec", "Bun.spawn", regexp.MustCompile(`Bun\.spawn`)},
	// env
	{"env", "process.env", regexp.MustCompile(`process\.env`)},
}

// DetectJS scans JavaScript and TypeScript sources for capability
// heuristics (spec 3 capability lint, spec 9 lint testing rules). It is
// deliberately heuristic and advisory, never sound static analysis: v0.1
// promises detection of obvious undeclared capabilities, not proof of
// absence (spec 1.3). DetectJS never executes, evaluates, or otherwise
// interprets the scanned source; it only matches literal, line anchored
// text against the package level pattern table.
//
// That posture carries accepted, documented limitations, each pinned by a
// test rather than left to prose alone. Known false positives: a commented
// out or otherwise inert construct still matches the line pattern, since
// comments and string literals are not parsed out
// (TestKnownFalsePositiveCommentedRequire). Three patterns, Bun.spawn,
// process.env, and fs/promises, are also left deliberately unanchored
// beyond their own structural dot or slash, so a substring collision inside
// some other identifier or path is possible in principle, the same accepted
// tradeoff as the comment case, though no such collision is common enough
// in practice to carry its own named test. Known false negatives: a
// dynamically computed import specifier and a capability hidden behind eval
// are never followed, since DetectJS matches literal text only and never
// evaluates anything (TestKnownFalseNegativeDynamicImport,
// TestKnownFalseNegativeEval).
//
// Only Sources whose Path ends in .js, .jsx, .ts, .tsx, .mjs, or .cjs are
// scanned; every other Source is skipped silently, since Python sources are
// DetectPython's responsibility starting Task 4.2.
//
// The result is sorted by path, then by line as a number, then by Class,
// then by Symbol, so identical input bytes produce byte identical output on
// every call. The sort deliberately compares the parsed line number rather
// than the flat "path:line" Location string: comparing Location as one
// string would sort "path:10" before "path:7", since "1" is
// lexicographically less than "7", putting line 10 ahead of line 7. At most
// one Detection is emitted per line per class, even when more than one
// pattern of that class matches the same line; distinct classes matching
// the same line each still produce their own Detection.
func DetectJS(files []Source) []Detection {
	var dets []jsDetection
	for _, f := range files {
		if !hasJSExtension(f.Path) {
			continue
		}
		dets = append(dets, scanJSSource(f)...)
	}
	sort.Slice(dets, func(i, j int) bool {
		if dets[i].path != dets[j].path {
			return dets[i].path < dets[j].path
		}
		if dets[i].line != dets[j].line {
			return dets[i].line < dets[j].line
		}
		if dets[i].class != dets[j].class {
			return dets[i].class < dets[j].class
		}
		return dets[i].symbol < dets[j].symbol
	})
	out := make([]Detection, len(dets))
	for i, d := range dets {
		out[i] = Detection{
			Class:    d.class,
			Symbol:   d.symbol,
			Location: fmt.Sprintf("%s:%d", d.path, d.line),
		}
	}
	return out
}

// hasJSExtension reports whether path ends in one of jsExtensions, ignoring
// case, so a Windows style .TS or .JS path is scanned the same as .ts or
// .js.
func hasJSExtension(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range jsExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// jsDetection is one pattern match found while scanning a Source, kept with
// its path and line number separate until after sorting. Formatting them
// into a single Location string before sorting would make the comparison a
// flat string compare, which sorts "path:10" before "path:7"; keeping line
// as an int lets DetectJS compare it numerically instead.
type jsDetection struct {
	class  string
	symbol string
	path   string
	line   int
}

// scanJSSource applies jsPatterns to f line by line, collapsing repeat
// matches of the same class on one line into a single jsDetection.
func scanJSSource(f Source) []jsDetection {
	var out []jsDetection
	scanner := bufio.NewScanner(bytes.NewReader(f.Content))
	// Real world sources occasionally carry one very long minified or
	// bundled line; raise the scanner's limit well past bufio's 64KiB
	// default so such a line is still scanned rather than silently dropped.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		matchedClasses := make(map[string]bool, len(jsPatterns))
		for _, p := range jsPatterns {
			if matchedClasses[p.class] {
				continue
			}
			if p.pattern.MatchString(line) {
				matchedClasses[p.class] = true
				out = append(out, jsDetection{
					class:  p.class,
					symbol: p.symbol,
					path:   f.Path,
					line:   lineNum,
				})
			}
		}
	}
	return out
}
