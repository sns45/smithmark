// Package lint holds the capability lint domain types and detection
// heuristics (spec 3, spec 5 `smithmark lint`). The Finding type, defined in
// Task 3.3, is the single shape a lint result takes, so pkg/core/verify's
// VerificationReport can embed a Findings slice from M3 onward. Task 4.1
// adds the first detection heuristics, DetectJS, plus the Source and
// Detection shapes it reads and produces; Task 4.2 adds DetectPython as its
// twin for Python sources, sharing the same scanning, dedup, and sort
// machinery; the declared versus detected gap engine that turns a Detection
// into a Finding lands in Task 4.3. This package stays pure and never
// touches a filesystem itself, exactly like the rest of pkg/core: sources
// always arrive pre read as bytes. Task 4.3 adds that gap engine, Gaps,
// plus the name aware env Symbol capture ("env:FOO") both DetectJS and
// DetectPython feed it, alongside a sanctioned change to the env patterns
// themselves.
package lint

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
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
// skipped silently. DetectPython owns .py (see pyExtensions).
var jsExtensions = []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

// pattern pairs one compiled regexp with the Class and Symbol a detector
// reports when it matches a line. DetectJS and DetectPython each build their
// own package level table of these, jsPatterns and pyPatterns; only the
// compiled patterns and the extension gate differ per language, so both
// share the same scanning, dedup, and sort machinery below (scanSource,
// runDetector), rather than each carrying a copy pasted twin of it.
type pattern struct {
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
//
// The env entries are the one place a pattern carries a real regexp
// capturing group (task 4.3): process.env.FOO and process.env["FOO"] both
// capture FOO, and matchSymbol turns a non empty capture into the language
// neutral Symbol shape "env:FOO" rather than the pattern's own static
// symbol field, so Gaps can key off variable name without caring which
// language produced the Detection. The final env entry is the pre task 4.3
// bare pattern kept as a fallback: an access this heuristic cannot resolve
// to a literal name, such as passing process.env itself around or
// iterating its keys, still reports a Detection, just with Symbol left as
// the bare "process.env" rather than a name.
var jsPatterns = []pattern{
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
	{"env", "process.env", regexp.MustCompile(`process\.env\.([A-Za-z_$][A-Za-z0-9_$]*)`)},
	{"env", "process.env", regexp.MustCompile(`process\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]`)},
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
// DetectPython's responsibility.
//
// The result is sorted by path, then by line as a number, then by Class,
// then by Symbol, so identical input bytes produce byte identical output on
// every call. The sort deliberately compares the parsed line number rather
// than the flat "path:line" Location string: comparing Location as one
// string would sort "path:10" before "path:7", since "1" is
// lexicographically less than "7", putting line 10 ahead of line 7. At most
// one Detection is emitted per line per class, even when more than one
// pattern of that class matches the same line; distinct classes matching
// the same line each still produce their own Detection. This scan, dedup,
// and sort pipeline lives in the shared runDetector, so DetectJS itself is
// nothing more than its extension set and pattern table.
func DetectJS(files []Source) []Detection {
	return runDetector(files, jsExtensions, jsPatterns)
}

// pyExtensions are the file extensions DetectPython scans; every other
// Source is skipped silently.
var pyExtensions = []string{".py"}

// pyPatterns is the Python capability detection table (spec 9), companion
// to jsPatterns. DetectPython shares pattern, detection, scanSource, and
// runDetector with DetectJS; only this table and pyExtensions are specific
// to Python.
//
// The eight import bearing modules (requests, httpx, urllib, socket,
// aiohttp, pathlib, shutil, subprocess), each matched in both "import x" and
// "from x" form for sixteen patterns total, are line anchored, unlike
// jsPatterns' require and from entries, which match anywhere in the line:
// each requires the module name to follow
// "import" or "from" at the true start of the line, after only optional
// leading whitespace (so a real import nested inside a function or try
// block, which carries indentation, still matches) and an optional "#". A
// natural language comment that merely mentions a module name mid sentence,
// such as "# we might want to import requests eventually", never fires,
// since "import" or "from" is not the token immediately following the
// optional "#". That same anchor deliberately still fires on a commented
// out import sitting alone at line start, such as "# import requests",
// since DetectJS already established the posture that comments are not
// parsed out (TestKnownFalsePositiveCommentedRequire), and DetectPython
// keeps that same posture for consistency rather than inventing a different
// one (TestKnownFalsePositiveCommentedImport).
//
// Each import pattern also carries a trailing \b so "import requests" does
// not fire on a different module that merely shares the prefix, such as
// requests_mock or urllib3; a following dot, as in "import
// requests.exceptions", still matches, since a dot is not a word character
// and the capability is the same one.
//
// open( carries a \b word boundary for the same reason DetectJS anchors
// fetch(: so a real identifier that merely contains "open(" as a substring,
// such as reopen(, does not fire. os.system(, os.popen(, os.environ, and
// os.getenv stay unanchored beyond their own structural dot, the same
// accepted tradeoff DetectJS documents for Bun.spawn, process.env, and
// fs/promises. os.exec is deliberately a bare prefix match with no trailing
// boundary or open paren, so it matches the whole os.exec* family,
// os.execv, os.execve, os.execl, os.execlp, os.execlpe, os.execvp, and
// os.execvpe, not just one spelling.
//
// Known false negatives, the same honesty posture DetectJS documents:
// importlib.import_module(variable) is never followed, since the module
// name is a variable, not literal text
// (TestKnownFalseNegativeDynamicImportModule), and a capability hidden
// behind eval is never scanned, since DetectPython matches literal text
// only and never evaluates anything (TestKnownFalseNegativeEvalPython).
var pyPatterns = []pattern{
	// network
	{"network", "requests", regexp.MustCompile(`^\s*#?\s*import\s+requests\b`)},
	{"network", "requests", regexp.MustCompile(`^\s*#?\s*from\s+requests\b`)},
	{"network", "httpx", regexp.MustCompile(`^\s*#?\s*import\s+httpx\b`)},
	{"network", "httpx", regexp.MustCompile(`^\s*#?\s*from\s+httpx\b`)},
	{"network", "urllib", regexp.MustCompile(`^\s*#?\s*import\s+urllib\b`)},
	{"network", "urllib", regexp.MustCompile(`^\s*#?\s*from\s+urllib\b`)},
	{"network", "socket", regexp.MustCompile(`^\s*#?\s*import\s+socket\b`)},
	{"network", "socket", regexp.MustCompile(`^\s*#?\s*from\s+socket\b`)},
	{"network", "aiohttp", regexp.MustCompile(`^\s*#?\s*import\s+aiohttp\b`)},
	{"network", "aiohttp", regexp.MustCompile(`^\s*#?\s*from\s+aiohttp\b`)},
	// filesystem
	{"filesystem", "open", regexp.MustCompile(`\bopen\(`)},
	{"filesystem", "pathlib", regexp.MustCompile(`^\s*#?\s*import\s+pathlib\b`)},
	{"filesystem", "pathlib", regexp.MustCompile(`^\s*#?\s*from\s+pathlib\b`)},
	{"filesystem", "shutil", regexp.MustCompile(`^\s*#?\s*import\s+shutil\b`)},
	{"filesystem", "shutil", regexp.MustCompile(`^\s*#?\s*from\s+shutil\b`)},
	// exec
	{"exec", "subprocess", regexp.MustCompile(`^\s*#?\s*import\s+subprocess\b`)},
	{"exec", "subprocess", regexp.MustCompile(`^\s*#?\s*from\s+subprocess\b`)},
	{"exec", "os.system", regexp.MustCompile(`os\.system\(`)},
	{"exec", "os.exec", regexp.MustCompile(`os\.exec`)},
	{"exec", "os.popen", regexp.MustCompile(`os\.popen\(`)},
	// env: mirrors jsPatterns' name capture (task 4.3). os.environ["FOO"] and
	// os.environ.get("FOO") both capture "FOO" into the same "env:FOO" Symbol
	// shape process.env.FOO reports, keeping Gaps language neutral; os.getenv
	// captures its literal first argument the same way. Each named form is
	// followed by its own unnamed fallback, so a dynamic or otherwise
	// unresolvable access, such as os.getenv(some_variable), still reports a
	// Detection, with the bare "os.environ" or "os.getenv" Symbol rather than
	// going undetected.
	{"env", "os.environ", regexp.MustCompile(`os\.environ\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]`)},
	{"env", "os.environ", regexp.MustCompile(`os\.environ\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']`)},
	{"env", "os.getenv", regexp.MustCompile(`os\.getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']`)},
	{"env", "os.environ", regexp.MustCompile(`os\.environ`)},
	{"env", "os.getenv", regexp.MustCompile(`os\.getenv`)},
}

// DetectPython scans Python sources for capability heuristics (spec 3
// capability lint, spec 9 lint testing rules), mirroring DetectJS exactly:
// deliberately heuristic and advisory, never sound static analysis (spec
// 1.3); it never executes, evaluates, or otherwise interprets the scanned
// source, and only matches literal, line anchored text against pyPatterns.
// See the pyPatterns doc comment for the anchor's exact shape, the
// commented import posture DetectPython shares with DetectJS, and the
// honesty tests that pin both known false positives and known false
// negatives.
//
// Only Sources whose Path ends in .py, matched case insensitively, are
// scanned; every other Source is skipped silently.
//
// The result is sorted by path, then by line as a number, then by Class,
// then by Symbol, the same numeric, not lexicographic, sort DetectJS uses,
// so identical input bytes produce byte identical output on every call. At
// most one Detection is emitted per line per class, even when more than one
// pattern of that class matches the same line; distinct classes matching
// the same line each still produce their own Detection.
func DetectPython(files []Source) []Detection {
	return runDetector(files, pyExtensions, pyPatterns)
}

// hasExtension reports whether path ends in one of extensions, ignoring
// case, so a Windows style .TS or .PY path is scanned the same as .ts or
// .py. Both DetectJS and DetectPython call this with their own extension
// set.
func hasExtension(path string, extensions []string) bool {
	lower := strings.ToLower(path)
	for _, ext := range extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// detection is one pattern match found while scanning a Source, kept with
// its path and line number separate until after sorting. Formatting them
// into a single Location string before sorting would make the comparison a
// flat string compare, which sorts "path:10" before "path:7"; keeping line
// as an int lets runDetector compare it numerically instead. Shared by
// DetectJS and DetectPython.
type detection struct {
	class  string
	symbol string
	path   string
	line   int
}

// envSymbolPrefix is the language neutral Symbol prefix a name aware env
// match carries (task 4.3): matchSymbol renders a captured variable name
// FOO as "env:FOO", and Gaps strips this exact prefix back off to recover
// the name, so the two must never drift apart.
const envSymbolPrefix = "env:"

// matchSymbol reports whether line matches p and, if so, the Symbol a
// Detection for that match should carry. Most patterns carry no regexp
// capturing group, so the static p.symbol is reported unchanged; the env
// patterns are the one case that do (see the jsPatterns and pyPatterns doc
// comments), and when the capturing group matched non empty text, the
// Symbol reported is envSymbolPrefix plus that text instead, the shared
// name aware shape both DetectJS's and DetectPython's env patterns produce
// so Gaps can key off a variable name without caring which language
// produced the Detection.
func matchSymbol(p pattern, line string) (symbol string, ok bool) {
	m := p.pattern.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	if len(m) > 1 && m[1] != "" {
		return envSymbolPrefix + m[1], true
	}
	return p.symbol, true
}

// scanSource applies patterns to f line by line, collapsing repeat matches
// of the same class on one line into a single detection. Shared by DetectJS
// (with jsPatterns) and DetectPython (with pyPatterns).
func scanSource(f Source, patterns []pattern) []detection {
	var out []detection
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
		matchedClasses := make(map[string]bool, len(patterns))
		for _, p := range patterns {
			if matchedClasses[p.class] {
				continue
			}
			if symbol, matched := matchSymbol(p, line); matched {
				matchedClasses[p.class] = true
				out = append(out, detection{
					class:  p.class,
					symbol: symbol,
					path:   f.Path,
					line:   lineNum,
				})
			}
		}
	}
	return out
}

// runDetector is the scan, dedup, sort, and format pipeline both DetectJS
// and DetectPython call: filter files to those matching extensions, scan
// each with patterns, sort the results deterministically, then format them
// into the public Detection shape. Extracting this once, rather than
// copying DetectJS's original body for DetectPython, is the sanctioned
// table driven refactor: only the extension set and pattern table differ
// per language.
func runDetector(files []Source, extensions []string, patterns []pattern) []Detection {
	var dets []detection
	for _, f := range files {
		if !hasExtension(f.Path, extensions) {
			continue
		}
		dets = append(dets, scanSource(f, patterns)...)
	}
	sort.Slice(dets, func(i, j int) bool {
		if dets[i].path != dets[j].path || dets[i].line != dets[j].line {
			return lessLocation(dets[i].path, dets[i].line, dets[j].path, dets[j].line)
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

// lessLocation reports whether (aPath, aLine) sorts before (bPath, bLine):
// path first, then line compared as a parsed integer, never as part of a
// flat "path:line" string comparison, which would sort "path:10" before
// "path:7" since "1" is lexicographically less than "7"
// (TestDetectJSSortsByNumericLineNotLexicographic pins this for
// detections). runDetector calls this directly on the path and line fields
// it already carries separately while sorting a []detection; Gaps calls it
// after splitLocation parses a Finding's already formatted Location string
// back apart, so the two share this one comparison rather than each
// restating it (task 4.3's "share the sort helper" requirement).
func lessLocation(aPath string, aLine int, bPath string, bLine int) bool {
	if aPath != bPath {
		return aPath < bPath
	}
	return aLine < bLine
}

// splitLocation parses a "path:line" Location, as Detection.Location and
// Finding.Location both format it, back into its path and numeric line.
// Gaps uses this to feed lessLocation the same numeric aware comparison
// runDetector uses, even though a Finding only ever carries the already
// formatted string, never the separate fields runDetector keeps. The line
// suffix is expected to always parse as an integer, since every producer of
// a Location string in this package formats it with "%d"; a location that
// somehow fails to parse sorts as line 0 rather than panicking.
func splitLocation(loc string) (path string, line int) {
	idx := strings.LastIndex(loc, ":")
	if idx < 0 {
		return loc, 0
	}
	line, _ = strconv.Atoi(loc[idx+1:])
	return loc[:idx], line
}

// classFindings maps a Detection Class other than env to the Finding Code
// and severity Gaps reports when that class fires undeclared (spec 1.1
// item 3). Network and exec are high severity, since an undeclared egress
// destination or an undeclared executed binary are the two most
// consequential surprises a manifest can hide from a reviewer; filesystem
// is medium. Env is handled separately in Gaps itself, since its severity
// and suppression rule depend on whether the Detection names a specific
// variable (see the Gaps doc comment).
var classFindings = map[string]struct {
	code     string
	severity string
}{
	"network":    {codes.UndeclaredNetworkEgress, "high"},
	"filesystem": {codes.UndeclaredFilesystem, "medium"},
	"exec":       {codes.UndeclaredExec, "high"},
}

// envDeclared reports whether name is covered by declaredEnv: either some
// entry equals name exactly, or some entry ends in "*" and its prefix (the
// entry with the trailing "*" removed) is a prefix of name, so a declared
// "AWS_*" covers "AWS_KEY". This same rule also covers the bare wildcard
// escape hatch without a separate special case: a declared bare "*" has an
// empty prefix, and every name has the empty string as a prefix, so "*"
// covers every name.
func envDeclared(declaredEnv []string, name string) bool {
	for _, d := range declaredEnv {
		if d == name {
			return true
		}
		if prefix, ok := strings.CutSuffix(d, "*"); ok && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// Gaps computes the declared versus detected gap this package's name
// promises (spec 1.1 item 3): given a manifest's declared CapabilitySet and
// the Detections DetectJS or DetectPython found across a source tree, it
// reports every Detection whose capability class the manifest leaves
// uncovered as an UNDECLARED_* Finding. Gaps is pure: it does no I/O and
// depends on nothing but its two arguments.
//
// Severities are fixed per class (see classFindings and the env case
// below): network and exec are high, filesystem is medium, env is medium
// when Gaps can name the specific variable and low when it cannot.
//
// Suppression differs by class. For network, filesystem, and exec, ANY non
// empty declared list for that class suppresses every Detection of that
// class, matched or not: a Detection's Symbol names the matched construct,
// such as fetch or child_process, never the actual destination host, path,
// or binary the call resolves to at runtime, so Gaps has no static way to
// compare one detected call against one specific declared entry. Matching
// specific hosts or paths against detected symbols is beyond what these
// static heuristics can honestly claim (spec 1.3): rather than pretend to
// check membership and get it wrong, v0.1 treats any declaration for the
// class as proof the class was considered at all, and reports the class as
// either fully covered or fully undeclared, never partially. A declared
// bare "*" (egress host "*", fs path "*" or "**", exec binary "*") is one
// way to declare the class this way, not a distinct rule; an empty list is
// the only declaration that leaves the class undeclared.
//
// Env is the one class Gaps can be precise about, because the detectors
// capture the variable name into Symbol when the source names it literally
// (see the jsPatterns and pyPatterns doc comments): a named Detection's
// Symbol has the shape "env:FOO". A named Detection fires UNDECLARED_ENV at
// medium severity, with Detail naming the variable, unless FOO is declared
// exactly or a declared entry ending in "*" has FOO as a prefix match (see
// envDeclared); that same trailing star rule is also why a bare declared
// "*" suppresses every name, without a separate case for it. A bare env
// Detection, one whose Symbol carries no name because the source read the
// environment through some access DetectJS or DetectPython could not
// resolve to a literal variable, fires UNDECLARED_ENV at low severity with
// a generic Detail instead, and is suppressed by any non empty declared env
// list at all, named or wildcard, on the theory that an author who declared
// at least one env var has considered the class at all.
//
// A declared capability that no Detection ever matches is never a Finding:
// over declaration is policy's business, not lint's (spec 1.3).
//
// The result is deduplicated by (Code, Location) and sorted by Code, then
// by Location with the same numeric line aware comparison DetectJS and
// DetectPython use (lessLocation, shared via splitLocation), so identical
// input produces byte identical output on every call. A nil or empty
// detections slice, or a declared set that covers every Detection, yields a
// non nil empty slice rather than nil, the same convention
// CapabilityManifest.Validate uses so a JSON encoding renders [] rather
// than null.
func Gaps(declared manifest.CapabilitySet, detections []Detection) []Finding {
	findings := []Finding{}
	seen := make(map[[2]string]bool)
	add := func(code, severity, detail, location string) {
		key := [2]string{code, location}
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, Finding{
			Code:     code,
			Severity: severity,
			Detail:   detail,
			Location: location,
		})
	}

	networkDeclared := len(declared.NetworkEgress) > 0
	filesystemDeclared := len(declared.Filesystem) > 0
	execDeclared := len(declared.Exec) > 0

	for _, d := range detections {
		switch d.Class {
		case "network":
			if !networkDeclared {
				cf := classFindings[d.Class]
				add(cf.code, cf.severity,
					fmt.Sprintf("network egress via %s is not declared in capabilities.networkEgress", d.Symbol),
					d.Location)
			}
		case "filesystem":
			if !filesystemDeclared {
				cf := classFindings[d.Class]
				add(cf.code, cf.severity,
					fmt.Sprintf("filesystem access via %s is not declared in capabilities.filesystem", d.Symbol),
					d.Location)
			}
		case "exec":
			if !execDeclared {
				cf := classFindings[d.Class]
				add(cf.code, cf.severity,
					fmt.Sprintf("exec via %s is not declared in capabilities.exec", d.Symbol),
					d.Location)
			}
		case "env":
			if name, named := strings.CutPrefix(d.Symbol, envSymbolPrefix); named {
				if !envDeclared(declared.Env, name) {
					add(codes.UndeclaredEnv, "medium",
						fmt.Sprintf("env var %s is not declared in capabilities.env", name),
						d.Location)
				}
			} else if len(declared.Env) == 0 {
				add(codes.UndeclaredEnv, "low",
					fmt.Sprintf("undeclared environment access via %s", d.Symbol),
					d.Location)
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		iPath, iLine := splitLocation(findings[i].Location)
		jPath, jLine := splitLocation(findings[j].Location)
		return lessLocation(iPath, iLine, jPath, jLine)
	})
	return findings
}
