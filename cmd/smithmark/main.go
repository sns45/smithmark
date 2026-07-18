// Command smithmark is the maker facing CLI: it generates, signs, and
// publishes capability attestations, and scaffolds the smithmark.yaml
// declaration a maker authors (spec 5). This file wires the command tree and
// the single exit code mapping; the per command pipelines live in attest.go
// and manifest.go.
//
// Dependency injection is the design center of this package. Every side
// effecting collaborator, the forgeseal SBOM generator, the Sigstore signer,
// the OCI target factory, and the clock, reaches a command only through a
// *deps value. Production wires the real adapters in main; tests wire fakes,
// so the whole CLI is exercised in process with no exec and no network.
//
// This package is never built for GOOS=wasip1 (the CI wasip1 check is scoped
// to ./pkg/...), so it imports the native, sigstore backed compose layer
// freely, unlike pkg/core which stays pure and platform independent.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/verify"
)

// version is the smithmark version stamped into every manifest's generator
// block and printed by the version command. It defaults to "dev" for a plain
// go build and is overridden at release time through a goreleaser ldflags
// injection, exactly as the forgeseal build wires its own version var.
var version = "dev"

// generatorName is the fixed generator.name every manifest smithmark produces
// carries (spec 3). It pairs with version to form the manifest's
// GeneratorInfo.
const generatorName = "smithmark"

// deps carries every injected collaborator a command needs. Command
// constructors read it rather than reaching for globals, so a test swaps in
// fakes by building its own deps value. Stdout and Stderr are injected too,
// so a test captures a command's output without touching the process's real
// streams.
type deps struct {
	// SBOM composes the dependency SBOM for an artifact (Task 2.4). In
	// production it shells out to forgeseal; tests inject a fake.
	SBOM compose.SBOMGenerator
	// Signer wraps a canonical statement in a signed DSSE bundle (Task 2.5).
	Signer compose.Signer
	// NewTarget resolves a repository string into an oras target to push an
	// attestation to (Task 2.7). Production returns a remote registry client;
	// tests return an in memory store, so publishing is exercised with no
	// network.
	NewTarget func(ctx context.Context, repo string) (oras.Target, error)
	// Verifier checks a bundle's DSSE signature against trust material (Task
	// 3.3). A compose.Verifier satisfies verify.SignatureVerifier structurally,
	// so verify.Run consumes this without pkg/core importing pkg/compose.
	// Production wires the native sigstore backed verifier; tests inject the
	// same real verifier over committed key based fixtures, since the fixtures
	// carry real signatures.
	Verifier verify.SignatureVerifier
	// Transport is the http.RoundTripper npm registry discovery is sent through
	// (Task 3.2). A nil value means net/http's own http.DefaultTransport; tests
	// inject a fixture serving round tripper so no test touches a real socket.
	Transport http.RoundTripper
	// Registry is the npm registry base URL for discovery. Empty means the real
	// registry.npmjs.org default.
	Registry string
	// ReadTarget resolves a repository string into a read only oras target for
	// attestation discovery (Task 3.2). Production returns a remote registry
	// client; tests return an in memory store, so discovery is exercised with no
	// network. It is distinct from NewTarget, whose push oriented oras.Target is
	// a different, write capable interface.
	ReadTarget func(ctx context.Context, repo string) (oras.ReadOnlyGraphTarget, error)
	// Now is the injected clock. The pure core never reads the wall clock
	// (spec 2.1); attest stamps generatedAt from here, verify stamps the report
	// verifiedAt, and a test pins it for a deterministic golden.
	Now func() time.Time
	// Stdout and Stderr are where commands write. Injecting them keeps every
	// test's output capture free of the real process streams.
	Stdout io.Writer
	Stderr io.Writer
}

// productionDeps builds the deps main runs with: the real forgeseal adapter,
// the native Sigstore signer, a remote OCI repository factory, and the real
// clock, writing to the process's own streams.
func productionDeps() *deps {
	return &deps{
		SBOM:   compose.NewForgesealCLI(),
		Signer: compose.NewSigner(),
		NewTarget: func(_ context.Context, repo string) (oras.Target, error) {
			return remote.NewRepository(repo)
		},
		Verifier:  compose.NewVerifier(),
		Transport: nil, // net/http's http.DefaultTransport
		Registry:  "",  // registry.npmjs.org
		ReadTarget: func(_ context.Context, repo string) (oras.ReadOnlyGraphTarget, error) {
			if repo == "" {
				// Live OCI attestation discovery needs a per artifact repository, but
				// v0.1 passes the attestation base straight through and does not yet
				// scope the client to the repository AttestationRef computes; when the
				// base resolves to empty, remote.NewRepository would fail with an
				// uncoded error surfaced as INTERNAL_ERROR. Fail closed with a coded
				// DISCOVERY_FAILED naming the limitation instead (tracked in
				// sns45/smithmark#4; the live wiring lands with M6).
				return nil, codes.E(codes.DiscoveryFailed,
					"no OCI repository resolved for live attestation discovery; v0.1 does not yet scope the registry client to the per artifact repository AttestationRef computes (see sns45/smithmark#4). Pass --bundle to verify an explicit bundle, or wait for the live registry wiring in a later release")
			}
			return remote.NewRepository(repo)
		},
		Now:    time.Now,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

func main() {
	os.Exit(runMain(productionDeps(), os.Args[1:]))
}

// runMain builds the command tree against d, runs it with args, and maps the
// outcome to a process exit code. It is the one place the exit code contract
// lives (decision D4). Most commands are binary: success is 0, and any failure
// is the operational 3 with a single machine readable JSON line on stderr.
// verify additionally distinguishes a completed but negative verification from
// an operational failure: it writes its report to stdout itself and then returns
// a *verifyExit carrying the classified code (0, 1, or 2), which this function
// unwraps ahead of the operational path so a failed verification never emits the
// stderr error line. It returns the code rather than calling os.Exit so tests
// assert the code directly; only main exits the process.
func runMain(d *deps, args []string) int {
	root := newRootCmd(d)
	root.SetArgs(args)
	root.SetOut(d.Stdout)
	root.SetErr(d.Stderr)
	if err := root.Execute(); err != nil {
		var ve *verifyExit
		if errors.As(err, &ve) {
			// verify already wrote its report; the sentinel only conveys the
			// classified exit code (D4), never an operational error line.
			return ve.code
		}
		return emitError(d.Stderr, err)
	}
	return 0
}

// errLine is the machine readable failure shape written to stderr on any
// command failure (decision D4): a stable registry code plus a human readable
// detail, one JSON object per line.
type errLine struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// emitError writes exactly one JSON error line to w and returns the operational
// exit code 3. The code is pulled off a *codes.Error anywhere in the wrapped
// chain with errors.As; a failure that carries no registry code reached the
// boundary uncoded and is surfaced under INTERNAL_ERROR, so the contract's
// code field is never empty.
func emitError(w io.Writer, err error) int {
	code := codes.InternalError
	var e *codes.Error
	if errors.As(err, &e) {
		code = e.Code
	}
	b, mErr := json.Marshal(errLine{Code: code, Detail: err.Error()})
	if mErr != nil {
		// A detail string that will not marshal is not a reason to lose the
		// code: fall back to a hand built line carrying the code alone.
		b = []byte(fmt.Sprintf(`{"code":%q,"detail":"detail could not be encoded"}`, code))
	}
	fmt.Fprintln(w, string(b))
	return 3
}

// newRootCmd assembles the smithmark command tree. Usage and error printing
// are silenced because this package owns the failure contract itself: cobra
// must not print its own usage banner or error text, or a command failure
// would emit more than the single JSON line decision D4 mandates.
func newRootCmd(d *deps) *cobra.Command {
	root := &cobra.Command{
		Use:           "smithmark",
		Short:         "Generate, sign, and publish agent capability attestations",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.AddCommand(newVersionCmd(d))
	root.AddCommand(newAttestCmd(d))
	root.AddCommand(newManifestCmd(d))
	root.AddCommand(newVerifyCmd(d))
	root.AddCommand(newLintCmd(d))
	root.AddCommand(newRegistryCmd(d))
	return root
}

// newVersionCmd prints the smithmark version. The root also carries a
// --version flag through cobra's Version field; this explicit subcommand gives
// the same value the plain, discoverable way.
func newVersionCmd(d *deps) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the smithmark version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(d.Stdout, version)
			return err
		},
	}
}
