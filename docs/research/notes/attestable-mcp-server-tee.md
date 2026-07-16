# co-browser/attestable-mcp-server (TEE remote attestation)

## What it is
An early stage open source project that lets an MCP client remotely verify that an MCP server is running intended, untampered code, using a hardware trusted execution environment (Intel SGX) and RA-TLS (remote attestation embedded in the TLS handshake via an X.509 certificate carrying an SGX quote).

## What it does
- Generates a certificate representing the currently running code of the server and presents it during the TLS handshake, so a client can attest that the code matches a specific build produced on GitHub Actions.
- Proves code identity: the running binary corresponds to a known build.

## What it does NOT do
- Does not declare or sign capabilities (egress, filesystem, exec, env, secrets) as a policy consumable artifact. It attests what code is running, not what that code is permitted to do.
- Does not compose npm provenance, Sigstore, SLSA, or CycloneDX; it relies on RA-TLS and SGX quotes.
- No skills coverage.
- Early stage: the README TODO and Future Plans sections indicate incomplete work (for example, a planned RA-TLS client demo).

## Strongest refutation quote
> "MCP Clients can remotely attest the code running on any MCP Server" (project README, `co-browser/attestable-mcp-server`, accessed 2026-07-16)

Assessed: this is code identity attestation on a different axis from the claim. It answers "is the server running the code I expect," not "what is this artifact declared to be able to do, signed and consumable by policy."

## Bearing on the §1.2 claim
Adjacent, not competing. Runtime code identity attestation via a TEE is orthogonal to a signed capability declaration; the two could even be complementary. It does not overlap the capability manifest idea and does not falsify the claim. Included for completeness because it surfaces under "MCP server attestation" searches and could be mistaken for prior art; it is not.

## Sources
- https://github.com/co-browser/attestable-mcp-server (accessed 2026-07-16)
