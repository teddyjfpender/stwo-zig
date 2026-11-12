# Ethereum product extraction

Owner: `ethereum-statement`, @teddyjfpender. Delivery issue: [#336](https://github.com/teddyjfpender/stwo-zig/issues/336).
The contract and its recorded amendments are [RFC #352](https://github.com/teddyjfpender/stwo-zig/issues/352).
This note records the current extraction boundary; it does not replace that RFC.

## Destination and compatibility

The destination is `src/products/ethereum/statement`, with the six approved
`statement`, `runner`, `prover`, `frontend`, `cpu`, and `cuda` domains. The two
legacy build exports must reuse the actual frontend and CPU component Module
pointers. Neutral packages must never import the product. Existing profile IDs,
protocol bytes, canonical records, rejection ordering, resource ownership and
named test discovery remain acceptance requirements.

The old `backup/c4-product-ownership-partial-20261110` ref is preservation only.
It has no completed package/module DAG and is not an integration candidate.
Use its reviewed path mapping, not its obsolete imports or duplicate metadata.

## Private dependency cuts

The current prerequisite slice separates these existing shared authorities:

- `rv64/services/call_abi.zig` owns the original SecpCall, Sha256Call,
  Arith256ModCall, CurveCall and Event definitions. Their complete bodies are
  unchanged; the existing session exports alias that single definition. Compact
  tape, tape wire, RAM-word capture and boundary capture import these records
  without importing the product executor. The packet modules still require
  their separate ownership cut before strict placement can pass.
- `rv64_proof_artifact_support.zig` owns the original physical-cell accounting,
  exclusive-file write and durable summary replacement. Seventeen consumers use
  this shared owner directly; the Ethereum receipt keeps its existing callable
  aliases and owns its schema, chain checkpoint and proof/receipt transaction.
  Helper bodies and error/cleanup ordering are unchanged.
- The three previously approved RV64 primitive provider names forward to the
  existing Precompiles implementations. No algorithm is copied or moved back
  into the RV64 executor. Their first additive version was `0.2.0`; the approved
  checkpoint signature transaction now sets this package to `1.0.0`.

The owner approved the two shared public providers and four checkpoint input
signatures in the [recorded RFC amendment](https://github.com/teddyjfpender/stwo-zig/issues/352#issuecomment-6828863621).
They are now installed: RV64 `service_calls` aliases the original call owner,
and CPU `rv64_proof_artifact_support` aliases the original shared helper owner.
The CPU package is `0.3.0`; these source-package versions are not release tags or
proof-protocol revisions. Checkpoint no longer imports the Ethereum session;
its four accessors infer the concrete caller's session pointer at compile time.
The actual memory identity, counters, page checks, error/copy/cleanup ordering
and data records are unchanged.

The real CPU public-consumer test runs beside the private owner tests. The
existing `dev_test.py` compiles these std-only paths directly against the actual
CPU module, holding the canonical build lock. This avoids loading the complete
package build runner for four small tests. Engine validation now runs inside the
unchanged concrete `CpuProverEngine` construction, retaining the assertion for
all consumers of that engine without forcing unrelated artifact consumers to
instantiate it. The package's dedicated test target and default-test consumer
wiring remain; the full build-runner attempt exceeded the laptop's 1 GiB guard
and is not counted as qualification.

Local actual-session checkpoint replay/tamper and canonical identity cases pass
in Debug and ReleaseFast, as do all four public-consumer/private IO cases.
Full product and frozen proof acceptance remain separate. Additional contract
changes discovered in the remaining closure need their own exact ledger and
recorded decision; this amendment is not blanket removal permission.

## Component construction checkpoint

`src/products/ethereum/statement` now has the approved v2 product contract,
manifest, owner routes, graph projection and graph-derived CI lane. Its three
component roots are created once. The primary exposes exactly the six approved
domains; both legacy build keys reuse their actual component pointers. CPU
imports frontend; CUDA imports frontend and CPU. The build checks those pointer
bindings. The primary's direct contract tests pass in Debug and ReleaseFast,
including canonical lower Cpu/Memory/HostInterface and primary/legacy identities.
These direct tests use the actual declared lower source modules and component
bindings; they do not execute the package build runner. Manifest/dependency
resolution (`zig build --fetch=all`) passes. Actual complete configuration and
product execution qualification remain open.

The component facades currently forward the existing owners. They establish
composition identity, not completed implementation ownership: product source
movement, neutral API removals, consumer migration and full discovery/proof
acceptance remain unfinished. No lower package imports this new product.

The next private cuts retain one artifact-framing implementation, with profile
selection outside it, and move curve arithmetic away from candidate dispatch.
Shared curve, bulk and sponge packet modules now live in RV64 `services/`.
Canonical native schemas, rung data and both unchanged embedded vector files
live in CPU `services/native_schema/`. The CpuDeclaration record has one shared
owner; the wire facade aliases it. These are seven physical file relocations,
not a rename of request/image or admission policy into a generic directory.

Focused Debug/ReleaseFast executions pass: 26 packet/capture/reference tests,
25 native schema/chain golden and adversarial tests, the four-profile artifact
framing test, and the planner/default admission regression. The planner test
moves intact out of shared GKR scope into its product-policy test owner and is
explicitly collected by the CPU module. This removes the test-only lower policy
edge without replacing its real planner oracle with copied defaults. All 80
workspace/graph Python checks pass; the graph now contains 37 packages and 173
edges. Source conformance retains the exact same 83 inherited findings.

## Boundary checks and acceptance

The strict product-placement predicate and negative fixtures reject product
paths, including generated paths, and product identifiers on lower public
surfaces. Product-layer dependency validation rejects lower-to-product and
product-to-product edges. These layer rules are active. The placement predicate
is tested but is not yet part of the repository-wide acceptance call: enabling
it belongs to the complete relocation transaction, without an allowlist or
baseline. Its current diagnostic finds 212 placement violations: seven shared-owner relocations remove seven of the original 218, while the separately retained planner test adds one product-owned file awaiting migration. A clean
existing workspace audit is not strict P3 completion.

Local prerequisite checks execute the real capture/tape and tape-wire cases in
Debug and ReleaseFast, including malformed advice, allocation failure and all
service sidecars. Actual file publication tests cover existing-file refusal,
complete summary replacement and staging cleanup on failed publication.
The RV64 identity case pins the shared records and primitive module aliases;
the original primitive arithmetic/oracle cases remain independent.

These bounded checks do not qualify a complete product build or full proof.
Remaining delivery: complete the private service/packet and request/image cuts,
construct the product package and concrete component DAG, migrate every affected
consumer and discovery root, activate strict P3, and run final frontend/CPU
acceptance with semantic negatives and frozen Native proof identity. No GPU,
performance, release or whole-extraction completion claim follows from this
prerequisite slice.

## Budget

The entire C4 transaction retains RFC #352's maximum +800 net source lines,
including tests/build/compatibility wiring. Moves receive no subtraction credit.
New flags and scripts are zero; documentation and configuration are separate.
The private cuts protect shared ownership and failure semantics; rollback must
restore their original aliases, consumers and tests together.

Measured source so far: prerequisite +174 and approved shared-boundary segment
+88, cumulative **262/800**. The latter includes the real public-consumer test,
complete counter-family regression and bounded developer routing. It adds no
flag or script; documentation/configuration remain separate. Source conformance
still has exactly the same 83 inherited findings, with no additions/removals.

The component-construction/shared-owner segment adds 766 source lines and removes
407, net **+359**; cumulative C4 source is **621/800**. The seven moves receive no
removal credit. Configuration adds 87 lines, removes zero; the new package guide
adds 80 documentation lines, with this extraction ledger reported separately.
Flags added/removed: zero; maintained scripts added/removed: zero. The additional
source owns explicit component wiring, compatibility identity and retained
negative/reference coverage. It does not authorize extra neutral public APIs.
