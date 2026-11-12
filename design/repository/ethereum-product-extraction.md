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

The entire C4 transaction retains the amended RFC #352 maximum +1200 net source lines
(originally +800),
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

## Approved canonical-provider landing

The owner explicitly approved the [bounded follow-up amendment](https://github.com/teddyjfpender/stwo-zig/issues/352#issuecomment-6832806430)
on 2026-11-12. It permits the exact four canonical bindings: frontend prover
`blake3_profile_artifact.ForOwner`, RV64 `service_calls.curves.arithmetic`, and
CPU `rv64_native_schema` / `rv64_native_rungs`. Existing algorithms and schemas
keep their sole definitions. The exact module member lists and implementation
hashes are recorded in that decision. The C4 source allowance is now **+1200**,
with target zero, no new flags/scripts and no removal credit for moves.

This landing publishes those additive bindings first. Four real product-owned
consumer cases require them and first fail on the four missing fields. They
exercise native class/table authority and legacy nominal identity, arithmetic
against integer modular arithmetic, canonical direct/umbrella machine and trace
types, and artifact framing/rejection precedence. They pass in Debug and
ReleaseFast alongside the two existing product identity cases (six named cases
plus the collection hook). Both direct RV32/RV64 dependencies bind the same
module instances already used by the neutral frontend; the actual build checks
those pointers. These source package changes keep CPU's unpublished 1.0.0 major
candidate; they do not publish a release or revise proof bytes.

The approved RV64 service-export removal, product profile-selector move and
strict placement activation remain in the separately preserved, **unqualified**
full migration draft until its complete consumer closure passes. That draft
physically relocates the product implementation and policy sources and has zero
placement findings with P3 active, but still has cross-owner imports. It is not
the pushed qualification state. The canonical-provider landing's existing
placement diagnostic remains 212 with P3 inactive; full C4 completion is not
claimed by this additive slice.

This additive landing is source +74/-2/net **+72**, cumulative C4 **693/1200**.
Configuration is +15/-5; documentation is reported separately. Flags and
maintained scripts added/removed remain zero. All 80 workspace/graph Python
checks pass at this landing (37 packages, 39 public modules, 175 edges), with
exactly the same 83 inherited source findings. The 25-case native golden/chain
suite passes in both modes, including its collection hook. These bounded
results do not establish complete frontend/proof acceptance for the preserved
migration draft.

## Native helper prerequisite landing

The next C4 slice removes request/packet policy from native qualifications
without publishing another neutral API. File SHA-256 pins, immutable executable
mapping collection, bounded byte I/O and tape/ROM profile compatibility each
have one private canonical owner. The original request/batch/packet names alias
those same definitions. CSP/Sail, distributed receipt and coverage consumers
call the shared owners directly. The prepared-job digest domain/offset and all
request/image admission remain with their original product implementation.

All transferred function/record bodies are exact. The two new owning tests
cover pin rejection precedence and bounded I/O truncation/section/buffer edges;
both pass Debug and ReleaseFast (285,933,568-byte sampled peak). A bounded
actual-module check also runs the existing Zbb authority/admission truth table
and exercises real native program mapping, canonical request/type identity,
empty-program refusal and mutable-executable refusal in both modes (three
cases per mode, 448,331,776-byte peak). All 80 workspace/graph tests pass.
The 83 inherited source findings remain; no ceiling or baseline is changed.
The focused checks do not qualify a complete frontend or frozen Native proof.

This slice is source +192/-130/net **+62**, cumulative C4 **755/1200**.
Documentation is separate; configuration, flags and maintained scripts add or
remove zero. Shared bodies are transferred, not counted as deleted code.
The complete product migration remains preserved and unqualified separately.

## Independent reference prerequisite landing

Pure arithmetic and FIPS SHA-256 reference bodies now have one private RV64
service owner. Candidate dispatch aliases those same functions; the AIR tests
call them directly. The independent reference is retained alongside the
optimized witness primitive, so the differential oracle is not weakened.
Curve reference tests use the already-approved canonical arithmetic binding.
All original names, vectors, assertions and production function signatures stay.

Actual candidate FIPS/big-integer cases pass in both modes (five cases including
two collection hooks, 404,373,504-byte peak); AIR arithmetic/curve and random SHA
reference cases also pass both modes (524,091,392 and 376,291,328-byte peaks).
Workspace passes at 37 packages/39 modules/175 edges; the same 83 inherited
source findings remain. Full frontend and frozen-proof acceptance remain open.
Source +53/-47/net **+6**, cumulative C4 **761/1200**; documentation is separate,
configuration/flags/maintained scripts unchanged. No move subtraction credit.
