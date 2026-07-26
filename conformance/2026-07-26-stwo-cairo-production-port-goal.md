# Stwo-Cairo Zig Production Port Goal

Status: active

Owner: Cairo frontend

Scope: Cairo CPU/SIMD and Metal products

Explicitly excluded: CUDA, RISC-V feature work, streaming-service optimization

## Goal

Port the complete official Stwo-Cairo prover into Zig and release it as two
independently buildable products:

```text
stwo-cairo-cpu
stwo-cairo-metal
```

Both products must accept a Cairo program or an official Stwo-Cairo
`ProverInput`, construct the complete Cairo statement and witness, produce a
canonical Stwo proof, and have that exact proof accepted by the pinned official
Rust `verify_cairo` implementation. Metal is a real backend, not a device label
around CPU proving, and must fail closed when required device work cannot run.

The port is complete only when it covers the current official Stwo-Cairo
surface, not merely raw `pc`/`ap`/`fp` traces, one opcode, the four SN PIEs, or a
proof-derived semantic pack.

## Frozen Upstream Authority

This goal starts from the latest official source inspected on 2026-07-26:

| Authority | Version or revision |
| --- | --- |
| Stwo-Cairo repository | `https://github.com/starkware-libs/stwo-cairo` |
| Stwo-Cairo commit | `82f21252a68ec006d73e299f5bf1ce6d4db0ee78` |
| Stwo-Cairo workspace version | `1.2.2` |
| Stwo repository | `https://github.com/starkware-libs/stwo` |
| Stwo commit | `7b211edde786775016ef3eecb837a6240d8fe792` |
| Stwo package version | `2.2.0` |
| Cairo VM | `3.2.0` |
| Scarb used by upstream | `2.15.0` |
| Rust edition | `2024` |

`src/frontends/cairo/air/official_claim_registry.zig` is generated directly
from these clean sources. Its 68 claim fields and 83 enable slots are a shape
contract, not evidence that their constraints or witnesses have been ported.

The previous `teddyjfpender/stwo-cairo` `dcd58345` artifacts remain historical
development evidence only. They must not be relabelled as official evidence.
They do not release either product.

An upstream upgrade is a deliberate conformance change. It must update this
document, the pin ledger, generated registries, Rust oracle lockfile, vectors,
and all proof interoperability evidence together.

## Product Boundary

The repository keeps frontend semantics independent from backend execution:

```text
src/frontends/cairo/
  adapter/          official input model and Cairo VM adaptation
  air/              claims, relations, components, constraint programs
  statement/        public data and transcript-bound statement
  witness/          backend-neutral witness and interaction plans
  proof/            Cairo proof model and canonical serialization

src/integrations/cairo_cpu/
  witness/          SIMD witness execution
  prover/           CPU composition of frontend and generic prover

src/integrations/cairo_metal/
  witness/          Metal witness execution
  prover/           Metal composition of frontend and generic prover
  resident/         process-owned device resources and proof session

src/products/cairo_cpu/
  main.zig          focused CLI shell

src/products/cairo_metal/
  main.zig          focused CLI shell
```

Frontend code may depend on core field, AIR, PCS, and backend contracts. It may
not import a concrete CPU or Metal backend. Integrations select a backend.
Products own argument parsing, filesystem transactions, diagnostics, and
process exit behavior. This is the same layering required for Native and RISC-V
frontends; Cairo must not add backend selection to generic prover code.

Files should remain below the soft 500-line target and the 850-line exceptional
ceiling in `CONTRIBUTING.md`. Existing oversized Cairo files are decomposition
debt, not a precedent. Split them along statement, witness, commitment,
interaction, quotient, decommitment, and lifecycle ownership while porting the
affected behavior.

## Required CLI

Each released product exposes the same frontend commands:

```text
stwo-cairo-{cpu,metal} prove
  --prover-input <input.json>
  --proof <proof.{json,bin,cairo}>
  [--params <params.json>]
  [--proof-format json|binary|cairo-serde]
  [--verify]

stwo-cairo-{cpu,metal} run-and-prove
  --program <program.json|executable>
  [--program-type json|executable]
  [--arguments <arguments.json>]
  --proof <proof.{json,bin,cairo}>
  [--params <params.json>]
  [--proof-format json|binary|cairo-serde]
  [--verify]

stwo-cairo-{cpu,metal} capabilities
stwo-cairo-{cpu,metal} identity
```

`prove` consumes the official JSON `ProverInput` schema. `run-and-prove`
executes with the official `all_cairo_stwo` layout and produces the same
adapted input semantics. A future native Zig Cairo VM may replace the execution
adapter without changing the proving boundary.

Output publication is transactional. Existing files are never silently
overwritten, incomplete output is removed, and a verification failure cannot
publish a proof. Machine-readable output goes to stdout; diagnostics go to
stderr. Product identity includes the implementation commit, dirty state,
frontend protocol identity, backend identity, official Stwo-Cairo and Stwo
pins, proof format, Metal AOT identity where applicable, and build mode.

Default proof parameters match official Stwo-Cairo's 96-bit configuration.
The supported channel set is:

- Blake2s;
- Blake2s over M31;
- Poseidon252.

Unsupported parameters, preprocessed variants, channels, or target features
fail before proving. Parameters are mixed into the transcript exactly once and
are included in the proof identity.

## Semantic Completion Requirements

### CP-01: Official input and execution

- Decode every field of official `stwo_cairo_adapter::ProverInput`.
- Preserve state transitions for all 20 opcode families.
- Preserve memory address-to-ID, small-value, and felt252-value tables.
- Preserve builtin segment bounds and the 11-bit public segment context.
- Preserve public memory addresses and `pc_count`.
- Support every builtin in `all_cairo_stwo`: output, Pedersen, range check,
  ECDSA, bitwise, EC op, Keccak, Poseidon, range-check96, add-mod, and mul-mod.
- Reject noncanonical field values, inconsistent counts, malformed segments,
  unsupported schema versions, and trailing data.

Evidence: field-by-field Rust/Zig adapter vectors, malformed-input tests, and
identical execution-resource reports for a coverage corpus.

### CP-02: Claims and public statement

- Port `CairoClaim`, `CairoInteractionClaim`, `PublicData`, flattened claims,
  component enable bits, component log sizes, and canonical mix order.
- Support all 68 claim fields and all 83 enable slots, including up to 16
  `memory_id_to_big` components.
- Bind public memory and public segment context into the proof statement.
- Match all fixed and dynamic log-size rules.
- Preserve canonical preprocessed-column ordering and IDs.

Evidence: exact serialized claims, mix-event transcripts, log-size vectors,
and mutation tests accepted or rejected identically by Rust.

### CP-03: Preprocessed trace

- Port canonical, canonical-small, and canonical-without-Pedersen variants.
- Port sequence, range-check, Poseidon, Pedersen, round-key, and other official
  preprocessed columns at exact domains and ordering.
- Authenticate immutable tables and share them across proof requests without
  changing transcript semantics.

Evidence: every column digest and commitment root matches Rust for each
variant; cache reuse and teardown tests preserve identical proof bytes.

### CP-04: Base witness

Port the base-trace generator for every official component family:

- Cairo opcodes and instruction verification;
- Blake and bitwise components;
- add-mod, mul-mod, range-check, Pedersen, Poseidon, and EC builtins;
- Pedersen and Poseidon helper components;
- memory address-to-ID, memory-ID-to-big, and memory-ID-to-small;
- all range-check and XOR lookup tables;
- all generated subroutines used by these components.

Witness programs derived from Rust source may be generated at build time, but
released products consume versioned, authenticated artifacts and do not invoke
Rust, Cargo, Git, or a source compiler while proving.

Evidence: cumulative per-component Rust oracle comparison, every base-column
digest, row count, padding row, and final base commitment root.

### CP-05: Relations and interaction trace

- Port every field of `CommonLookupElements` in canonical draw order.
- Port all LogUp numerators, denominators, batching, claimed sums, and lookup
  total validation.
- Bind the interaction proof-of-work at the exact transcript position.
- Reject zero denominators and nonzero global lookup sums.

Evidence: channel-event trace, drawn elements, per-component interaction
columns and sums, cumulative lookup accumulator, final interaction root, and
adversarial relation mutations.

### CP-06: AIR constraints and quotient

- Port the complete official component constraint programs.
- Preserve trace-location allocation, preprocessed-column allocation, mask
  offsets, extension degree, log-degree bounds, and component ordering.
- Accumulate constraints identically for CPU and Metal.
- Remove the raw three-column trace prover from any production claim; it is a
  diagnostic example, not the Cairo AIR.

Evidence: randomized row-level evaluator parity, full-domain cumulative
accumulator parity after every component, quotient commitment parity, and
mutation tests for each relation and boundary constraint.

### CP-07: Proof and transcript

- Match the official commitment order: preprocessed, base, interaction,
  composition, and FRI/decommitments.
- Match channel salt, PCS configuration, claim mixing, proof-of-work, sampled
  values, OODS points, quotient construction, FRI, and decommitment ordering.
- Support official JSON, compressed binary, and Cairo-serde proof formats.
- Verification must operate on the exact bytes published to the caller.

Evidence: deterministic proof bytes where the format promises determinism,
canonical decoded proof equality otherwise, transcript-event equality, and
independent Rust `verify_cairo` acceptance.

## Backend Requirements

### CP-08: CPU/SIMD

`stwo-cairo-cpu` uses the repository CPU/SIMD backend through backend
contracts. It enables parallel proving in production builds, reports worker and
SIMD capability identity, and has no Metal, Objective-C, or CUDA dependency.

Evidence:

```text
zig build stwo-cairo-cpu -Doptimize=ReleaseFast
zig build test-cairo-cpu-product -Doptimize=ReleaseFast
```

The product-closure gate must confirm the absence of GPU frameworks and
frontend/backend layering violations.

### CP-09: Metal

`stwo-cairo-metal` must execute all released proving stages through the Metal
backend wherever its capability contract says it does. No unreported scalar or
SIMD fallback is allowed. Production shaders are AOT compiled and
authenticated; runtime source compilation is a development-only mode.

The runtime is process-owned. A proof session owns per-proof buffers and
registrations, and teardown cannot synchronize unrelated work or scan global
state. Host/device transfers, dispatches, waits, copybacks, fallback counts,
and peak resident bytes are reported.

Evidence:

```text
zig build stwo-cairo-metal -Doptimize=ReleaseFast
zig build test-cairo-metal-product -Doptimize=ReleaseFast
```

Tests include CPU/Metal proof equality, forced Metal execution, missing-device
failure, buffer lifetime, repeated proof sessions, and allocation/error unwind.

Performance is optimized only after exact parity. It is not a substitute for
feature completion.

## Correctness Oracle

The official Rust Stwo-Cairo verifier is the final correctness oracle.

Acceptance requires an isolated Rust verifier built from the exact official
pins above with:

- no path dependencies;
- no Cargo patch or replace entries;
- a committed lockfile;
- a recorded executable and lockfile digest;
- a machine-readable identity command;
- support for all released channels and proof formats;
- rejection tests for proof, statement, parameter, and identity mutations.

Zig verification, CPU/Metal agreement, identical proof hashes, component
receipts, and historical fork acceptance are necessary diagnostics but cannot
override official Rust rejection.

## Release Matrix

Every row must be green before the corresponding product changes from disabled
to parity-gated or released.

| ID | Requirement | CPU | Metal | Required evidence |
| --- | --- | --- | --- | --- |
| RF-01 | Official source pins and generated registry | required | required | clean-source regeneration check |
| RF-02 | Official JSON input | required | shared | adapter differential corpus |
| RF-03 | Cairo VM run-and-adapt | required | shared | program execution corpus |
| RF-04 | All claims and public data | required | shared | canonical statement vectors |
| RF-05 | All preprocessed columns | required | required | column and root parity |
| RF-06 | All base witness components | required | required | per-component cumulative parity |
| RF-07 | All interactions and lookup sums | required | required | per-component cumulative parity |
| RF-08 | All AIR constraints and quotient | required | required | evaluator and quotient parity |
| RF-09 | Complete PCS, FRI, and proof | required | required | official Rust acceptance |
| RF-10 | JSON proof format | required | required | roundtrip plus Rust acceptance |
| RF-11 | Binary proof format | required | required | roundtrip plus Rust acceptance |
| RF-12 | Cairo-serde proof format | required | required | roundtrip plus Rust acceptance |
| RF-13 | CLI `prove` | required | required | subprocess success/failure matrix |
| RF-14 | CLI `run-and-prove` | required | required | compiled-program corpus |
| RF-15 | Product closure | required | required | focused build dependency audit |
| RF-16 | No backend fallback | n/a | required | forced-device telemetry |
| RF-17 | Failure and mutation suite | required | required | adversarial test matrix |
| RF-18 | Repository conformance | required | required | format, source, docs, pin gates |

## Coverage Corpus

The release corpus must exercise more than Fibonacci:

- control flow: calls, returns, absolute/relative jumps, taken/non-taken JNZ;
- arithmetic: small/full add and multiply, QM31, add-mod, and mul-mod;
- memory: public memory, small values, felt252 values, all big-memory shards;
- cryptography: Pedersen, Poseidon, Blake, bitwise/XOR, EC op, and ECDSA;
- range checks: builtin and every fixed lookup shape;
- mixed programs that activate many component families simultaneously;
- official upstream test programs;
- at least one realistic Starknet PIE accepted by the supported adapter.

For each case, record input identity, active components, trace cells, proof
parameters, proof size, CPU/Metal backend telemetry, and official Rust verdict.
Large performance cases are valuable only after the same semantic gates pass.

## Current Evidence and Gaps

As of the starting commit `cfd47be9`:

| Area | Evidence | Status |
| --- | --- | --- |
| Official source identity | clean-source generated registry and pin-ledger gate | complete for frozen pin |
| Official JSON input | strict bounded reader plus all-opcodes and all-builtins Rust semantic summaries | complete for the frozen `ProverInput` wire schema |
| Public statement | exact packed-word digests and Blake2s roots match Rust for both inputs; all-opcodes is anchored to the public data inside the official proof | complete for frozen fixtures |
| Claim geometry | active generator imports only the official 68-field/83-slot registry; all-opcodes enable bits, live-input known logs, resolved flat logs, and Blake2s claim mix match the official proof | complete for one frozen proof |
| Official base-trace oracle | isolated official Rust tool emits deterministic per-column and cumulative component checkpoints; all-opcodes pins 46 components/1,464 columns and all-builtins pins 48 components/3,332 columns | complete as the CP-04 comparison authority for two frozen fixtures |
| Official witness recordings | repository-owned source compiler reproduces an authenticated `STWZWIT/1` checkpoint containing all 64 generated official-source programs and 157,733 SSA instructions; its authenticated 1,780-edge source topology drives generated, fixed, and memory writers without fixture-specific routing | complete for the two frozen CP-04 fixtures |
| Official base-trace parity | all-opcodes matches 24 generated, 19 fixed, and 3 memory components (46/46); all-builtins matches 26 generated, 19 fixed, and 3 memory components (48/48), including all 624 `partial_ec_mul_generic` columns | complete for both frozen fixtures; broader execution corpus remains |
| Official interaction-trace parity | all-opcodes matches 46 components and 1,032 columns; all-builtins matches 48 components and 2,220 columns, including every claimed sum and the cumulative accumulator after each component | complete for both frozen fixtures under the explicitly diagnostic challenge; proof-transcript challenges remain |
| Official preprocessed trace | backend-neutral registry constructs canonical (161 columns), canonical-without-Pedersen (105 columns), and canonical-small (156 columns) in exact stable identity order; canonical AIR indices project to canonical-small identities and reject absent columns | commitment-root parity and process-owned cache reuse remain |
| Official base commitment input | all-opcodes executes the authenticated witness graph and materializes all 1,464 columns and 28,690,992 M31 cells in Rust commitment order; every value vector is re-digested against the cumulative Rust checkpoint before admission | commitment root and live-input geometry derivation remain |
| Official AIR compiler | authenticated exact-source overlay lowers the 46 active all-opcodes component evaluators into one backend-neutral bundle containing 678 constraints, 9,689 base instructions, and 14,797 extension instructions | complete for the frozen all-opcodes proof; all-family coverage and quotient execution remain |
| Native Zig AIR | executes authenticated captured programs through the generic CPU/SIMD domain accumulator; a focused functional gate covers trace indexing, extension arithmetic, coefficient order, and coset-denominator placement | evaluator complete; official trace/proof integration incomplete |
| Raw trace prover | proves three register columns | diagnostic only |
| Program prover | consumes proof-derived semantic packs | development only |
| Production admission | explicitly rejects current packs | correct fail-closed behavior |
| CPU product | disabled descriptor, no executable or product test | incomplete |
| Metal product | disabled descriptor, no executable or product test | incomplete |
| Rust oracle | isolated official verifier accepts committed all-opcodes proof and rejects mutation | complete for Rust JSON/binary |
| CLI execution | `cairo-input` inspection only | incomplete |
| Metal execution | substantial SN2-specific resident machinery | not release evidence |
| Repository structure | several Cairo files exceed size policy | incomplete |

No existing benchmark, SN PIE receipt, compact envelope, or raw-trace test
proves this goal complete.

The focused backend-neutral admission gate is:

```text
zig build test-cairo-frontend -Doptimize=Debug
```

It does not configure CPU proving, Metal, or CUDA. The two committed official
inputs are hashed byte-for-byte, independently decoded by the pinned Rust
adapter, and compared against Zig for every opcode-state sequence, memory
table, public address, builtin segment, public-context bit, and execution
resource. Their `PublicData` is also compared for unpadded and transcript-padded
public claims, output and program value splits, and Blake2s roots. The
all-opcodes statement is independently recovered from the committed official
proof and required to equal the input-derived Rust statement. RF-02 still
requires the broader execution corpus. The same proof now pins the exact flat
claim, interaction-claim values, trace log-size matrix, and claim mix digest.
Zig derives its activation closure from the admitted input, resolves only
witness-fed log sizes from the oracle vector, and reproduces the exact claim
mix. Independent live-witness derivation of those deferred logs and the
interaction mix remain open, as does RF-03; these vectors do not establish
witness or proof parity. The official base checkpoints now define the exact
CP-04 target after every component: final accumulators are
`45acd12a96745ee0e9fbc32b5509de84c65676eb4d2a9d2bdb5822b696fd38d6`
for all-opcodes and
`d7a654ae5c3017c1c742fe9186a38f625722adf22ce47896840c83817e1818f8`
for all-builtins. A checkpoint is diagnostic evidence; only a complete proof
accepted by the official verifier satisfies RF-09.

The current official-source recording checkpoint is
`vectors/cairo/official/witness_programs_v1.bin` (2,527,495 bytes,
SHA-256 `b2108615463b3c7003b07df20e800a42c4c7625344a681ed22e78e57238c90a6`).
It contains all 64 generated official writers as complete, poison-free
programs. The source-derived feed topology at
`vectors/cairo/official/witness_feed_topology_v1.json` authenticates 1,780
producer edges from the same clean source and compiler-rewriter closure. The
backend-neutral graph executes 24 generated all-opcodes components and 26
generated all-builtins components exactly. Generic topology routers then
construct all 19 fixed multiplicity tables and all 3 memory tables for each
fixture. Together these paths reproduce every base column and cumulative
component accumulator: 46/46 components for all-opcodes and 48/48 for
all-builtins. The latter includes the 16,128 active rows, padded to 16,384, and
all 624 columns of `partial_ec_mul_generic`.

The same backend-neutral graph also reproduces every official interaction
column for both fixtures under the pinned diagnostic lookup challenge. The
final interaction accumulators are
`74386dacef4d5c36da2b02a570e894ed2a8f050f6d32d7e1228c378b3c7d0a60`
for all-opcodes and
`c62b56454feb25f110bb16dcebe583aa0adfa42e042cfefcea0827192fc1f37e`
for all-builtins. These checkpoints cover 46/46 and 48/48 components,
respectively, but deliberately do not claim the Fiat-Shamir proof transcript.

The authenticated AIR source compiler at
`tools/stwo-cairo-air-compiler` archives the exact official Stwo Git tree,
applies one exact-context evaluator accessor in an ignored overlay, and lowers
the official typed constraint tree without patching proof semantics. For the
committed all-opcodes proof it records all 46 active components, 678
constraints, 9,689 base instructions, 14,797 extension instructions, and 655
deduplicated runtime extension parameters. Two independent warm generations
produce the same 490,417-byte bundle with SHA-256
`73bae8ed0b8bf3d68e523a0eb4993918135cd1dfa9a8074118f8f9042302ec6c`.
The Zig inspector reports 46 components, 678 constraints, maximum evaluation
log 21, and plan hash `a3611657b6f2c65f`. This is exact CP-06 source
extraction evidence only: the Zig quotient evaluator and a Rust-accepted Zig
proof are still required.

The CPU integration at `src/integrations/cairo_cpu/air` now adapts those same
captured programs to the generic prover component contract. Its fixed-width
SIMD interpreter evaluates base and extension instructions directly on the
composition domain, consumes the generic accumulator's random coefficients in
the verifier's recurrence order, and applies the recorded coset-vanishing
inverse without a Cairo-specific prover fork. The focused
`zig build test-cairo-cpu-air -Doptimize=Debug` gate verifies that boundary
black-box. This establishes native quotient execution as an implementation
boundary; it is not proof evidence until the official trace commitments and
Fiat-Shamir transcript pass the Rust verifier.

The backend-neutral proof-input boundary now constructs all three official
preprocessed variants without backend imports. Stable public identities project
the canonical AIR indices onto canonical-small for the first proof campaign and
fail closed when a required column is absent. The all-opcodes conformance path
also converts the authenticated witness, fixed-table, and memory sources into
the exact 1,464-column, 28,690,992-cell M31 base commitment input. Every column
is checked against the Rust checkpoint before ownership crosses into PCS. This
is commitment-ready value parity, not a commitment-root or complete-proof
claim; production admission must additionally derive component geometry from
the live input instead of accepting fixture checkpoint geometry.

Compact claim inputs use one backend-neutral implementation of the official key
sort, tuple multiplicity merge, first-row padding, enabler, and iota laws. The
complete Poseidon deduction family is mechanically bound to the pinned official
round keys. The window-18 Pedersen aggregator and partial-EC chain use exact
on-demand Stark-curve table semantics, avoiding a 1.8 GB host-table dependency
while remaining column-identical to the Rust oracle.
This comparison also corrected a Zig semantic defect: official
`verify_instruction` multiplicities include only producer `n_active_rows`, not
the producer's padded rows. The companion provenance is intentionally marked
non-release because interaction/AIR parity and complete SIMD and Metal proofs
have not yet passed the official verifier. The repository-owned compiler
at `tools/cairo-witness-compiler` now authenticates the clean official checkout,
applies its finite AST lowering in an isolated overlay, records and validates
the bundle, and reproduces the historical checkpoint byte-for-byte. Its stable,
content-addressed Cargo cache reduces an identical-closure complete reproduction
to 3.97 seconds on the development host. The large generated EC recorder also
exposed an inappropriate `-O3` artifact-export build: the dedicated exporter
profile now compiles the changed local prover closure unoptimized in about
39 seconds instead of exceeding 16 minutes and 5.7 GB RSS.

## Delivery Order

1. Freeze official source authority and create the isolated official Rust
   verifier.
2. Port official input JSON and public statement with differential vectors.
3. Generate and authenticate complete AIR and witness programs from the pinned
   official source.
4. Reach cumulative CPU parity after every active component for base and
   interaction traces.
5. Produce one complete CPU proof accepted by official Rust, then expand the
   coverage corpus to all component families and proof formats.
6. Release the focused CPU product and CLI gates.
7. Execute the same backend-neutral proof plan through Metal, with forced-device
   telemetry and zero fallback.
8. Reach official Rust acceptance for Metal across the same corpus.
9. Decompose touched legacy monoliths, remove obsolete production claims, run
   repository conformance, and release the Metal product.

CPU correctness is the semantic reference implementation for the Zig port.
Metal work may proceed in parallel only on interfaces already fixed by
CPU/Rust parity; it cannot define Cairo semantics.

## Definition of Done

This goal is complete only when:

- all `RF-01` through `RF-18` evidence exists and passes;
- both focused products build from a clean checkout;
- both CLIs prove official inputs and execute and prove Cairo programs;
- all official component families are covered;
- every published proof in the release corpus is accepted by the exact
  official Rust oracle;
- Metal telemetry proves the required device path with zero hidden fallback;
- disabled/deferred Cairo product policy is removed;
- obsolete development-only paths are clearly isolated or deleted;
- changed files satisfy `CONTRIBUTING.md`, source conformance, formatting,
  focused tests, and product-closure gates;
- README and CLI help describe only behavior the released binaries provide.

Anything less remains an active port.
