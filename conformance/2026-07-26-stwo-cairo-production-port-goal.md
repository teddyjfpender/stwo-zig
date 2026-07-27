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
| Cairo language executable stack | `2.20.0` |
| Cairo language repository | `https://github.com/starkware-libs/cairo` |
| Cairo language commit | `eea264fa54fac04a1a5745ad533a0c0ab3106ab3` |
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

The table started at commit `cfd47be9` and is updated as evidence lands on
`feature/cairo-frontend-completion`:

| Area | Evidence | Status |
| --- | --- | --- |
| Official source identity | clean-source generated registry and pin-ledger gate | complete for frozen pin |
| Official JSON input | strict bounded reader plus all-opcodes and all-builtins Rust semantic summaries | complete for the frozen `ProverInput` wire schema |
| Public statement | exact packed-word digests and Blake2s roots match Rust for both inputs; all-opcodes is anchored to the public data inside the official proof | complete for frozen fixtures |
| Public lookup boundary | public program, output, safe-call, segment-pointer, and initial/final state relations are derived in official order; the resulting public LogUp term cancels all 46 all-opcodes component claims under both diagnostic and proof-transcript challenges | complete for the frozen all-opcodes proof |
| Claim geometry | active generator imports only the official 68-field/83-slot registry; direct, gathered, compact, fixed, and memory domains are derived from live input and the authenticated witness graph for both official fixtures, the six-program legacy corpus, and the executable corpus | complete for the admitted CPU corpus |
| Official base-trace oracle | isolated official Rust tool emits deterministic per-column and cumulative component checkpoints; all-opcodes pins 46 components/1,464 columns and all-builtins pins 48 components/3,332 columns | complete as the CP-04 comparison authority for two frozen fixtures |
| Official witness recordings | repository-owned source compiler reproduces an authenticated `STWZWIT/1` checkpoint containing all 64 generated official-source programs and 157,733 SSA instructions; its authenticated 1,780-edge source topology drives generated, fixed, and memory writers without fixture-specific routing | complete for the two frozen CP-04 fixtures |
| Official base-trace parity | all-opcodes matches 24 generated, 19 fixed, and 3 memory components (46/46); all-builtins matches 26 generated, 19 fixed, and 3 memory components (48/48), including all 624 `partial_ec_mul_generic` columns | complete for the all-family differential fixtures; release corpus adds proof-level coverage |
| Official interaction-trace parity | all-opcodes matches 46 components and 1,032 columns; all-builtins matches 48 components and 2,220 columns, including every claimed sum and the cumulative accumulator after each component; the all-opcodes proof-input path lowers the same secure columns into exact M31 commitment order | complete for both frozen diagnostic fixtures and for the all-opcodes proof-transcript challenge |
| Official preprocessed trace | backend-neutral registry constructs canonical (161 columns), canonical-without-Pedersen (105 columns), and canonical-small (156 columns) in exact stable identity order; canonical AIR indices project to canonical-small identities and reject absent columns | canonical-small and canonical are committed in independently accepted proofs; process-owned cache reuse remains |
| Official base commitment input | live execution resolves claim geometry, routes fixed and memory multiplicities, and materializes every base column in canonical commitment order without a checkpoint parameter | committed in every accepted CPU release-corpus proof |
| Official AIR compiler | authenticated exact-source overlay lowers official evaluators from either a proof or a live `ProverInput`; three source bundles cover all 68 claim fields across canonical and canonical-small preprocessing; generation differentially evaluates every recorded component against official Rust on deterministic OODS masks | complete as an authenticated template authority for the two frozen proof fixtures |
| Native Zig AIR | authenticates the template library, selects each live component by official claim identity and domain, derives live vanishing inverses, binds statement parameters, and executes through the generic CPU/SIMD domain accumulator | complete for the frozen all-opcodes and all-builtins proofs; Zig and official Rust verification pass |
| Raw trace prover | proves three register columns | diagnostic only |
| Program prover | consumes proof-derived semantic packs | development only |
| Production admission | explicitly rejects current packs | correct fail-closed behavior |
| CPU product | focused `stwo-cairo-cpu` product, adjacent pinned Cairo VM sidecar, checkpoint-free authenticated canonical and canonical-small profiles, strict CLI, product closure, Zig verification, exact JSON, Cairo-serde, and compressed-binary transports, and a serial official Rust oracle gate | compiled-JSON and Cairo 2.20 executable release corpora complete |
| Metal product | disabled descriptor, no executable or product test | incomplete |
| Rust oracle | isolated official verifier accepts deterministic Zig all-opcodes, all-builtins, six legacy-program proofs, and the Cairo 2.20 executable proof, rejects mutation, and independently derives canonical Cairo-serde and raw-bincode transports | complete for the admitted CPU corpus and all three released proof transports |
| Cairo VM execution | isolated `stwo-cairo-vm-adapter` runs compiled Cairo JSON and modern Cairo 2.20 executables under Cairo VM 3.2.0 with `all_cairo_stwo`, sorts public-memory addresses, reproduces the 181,534-byte official all-opcodes `ProverInput` byte-for-byte, derives standalone public segments from the executable builtin list, and executes the release corpus | complete for compiled JSON and executable formats |
| CLI execution | installed `stwo-cairo-cpu prove` consumes official JSON; `run-and-prove` invokes the adjacent identity-bound VM adapter for compiled JSON or executable artifacts and optional arguments; both derive the live proof schedule, publish all three transports transactionally, emit format/execution-bound reports, and optionally verify in Zig before publication | complete for direct all-opcodes/all-builtins inputs and both program formats |
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
proof and required to equal the input-derived Rust statement. RF-02 is
complete. The same proof pins the exact flat claim, interaction-claim values,
trace log-size matrix, and claim mix digest. The focused adapter vectors do not
alone establish witness or proof parity; the live proof and compiled-program
release gate described below supplies that evidence. The compiled-JSON and
Cairo 2.20 executable cases close RF-03 and RF-14 for the CPU corpus. The official base checkpoints now
define the exact CP-04 target after every component: final accumulators are
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

The production-side live graph no longer accepts component row counts from a
checkpoint. Direct roots derive their exact padded domains from opcode states
or builtin segments, gathered consumers derive them from producer
cardinalities, and compact consumers derive them from the actual unique tuple
set. The all-opcodes and all-builtins gates independently derive all 46 and 48
component logs, execute 24 and 26 generated writers, and only then compare
their rows, columns, and digests with Rust. Generic Stwo proof JSON encoding now
lives under `stwo_core`; the focused Cairo frontend no longer escapes its Zig
module to import an interop implementation file.

The CPU base commitment now prepares that graph before claim transcript mixing,
derives the statement enable bits and logs from the resolved live geometry, and
collects generated, fixed, and every memory shard in canonical claim order.
The authenticated composition bundle is checked against this live schedule
rather than against a checkpoint. The complete CPU AIR and proof gates remain
green after the ordering change.

The authenticated AIR source compiler at
`tools/stwo-cairo-air-compiler` archives the exact official Stwo Git tree,
applies one exact-context evaluator accessor in an ignored overlay, and lowers
the official typed constraint tree without patching proof semantics. It can
recover the frozen all-opcodes claim from the official proof or derive claims
and interaction claims directly from an official `ProverInput`. The
authenticated template library combines three sources: the all-opcodes
canonical bundle and all-builtins canonical and canonical-small bundles.
Together they cover all 68 official claim fields. Their respective bundle
digests are
`73bae8ed0b8bf3d68e523a0eb4993918135cd1dfa9a8074118f8f9042302ec6c`,
`2572dea6e6d3faf6dc91931f298116e3dc33a0cdda68d013913e0790f22f3b66`,
and
`55a0e17c348e5a3d92fad35cd4d80260927ed73ab556a87b02085f562886d026`.
The product authenticates the manifest and every source bundle before
admission, selects templates by official claim identity, and retargets only
live statement parameters: component domains, memory strides, builtin segment
starts, preprocessed identities, tree spans, and random-coefficient offsets.
The resulting all-opcodes proof is byte-identical to the frozen reference. The
same library now produces a complete all-builtins proof under canonical
preprocessing. Both and every proof in the compiled-program release corpus are
accepted by the native Zig verifier and the pinned official Rust verifier.

The CPU integration at `src/integrations/cairo_cpu/air` now adapts those same
captured programs to the generic prover component contract. Its fixed-width
SIMD interpreter evaluates base and extension instructions directly on the
composition domain, consumes the generic accumulator's random coefficients in
the verifier's recurrence order, and applies the recorded coset-vanishing
inverse without a Cairo-specific prover fork. The focused
`zig build test-cairo-cpu-air -Doptimize=Debug` gate verifies that boundary
black-box. The complete CPU transaction now carries the same implementation
through official trace commitments and the Fiat-Shamir transcript to a
Rust-accepted proof.

The backend-neutral proof-input boundary now constructs all three official
preprocessed variants without backend imports. Stable public identities project
the canonical AIR indices onto canonical-small for the first proof campaign and
fail closed when a required column is absent. The all-opcodes conformance path
also converts the authenticated witness, fixed-table, and memory sources into
the exact 1,464-column, 28,690,992-cell M31 base commitment input. Every column
is checked against the Rust checkpoint in the differential corpus. The
production profile commits the same values from its live schedule without
installing or reading that checkpoint.

The same proof-input boundary now derives all 128 relation powers from an
arbitrary lookup alpha, evaluates generated, fixed, XOR, and memory LogUp
sources through the shared relation evaluator, scans each final secure
column, and lowers the result to the exact four-coordinate PCS order. Under
the diagnostic challenge it reproduces all 46 all-opcodes claimed sums and all
1,032 Rust interaction columns. It retains the aggregate component sum for the
official `public_data.logup_sum + component_sum == 0` statement check; component
sums alone are intentionally not required to be zero. The production builder
orders and sizes those interaction columns from the resolved live geometry;
transcript-derived challenges and the resulting commitment remain accepted by
both Zig and the official Rust verifier.

The statement layer now implements that public-data term independently. It
enumerates program, safe-call, public segment pointer, and output memory in
official order; contributes both address-to-ID and ID-to-big relations; and
adds the signed final and initial opcode-state boundaries before one batch
inverse. The diagnostic all-opcodes gate proves that this value plus the 46
materialized component claims is exactly zero. The CPU transaction now repeats
that check under transcript-derived challenges before proof generation and
native verification.

The focused `test-cairo-cpu-proof` gate now executes the complete official
all-opcodes transaction using canonical-small preprocessed columns: channel
salt and PCS configuration, preprocessed and base commitments, interaction
PoW-24, transcript-derived lookup elements, interaction claim and commitment,
all 46 generic Cairo component provers, composition, FRI, and decommitments. It
returns the expected four commitment roots and tears down cleanly under both
`ReleaseSafe` and `ReleaseFast`. The focused product serializes the exact
3,006,412-byte official JSON proof with SHA-256
`79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`.
The native Zig verifier accepts it in process, and the pinned official Rust
verifier accepts the published bytes. The release gate also rejects a changed
interaction nonce and a changed claimed sum before proof consumption. A
ReleaseFast product run on the development host proved in 3.68 seconds and
verified in Zig in 7.1 milliseconds; these are functional measurements, not
promoted performance evidence.

The canonical all-builtins profile proves all 48 active components and
publishes a 5,305,988-byte JSON proof with SHA-256
`66768d31c69f7a637461b4cfe786cd4f13bcb55a8b7ebee02c1eba5475382348`.
On the development host, the functional ReleaseFast run proved in 127.02
seconds, verified in Zig in 13.8 milliseconds, and peaked at 21.0 GB RSS. The
pinned official Rust verifier accepted the exact published bytes in 0.52
seconds. This proof exposed and closed a generic lifted-PCS defect: an
unsampled high-domain preprocessed column must not raise the FRI lifting domain
above the final split-composition tree. A focused PCS roundtrip now covers that
heterogeneous-tree case. RF-09 is complete for the admitted CPU corpus.

The CPU product also streams the official Cairo-verifier transport without
building a second in-memory felt document. For the canonical all-builtins
proof, Zig emits 553,541 field elements in a 7,965,969-byte pretty-JSON array
with SHA-256
`895b577dfe8512dec3b667fbd7f452f42d56c29034aa158d15105861a3a217e7`.
The pinned Rust adapter independently deserializes the accepted JSON proof,
applies the official fixed-claim omission, interaction-claim flattening,
stable trace-log sort, and row-major query transpose, and emits identical
bytes. The release gate repeats the comparison on the all-opcodes CLI path.
RF-12 is complete for the two frozen profiles. RF-11 is complete on the
canonical all-opcodes release path.

The binary path emits the official bincode 1.3 fixed-width object layout and
compresses it as a standard `BZh9` stream through a bounded Zig-owned libbzip2
interface. The pinned Rust adapter independently serializes the corresponding
accepted JSON proof and decompresses the Zig artifact. The all-opcodes release
gate compares the complete 1,230,990-byte raw payload byte-for-byte, with
SHA-256
`0af5f5883a852085cbcc7d3babfde19edc651d5719ad26af54181a20fd6ce78e`,
then requires `verify_cairo` to accept the 881,489-byte Zig proof. Compression
bytes are deliberately not an equality target because Rust and Zig use
different conforming bzip2 implementations. RF-11 is complete for the released
Blake2s transport.

The CPU installation now includes `stwo-cairo-vm-adapter` as a separate
execution boundary. It is pinned to Cairo language 2.20.0, Cairo VM 3.2.0,
and the same official Stwo-Cairo/Stwo source pair, and does not contain
proof-generation or verification authority. Its all-opcodes execution produces byte-identical
`ProverInput` with SHA-256
`7f94bd5dcf32e7dd69a8a47f42d41830b4fdd3b75846ef9f7694f3164117fcd6`.
The installed `run-and-prove` path executes that 3,347,296-byte compiled
program, records the program and adapter hashes in report schema v2, then
publishes the same 881,489-byte binary proof with SHA-256
`c85871be873122a30a4c6e9c553a368281d206bc55d78c0a40ea16d819474740`
as direct `prove`. On the development host, a functional cold run spent
368.5 milliseconds in execution and 5.70 seconds in proving; the independent
official Rust verifier accepted the result. The release gate repeats execution
parity and proof acceptance.

The modern executable corpus pins a 59-byte `#[executable]` source, its
3,348-byte Cairo 2.20 executable artifact, and the hexadecimal argument vector
independently. The identity-bound production CLI derived the executable's
output and range-check public segment context, executed it in 24.10
milliseconds, proved in 2.09 seconds, and verified in Zig in 4.33 milliseconds.
It emitted a deterministic 1,884,725-byte JSON proof with SHA-256
`6560fcf8c53e74294f9e2284b7ea041c2a0a9bf7c2efc096cde4d850c061c742`;
the untouched pinned Rust verifier accepted those exact bytes. These are
functional release-gate timings, not benchmark evidence. RF-03 and RF-14 are
complete for both admitted program formats.

The repository-owned compiled-program corpus adds six independent programs
from the same pinned Stwo-Cairo tree. The manifest
`vectors/cairo/programs/official_corpus.provenance.json` binds every byte,
source path, adapter version, VM version, and proving profile. One serial
ReleaseFast release-gate run produced the following functional evidence:

| Case | Execute | Prove | Zig verify | Proof bytes | Proof SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| Bitwise | 54.58 ms | 2,839.27 ms | 4.86 ms | 1,828,426 | `3b86383712e8b742...1546470e` |
| Range check 96 | 34.11 ms | 2,230.76 ms | 5.66 ms | 1,817,014 | `35dbf85ce05e2473...803b247b` |
| Range check 128 | 37.21 ms | 8,779.75 ms | 7.77 ms | 1,777,306 | `9f2f861d3d9e89a9...a2cce2f8` |
| Poseidon | 35.62 ms | 2,185.51 ms | 6.20 ms | 2,714,305 | `9a434f2e2134125c...7eceac20` |
| Ret | 17.97 ms | 2,587.67 ms | 5.57 ms | 1,628,472 | `0261cf9ecb1d33ab...1b48d07` |
| Pedersen | 41.22 ms | 7,684.01 ms | 8.40 ms | 2,432,073 | `e6b201fc285cb6c3...aa96638` |

Every digest above was independently accepted by the untouched pinned Rust
`verify_cairo`. These are correctness timings under a contended development
host, not benchmark or promotion evidence.

This corpus closed three general correctness gaps. Live AIR template binding
now rebinds sequence preprocessed columns to the component's derived domain
instead of retaining the source fixture's `seq_<log>` identity. Empty
large-felt memory uses one all-zero log-4 shard, which is an upstream-supported
claim shape and avoids a real subtraction underflow in the pinned Rust
verifier's empty-vector path without changing that oracle. Narrow Pedersen now
has the official window-9 aggregator and 56-by-86-word partial-EC dependency
edges plus exact implementations of witness selectors 12 and 13.

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
