# Composition preparation boundary

`vm_composition_preparation.zig` owns the graph, retained schedule, evaluation
and row-18 input values used by the Ethereum V4 materializer. The recursive core
consumes its `Source` contract. It does not receive a mutable program or witness.

| Boundary | Input | Result and validation owner |
| --- | --- | --- |
| Compile | Typed Ethereum compiler input | `Compiled` privately builds one graph and one schedule. All buffer views are const. |
| Finalize | Base-field inputs and worker count | Consumes `Compiled` on success or failure. Computes all derived nodes, checks zero outputs and the complete row-18 preparation, then returns `Owned`. |
| Internal read | `Owned.source()` | A borrowed capability with copied metadata and const slices. The owner must outlive it. No graph hashing or witness replay in ordinary reads. |
| Legacy admission | `Source.borrowed` | Retains full validation of the existing mutable V2 preparation; no cached admission flag. |
| Deep audit | `Source.audit()` / `Owned.auditAgainst()` | Replays the complete preparation; the latter also reconstructs the Ethereum program from the supplied authority. |
| Row emission | Source plus executor and output columns | Invokes the existing row executor inside the ownership boundary. Mutable preparation pointers never escape. |

The compiler and finalizer share private storage. Finalization transfers the
retained schedule without copying the graph or compiling a second schedule.
No public constructor adopts an externally mutable program or evaluation.
Compiled and finalized handles have different opaque types. Consumer views are
data projections, not independently serializable proof authority.

Run the small ownership loop from the repository root:

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv \
  test-recursion-preparation -Doptimize=ReleaseSafe --summary all
```

This target checks allocation failures, rejection cleanup, alias isolation,
unchanged legacy circuit identity/data, and mutable-witness rejection. It does
not prove an Ethereum wrapper. The retained genuine-input integration gate is:

```sh
STWO_ROLE0_STAGE101_REPLAY_DIR="$PWD/.git/local-ethereum/role0-genuine-stage101-canonical-io" \
STWO_ROLE0_GENUINE_WORKER_COUNT=1 \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-incremental-leaf-materializer-custody-v4-replay \
  -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all
```

For the broader VM profile and field-publisher compatibility gate:

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv \
  test-vm-air-profile-v2 -Doptimize=ReleaseSafe -Dprofile-test-strip=true \
  --summary all
```

`profile-test-strip` omits debug symbols from this test target; it does not
disable ReleaseSafe checks. Leave it unset for symbol-rich debugging. A compiler
sample identified LLVM debug-history generation as the expensive phase: the
same 15 checks compiled in 6m/6G with symbols and 25s/1G without them, with the
same 6s/77M test runtime. These are local development measurements, not prover
performance results.

## Remaining admission boundaries

The Ethereum V4 materializer now uses the schema-2 statement-root graph.
Its `StatementRootCompilerInput` accepts
geometry but has no root-value fields. `Compiled.initEthereumWithStatementRoots`
appends two canonical statement inputs and records the bridge AIR over them.
`vm_statement_roots.zig` owns their coordinates and profile extension encoding.
The separate zero-count legacy profiles retain input order, tags and identity
preimages; the shared RV32/CSP route has not been switched to this graph.

The retained native-proof gate accepts the authentic roots under this graph and
rejects a change to either root without changing its graph identity:

```sh
STWO_ROLE0_STAGE101_REPLAY_PATH="$PWD/.git/local-ethereum/role0-genuine-stage101-canonical-io/fb15a6064ae68884f64ef138987b0f5053f18df708162b29336091e14db94e6b.bin" \
STWO_ROLE0_STAGE101_REPLAY_SHA256=fb15a6064ae68884f64ef138987b0f5053f18df708162b29336091e14db94e6b \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-statement-root-replay -Doptimize=ReleaseSafe \
  -Dethereum-proof-strip=true --summary all
```

Each new row consumes `(segment statement scope, canonical root-word index,
root value)` through the existing statement-word relation.
`statement_input_roots_v3.zig` provides a separately sealed provider AIR and
fixed routing schedule: the two canonical root words each have one extra
segment-scope emission. It uses the same AIR builder as V2; the legacy branch
retains its exact semantic and static-profile identities. The extra column is
preprocessing slot 7 (logical slot 9), before the five verifier parameters.
Physical and logical layouts both use main, preprocessing, parameters. The
earlier opt-in layout placed this input after parameters; logical replay alone
could not detect its incompatibility with the native physical adapter.
The static-profile check measures 15 logical inputs, 2 direct constraints and
4 relation events. Its modeled interaction degree is 4 (V2 is 3), so admission
must also derive quotient geometry from this profile.

`statement_root_routing_audit.zig` checks the entire 412-word **segment scope**
using entries compiled from the provider, canonical statement-semantics circuit,
and VM input AIR. It does not synthesize opposing terms. The focused command
also rejects missing, duplicated and changed root consumers, schedule mutation,
and AIR mutation, and runs all six existing V2 statement-provider checks.
The same audit runs on the retained native proof's statement and graph inputs.

`StatementRootOuterCatalog` in the shared composition-profile module selects
the new provider type for row 10. The existing manifest builder derives its
geometry and downstream offsets; all other component geometries stay frozen.
`statement_root_physical_audit.zig` exercises the allocation-free preprocessing
writer, legacy-profile rejection, and actual native verifier point callback.
It records the same component once and compares recursive evaluation across
authentic and altered physical samples. These physical checks use fixed test
challenges; they are evaluator parity evidence, not an outer STARK proof.
The genuine replay also runs them with the retained native statement words.

The initial live Ethereum wrapper selected this catalog through manifest schema 4,
with 571 preprocessing columns. Its row-10 native component and physical writer
use the same selected AIR. All 40 focused integration checks pass, but this is
**not outer provider closure**: the genuine complete-cohort replay fails with
`EthereumIncrementalTupleNotClosedV4` before PCS allocation. Its first measured
request took 402.9 seconds and peaked at 38,459,568,304 physical-footprint bytes.
The replay now reports bounded unmatched tuple provenance:

```sh
STWO_ROLE0_STAGE101_REPLAY_DIR="$PWD/.git/local-ethereum/role0-genuine-stage101-canonical-io" \
STWO_ROLE0_GENUINE_WORKER_COUNT=1 \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-statement-root-cohort-replay -Doptimize=ReleaseSafe \
  -Dethereum-proof-strip=true --summary all
```

This command constructs all 36 components and both shared providers. It must
close every relation and scope; the small segment-scope routing check cannot
substitute for it. The first failure and its SHA-pinned genuine inputs are
retained as regression evidence. Preparation improvements remove duplicate
parent validation and per-component geometry reads while retaining input,
finalization and proof-boundary checks.

Before admitting the statement/public-claim arithmetic graphs, the replay retained 66,568,919 contributions. The statement-word relation
closes across the complete cohort, while five other domains have 115,664
unmatched tuples. Hoisting repeated validation reduces this same failing
request from 354.7s to 244.0s; peak footprint remains 35.8 GiB. This is development
loop evidence, not a completed proving benchmark. Exact counts, sampled origins
and input hashes are retained in the PR198 progress checkpoint.
The existing V1 field publishers share `vm_binding_field_encoding_v1.zig` and
explicitly reject these new inputs until their field admission is versioned.

Other statement/boundary constants in recursive construction, shared transcript
admission, and proof serialization followed by verification after producer
destruction remain outstanding. This module does not yet admit an independently
verifiable universal root.

Keep broader wrapper optimization and block benchmarking behind those gates.
Preserve the raw V2 route until its replacement passes complete proof checks and
the current-tree CSP latency/memory comparison. Library boundaries should follow
these ownership and protocol contracts; file count is not the success metric.

## Statement and public-claim arithmetic admission

`ethereum_statement_arithmetic_v4.Prepared` owns the two graphs whose inputs
are emitted by rows 11 and 15. The Ethereum native core now includes both in
the existing shared arithmetic lowering. Previously those input providers
were present while their graph consumers were absent.

Construction validates the fixed canonical statement circuit, rebuilds the
expected claim circuit under the SegmentV2 statement-I/O policy from its
capacity, and compares the complete claim authority identity. A self-consistent
producer graph or the legacy zero-I/O policy cannot substitute for this circuit.
It checks every evaluation node, copies the converted graphs and evaluation
values into private storage, and exposes only const views. The owner must
outlive the native core; all source allocations can be destroyed after admission.
Version 1 of this admission hashes fixed circuit IDs, source identities and
graph identities. The native core binds that identity only on the Ethereum
path, preserving the null/legacy identity preimage. Witness values are excluded
from the circuit-admission identity.

The everyday `test-recursion-preparation` command includes rejection of stale
evaluations and the wrong I/O policy, failure cleanup at every allocation,
source mutation isolation, and reads after destroying all source state.
Those are ownership/admission checks; they do not replace the complete proof.

| Data | Admission responsibility | Remaining AIR responsibility |
| --- | --- | --- |
| Circuit IDs, graph policy and capacity | Reconstruct and version the expected graphs. | Evaluate the admitted operations through shared arithmetic AIR. |
| Statement and claim input descriptors/use counts | Derive from those graphs and retain immutable plans. | Row-11/15 input tuples must match every arithmetic consumer. |
| Statement words, including bridge roots | Keep values out of fixed graph identity. | Authenticate through statement-word relations and exact provider counts. |
| Public-sum register bytes | Admit exact byte coordinates, destinations and use counts in the shared statement-routing plan. | The Ethereum byte AIR reuses statement-word authentication, integer decomposition and `(8,8)` ranges; all 256 byte wires close in the genuine cohort. |
| Public-sum register clocks, role-I/O stream, tuple selectors and published values | Admit their layouts and source classes, not their values as constants. | Connect every used input to the committed source and constrain selectors. This remains incomplete. |
| Relation challenges and claimed sums | Share their transcript order and coordinate layout. | Join the verifier-input/challenge relations and complete closure. |

The remaining public-sum boundary is explicit in
`recursive_common_ethereum_incremental_leaf_public_logup_input_v4.zig`: it
currently projects only one selector and 32 challenge words. Its native graph
also reads the other source classes listed above. Full routing must account
for those inputs and their authenticating providers before changing the old
public-claim word/byte emission counts. Producer-state destruction followed by
independent verification of a serialized wrapper remains a separate required gate.


## Complete-proof development gate

From the repository root, with the retained SHA-pinned corpus available:

```sh
STWO_ETHEREUM_PROOF_CORPUS="$PWD/.git/local-ethereum" \
STWO_ROLE0_GENUINE_WORKER_COUNT=1 \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-complete-proof -Doptimize=ReleaseSafe \
  -Dethereum-proof-strip=true --summary all
```

This one target runs the genuine label-input commitment rejection case and the
wrapper replay. A successful replay must prove the complete cohort, retain
serialized wrapper bytes, destroy every producer capture/campaign/materializer,
rebuild verifier inputs from the serialized native proofs, then cold-verify the
wrapper. A materialization-only result cannot pass this target. The existing
focused commands remain available; `STWO_ETHEREUM_PROOF_CORPUS` selects both case
directories without changing their pinned hashes.

The current route still fails exact cohort closure before PCS. The command is
an acceptance gate, not evidence of an independently verified wrapper or root.
The separate `test-ethereum-independent-inputs-replay` target exercises producer
destruction and fresh input reconstruction without producing a wrapper; its
receipt explicitly says `wrapper_verified=false`.

The Ethereum manifest is now schema 6: 575 preprocessing columns, 1,044 main
columns, 564 interaction columns and 1,313 constraints. A private row-16 owner
retains the copied, value-independent `statement_routing_v4.Plan` (schema 2).
It derives the used statement inputs and the canonical 256 register-byte inputs
from the admitted public-sum graph. That single plan supplies row-10 provider
multiplicities and row-11 word/byte destinations with exact graph use counts.
A statement input is consumed once when either its word or one of its bytes is
used; unused inputs add no rows. Internal plan reads remain const and cheap.

`StatementRoutingOuterCatalog` selects `statement_semantics_bytes_v2` for row 11.
This Ethereum-only AIR calls the shared legacy builder and reuses its integer
decomposition constraint and `(8,8)` range lookup. Four fixed preprocessing
columns carry the low/high byte destinations and counts; two extra events emit
those authenticated bytes. Main trace columns and direct constraints stay at
four and six. Witness values are excluded from the routing identity. Native
adapters and recursive recording consume this selected AIR and the same logical
rows through the manifest. The legacy default and root-only catalogs, AIR seals,
CSP defaults and worker policy remain unchanged.

The byte-routing checkpoint passes 42/42 focused checks and 26/26 preparation
and legacy-compatibility checks, including eight existing row-11 cases. On the
retained tiny genuine leaf pair, all 256 register-byte wires close: arithmetic
residuals fall from 456 to 200. The complete command still passes only 1/2 tests.
Its 68,820,890 contributions contain 34,493 unmatched tuples; statement and range
relations close, while Poseidon I/O (131), arithmetic wires (200), verifier input
words (6,832), public-claim words (10,506) and public-claim bytes (16,824) remain.
The wrapper fails before PCS in 248.0 seconds with 36.0 GiB peak physical
footprint. These are failure diagnostics, not an Ethereum proving benchmark.
The proof serialization/destruction/fresh-verification path has not been reached.
Exact measurements, input hashes and tuple samples are retained in
`statement_byte_routing` in the PR198 progress checkpoint.

Clock limbs, role-I/O words, tuple selectors, published sums and the remaining
wrapper statement/boundary inputs still need complete authenticated routing and
admission. The source no longer describes its selector/challenge projection as
lossless. All three prerequisites continue to gate block proving, and these
compatibility checks do not replace current-head CPU/Metal CSP A/B measurements.


## Shared detailed-claim routing and saved wrapper replay

Ethereum transcript-program schema 4 classifies the 12 native extension batch
claim frames into ordered detailed verifier inputs (kind 12). The shared
transcript-payload witness owns the Ethereum recorded-frame admission and layout;
the integration uses it directly. Existing default recorded/scheduled entrypoints
continue to reject kind 12. The consolidated focused routing/storage suite passes
45/45. The complete genuine cohort closes 6,680 former verifier-input residuals,
leaving 152. Total unmatched tuples are 27,813; the full gate remains 1/2 and
fails before PCS. Singleton aliases, base claim authentication, clock/IO/publication
joins and independent circuit admission remain incomplete.

The final replay takes 250.374 seconds with 36.0 GiB process lifetime peak
footprint. Bounded Ethereum-only resource markers record ledger length/capacity,
record bytes and phase intervals. The observed peak rises during native tuple
append. The final ledger uses 9,360,549,520 bytes in 12,350,301,848 bytes capacity;
record size is 136 bytes. These ledger totals are exact; lifetime process peaks
do not report current live allocations or identify growth overlap by themselves.
The checkpoint retains every marker and source hash. No completed proof or CSP
performance result follows from these diagnostics.

To independently reopen a retained wrapper, replace the placeholders and run:

```sh
STWO_ETHEREUM_WRAPPER_REPLAY_DIR="<corpus>/wrapper-replays/<triplet-sha256>" \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-wrapper-replay -Doptimize=ReleaseSafe \
  -Dethereum-proof-strip=true --summary all
```

The directory contains `leaf-0.bin`, `leaf-1.bin` and `wrapper.bin`; its identity
includes the ordered hashes of all three files. Existing files are compared with
bounded buffers and mismatches reject. The command rebuilds verifier preparation
from disk inputs and cold-verifies the wrapper without a live producer owner.
It has compiled successfully, but no genuine Ethereum wrapper exists to execute
it. Export occurs only after the proving API returns, so failures during its
internal verification/initial capture still cannot be retained by this hook.
The combined complete-proof gate must still reach serialization, producer
destruction and fresh verification before the three prerequisites are satisfied.


## Native schema-3 development checkpoint

The explicit native producer command now passes its complete native lifecycle:

```sh
STWO_ETHEREUM_PROOF_CORPUS="$PWD/.git/local-ethereum" \
STWO_ROLE0_GENUINE_WORKER_COUNT=1 \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-native-base-bound-producer -Doptimize=ReleaseSafe \
  -Dethereum-proof-strip=true --summary all
```

It generates two schema-3 native leaves into `base-bound-v3`, destroys producer
allocations and buffers, then reads and freshly verifies both pinned files.
Measured result: 1/1, 125.139s, 1,179,403,824 bytes lifetime peak physical footprint.
The selected base claims have one shared native/recursive layout. Legacy
schema-2 artifacts remain separate regressions; changing a schema label cannot
admit their proof under the new transcript.

This does not establish a complete wrapper. The earlier 27,813-unmatched closure
result is a historical snapshot, before the latest clock, alias and cancellation
changes. The focused 52/53 header mismatch has an implemented eight-limb fix
awaiting rerun. The schema-4 public-sum endpoint and schema-6 row-16 canonical
claim routing also await combined proof-level verification. The evidence receipt
is `autoresearch/notes/2026-09-05-pr198-local-ethereum-plan/evidence/recursive-segment-v2-io-progress.json`.

## Bounded admission and tagged native transcript checkpoint

Focused publication preparation passed 43/43 before later prototype removal;
whole-program admission passed 4/4, and the subsequent integration batch passed
65/65. The earlier schema-3 native production/destruction/disk-verification
receipt remains 1/1. These are separate receipts, not a complete wrapper result.
The new schema-3 cohort replay has started without a terminal receipt here.

Whole-ELF admission now fixes every supported executable completion row and its
native program commitment independently of a proof's selected PC. The current
fixture profile caps the table at 64 executable rows and role routing at 32
tuples, with explicit nonfinal completion semantics. Oversized programs fail
before polynomial/graph allocation. This is not the mainnet proving profile.

The native schema-4 opt-in introduces a shared tagged frame walker in
`ethereum_incremental_field_transcript_v4.zig`. Native channel emission and
recursive frame description can consume the same exact payload encodings.
Custody-only SHA identities remain in input validation, while role IO and
completion enter the transcript as explicit words. Historical schema-2/3
recorded-frame comparison and real schema-4 helper tests are implemented under
`Ethereum schema4` but have not passed a gate yet. Exhaustive raw V2 layout and
its authenticated routes remain a separate prerequisite; an initial layout
compiler failure is retained in evidence.

The wrapper replay directory now contains both native leaves, `program.elf`, and
`wrapper.bin`, all included in its identity. Fresh verification still reopens and
natively verifies the leaves and reconstructs verifier preparation before
checking the wrapper. It removes dependence on producer state; it does not
provide root-only verification. The authoritative receipts and their exact
scope are recorded in `bounded_admission_and_publication_checkpoint` under the
PR198 evidence directory. No independently verified wrapper or current-head
CPU/Metal CSP A/B promotion receipt exists at this checkpoint.

## Final-claim consolidation and current complete-proof rerun

The current focused receipts are frontend 41/41, integration 79/79 and native V2
layout 18/18. Native schema-4 emission, exact legacy framing and frame-plan checks
pass. The final interaction sequence is shared through
`AuthorityV4.mixFinalClaims`: selected base claims when admitted, then bridge,
after the existing extension prefix. This fixes the real recursive replay's
missing selected-base absorption without changing legacy schema-2 bytes.

The real cohort previously stopped with 458 residuals: 450 duplicate public
boundary emissions and eight inherited VM-claim-digest consumers with no native
Ethereum source. The current Ethereum route removes these redundant paths,
including the old child hash allocations/rows/provider calls. Semantic and role
claim routes and IO hashes remain; CSP's original semantic seal is checked.
The full lifecycle rerun in `/tmp/ethereum-complete-proof-boundary-v4.log`, session
19754, has returned; its terminal receipt follows.

A historical 1/1 input reconstruction receipt records producer destruction and
fresh preparation from serialized native inputs, with `wrapper_verified=false`.
Its source head and exact executable snapshot are unknown; it is not part of the
current 41/79/18 batch and has not been verified against the current tree. The current wrapper route remains native-assisted.
The tested schema-4 FramePlan has not yet replaced active recursive admission,
and raw V2 sources still need exact authenticated closure. This is a bounded
64-row-program, 32-role-tuple, nonfinal development profile, not a full-block or
root-only proving endpoint. Evidence is retained under
`shared_final_claims_and_boundary_closure_checkpoint` in the PR198 JSON receipt.


## Exact cohort closure and the remaining proving failure

Session 19754 (`test-ethereum-complete-proof`) passed 2/3 tests and failed the
genuine saved-pair wrapper request at `prove.stark` with `InvalidProofShape`.
Before that failure, the exact tuple ledger classified and released all
68,788,872 contributions without mismatch. The redundant boundary and inherited
claim-hash routes are therefore closed for this actual cohort. No wrapper was
serialized or independently verified.

The request took 597.676632792s. Ledger classification reached a process lifetime
peak of 27,332,448,608 bytes; later proving raised the overall peak to
45,273,744,552 bytes. The historical 458-residual run peaked at 38,094,647,232
bytes. The lower ledger high-water is not a whole-request memory improvement or
a live-owner measurement. Full telemetry and the uniquely retained terminal log
are recorded in `complete_proof_boundary_v4_checkpoint` in the PR198 JSON receipt.

Focused schedule admission now passes 15/15 and native V2 layout 20/20. The
proving-policy correction being implemented after the failure is unverified at
the complete-proof level. Schema-4 FramePlan integration, authenticated raw V2
AIR routing, and the complete serialization/destruction/verification lifecycle
remain prerequisites. The active bounded fixture route is native-assisted, not
a root-only or mainnet block endpoint. The historical source-unknown input
reconstruction receipt remains separate from current gates.


## Focused schedule and quotient-domain checks

Run these focused checks from the repository root:

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-recursion-schedule-admission -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-recursion-quotient-domains -Doptimize=ReleaseSafe --summary all
```

Retained receipts pass 15/15 schedule tests and 6/6 quotient-domain tests. The
latest integration batch passes 83/83 and native V2 layout 20/20. Complete-proof
retry 1030 has now returned; its later finalization failure is recorded below.
Separate source batches and documentation-time hash limitations are explicit in
`retained_coefficients_retry_checkpoint`; no wrapper verification is inferred.


## Retained-coefficient terminal receipt

Retry 1030 passed 2/3 tests: all 68,788,872 exact tuple contributions closed,
then finalization rejected with `ConstraintsNotSatisfied`. The former
`InvalidProofShape` is no longer this run's stopping point, but no wrapper was
serialized or independently verified. The full request took 814.173816291s with
a 59,835,018,536-byte process lifetime peak. Finalization/OODS debugging and a
later focused 87-test gate are pending; no successful outcome is inferred.

The actual resource plan has `blowup_log=1` (LDE factor 2). Native-sized retained
coefficients total 10,908,653,376 bytes, half the LDE storage; the earlier guessed
1/16 ratio does not apply. The PCS minimum estimate is 32,725,960,128 bytes,
excluding Merkle, witness and composition owners, and is distinct from the
measured process peak. The uniquely retained terminal log and hashes are in
`retained_coefficients_terminal_checkpoint`. The active route still needs fixed
recursive admission and a complete wrapper lifecycle; native-assisted reopening
is not root-only verification or a mainnet block benchmark.


## Verified coefficient recovery and bounded preflight

Quotient recovery now passes 8/8 after fixing packed radix-8 indexing for a
larger twiddle tower. Exact-size indexing remains unchanged. The independent
1/1 kernel regression covers forward, inverse, normalized inverse and
duplicated-half expansion with 1x/2x/4x table sizes. Missing coefficients are
recovered from the complete committed LDE inside the existing quotient buffer;
nonzero coefficients above native degree reject before truncation. Genuine
nonconstant polynomial parity passes at native logs 2/4/6/7/8. No additional
whole source coefficient set is retained; quotient buffers remain live.

Integration passes 89/89 and static AIR preflight 2/2. The genuine first-18
component preflight passes 1/1, checking direct roots, adapter parameters and
padding (93.695878083s, 17,835,849,240-byte lifetime peak). Its receipt explicitly
excludes the full cohort and wrapper verification. Exact logs and source-batch
limitations are in `quotient_recovery_and_preflight_checkpoint`. The full
schema-3 native-assisted wrapper still fails OODS finalization with
`ConstraintsNotSatisfied`; no root-only verification or Ethereum block proof
is established. Fixed schema-4 admission and raw V2 AIR integration remain open.


## Normalized mixed-quotient admission checkpoint

The production-geometry fixture exposed a q1/q2 lifting mismatch (3/4 tests
passed). Ethereum wrapper admission v1 now selects split two for every component:
q1 callbacks use the existing polynomial extension; q2 callbacks change only
the split declaration. Both prover/verifier handle sets are normalized before
gate sealing. Wrapper manifest schema 13 binds this policy into the contract
identity; native schema-3 leaf fixtures and default CSP geometry stay unchanged.

Admitted geometry passes 5/5, core split-only behavior 3/3, and explicit wrapper
capture admission 3/3. Capture reconstruction uses normalized `max(trace+2)`
and requires split two only through the Ethereum wrapper constructor; legacy
constructors still reject it. The first-34 genuine AIR preflight passes 1/1
(101.466684791s, 17,835,931,208-byte lifetime peak), excluding provider rows and
wrapper verification. The small proof executable passes 2/2 but its target's
count guard failed; the aggregate remains 95/96 until corrected retry 40794
finishes. These results are retained in `normalized_wrapper_geometry_checkpoint`.

No new full wrapper receipt exists: the last complete request failed OODS
finalization. The current native-assisted diagnostic is not root-only
verification or an Ethereum block benchmark. PCS resource estimates exclude
additional quotient-extension/composition buffers.


## 2026-09-06: corrected combined gate passes 101/101

Combined session 40794 passed **101/101 tests and 8/8 build steps**, including
both exact-count guards: small composition proof **2/2** (19s/1G compile,
304ms/4M run) and integration **99/99** (1m/5G compile, 1s/69M run). This
supersedes the earlier fixture-count and test-count-guard failures; their logs
remain retained as historical regression evidence. The new immutable receipt is
`ethereum-composition-admission-combined-101-passed.log` in the PR198 evidence
directory, with its SHA-256 and source-batch scope in `combined_pass_checkpoint`.

Complete-wrapper and failed-proof replay compile checks are running in session
41064; no terminal result is recorded here. The latest full wrapper result
remains the retained `ConstraintsNotSatisfied` failure. These focused successes
do not establish wrapper serialization/fresh verification, a root-only endpoint,
a full Ethereum block benchmark or CSP promotion.
