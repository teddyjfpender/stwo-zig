# Small native and recursive proof loop

The small detached route now proves both segments of a completed memory
workload using CPU or Metal native proving, followed by CPU outer proving.
A separate verifier checks both serialized proofs, exact coverage, memory and
clock continuation using explicit keys and expected public inputs. The two child
proofs can now be recursively verified in one CPU parent STARK. Its standalone
verifier needs only the admitted key, expected root, claims and serialized proof.
This is the q1/native, q3/child-and-parent development profile. Actual4/8-segment
jobs now produce every child, intermediate parent and one freshly verified root.
Production-security measurements and CSP performance promotion remain pending.

Current retained evidence and rejection cases are indexed in
[the detached-route progress report](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/progress.md).

## Complete detached proof gate

Build the producer and verifier once:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  build-recursive-segment-v2-concrete-outer-proof \
  build-recursive-segment-v2-detached-verifier -Doptimize=ReleaseSafe --summary all
```

Then generate both children, wait for producer destruction and process exit,
and check acceptance plus tampering in fresh verifier processes:

```sh
proof_bins=src/integrations/riscv_cpu/zig-out/bin
proof_evidence=vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1
proof_output=.git/local-riscv-proving-stack/detached-cpu-example
python3 scripts/riscv_segment_v2_detached_gate.py \
  --producer "$proof_bins/recursive-segment-v2-concrete-outer-proof" \
  --native-backend cpu --initial-memory-word 13 \
  --verifier "$proof_bins/recursive-segment-v2-detached-verify" \
  --bundle "$proof_output/child-0" \
  --key-sha256 a0c39b4d4fcc7f94cd37d62dd671f90bfc778cb879bff29ea7bbdd2172539aaa \
  --expected-wire "$proof_evidence/dynamic-memory-v3-admission/seed13-child-0-expected-wire.json" \
  --other-expected-wire "$proof_evidence/dynamic-memory-v3-admission/seed13-child-1-expected-wire.json" \
  --adjacent-bundle "$proof_output/child-1" \
  --adjacent-key-sha256 02697d47111fa4cec96b3c2d701f59940eb070d8b94a9c45d63db8f331f20517 \
  --adjacent-expected-wire "$proof_evidence/dynamic-memory-v3-admission/seed13-child-1-expected-wire.json" \
  --output "$proof_output.json"
```

Choose a new output path for each run. Key pins and expected statements above
come from independently retained admission for this exact fixture; the command
never trusts newly produced admission files. A circuit change must be admitted
separately before replacing these pins.

The current command uses reviewed seed13 admission after dynamic memory ranges
and selectors were added. Seeds13/14/269 have fresh CPU proof evidence under
the same per-child keys; arbitrary address topology is a separate admission.

For Metal, build the same producer target under `src/integrations/riscv_metal`,
use that directory's installed producer with `--native-backend metal`, and add
`--aot-bundle PATH --aot-manifest-sha256 SHA256`. Keep the CPU verifier and the
same independent pins and expected statements. The gate checks real Metal
dispatch for both children. AOT generation is described below.

Omit `--producer` to replay existing artifacts without taking the heavy-job
lock. This keeps the small verification loop usable during a separate build.
The retained complete commands passed all 17 cases in 8.076 seconds on CPU and
6.282 seconds with Metal native proving. These are development observations,
excluding compilation, and do not establish a production-security benchmark.

## One independently verified recursive parent

Build `build-recursive-segment-v2-detached-parent-producer` and
`build-recursive-segment-v2-detached-parent-verifier` under the CPU integration
with the serial build command above. Both CPU- and Metal-produced child bundles
use this same CPU parent route. Metal parent proving is not claimed.

Derive expected root words from the independently retained child public inputs,
without reading any candidate proof or producer-generated root:

```sh
"$proof_bins/recursive-segment-v2-detached-parent-verify" --derive-expected \
  "$proof_evidence/dynamic-memory-v3-admission/seed13-child-0-expected-wire.json" \
  "$proof_evidence/dynamic-memory-v3-admission/seed13-child-1-expected-wire.json" \
  /absolute/new/expected-root.json
```

The retained independent fixture admission is `detached-parent-v2-admission/`.
The parent key pin is
`3b96247b69ad8499f93de85bf528444dd27fa946c3b06f31ee5bf0af9f21d0b6`.
It covers exactly `tiny-memory-root-v2`, including address membership and child keys;
it does not authorize arbitrary circuits of the same dimensions.

One command then produces, destroys the producer process, and runs all 25
fresh-process acceptance/rejection cases:

```sh
python3 scripts/riscv_segment_v2_detached_parent_gate.py \
  --producer "$proof_bins/recursive-segment-v2-detached-parent-prove" \
  --producer-sha256 REVIEWED_PRODUCER_BINARY_SHA256 \
  --verifier "$proof_bins/recursive-segment-v2-detached-parent-verify" \
  --verifier-sha256 REVIEWED_VERIFIER_BINARY_SHA256 \
  --parent-key "$proof_evidence/detached-parent-v2-admission/parent-key.json" \
  --key-sha256 3b96247b69ad8499f93de85bf528444dd27fa946c3b06f31ee5bf0af9f21d0b6 \
  --expected-root /absolute/path/to/expected-root.json \
  --expected-root-sha256 REVIEWED_EXPECTED_ROOT_SHA256 \
  --left "$proof_output/child-0" \
    a0c39b4d4fcc7f94cd37d62dd671f90bfc778cb879bff29ea7bbdd2172539aaa \
    "$proof_evidence/dynamic-memory-v3-admission/seed13-child-0-expected-wire.json" \
  --right "$proof_output/child-1" \
    02697d47111fa4cec96b3c2d701f59940eb070d8b94a9c45d63db8f331f20517 \
    "$proof_evidence/dynamic-memory-v3-admission/seed13-child-1-expected-wire.json" \
  --bundle /absolute/new/parent-bundle --output /absolute/new/parent-report.json
```

Omit the producer options, parent-key path and child arguments to replay an
existing bundle without the heavy-job lock. Review binary hashes against the
build/source receipt; a freshly hashed arbitrary executable is not admission.
The lifecycle starts from saved child proofs; it does not include native proving.

The earlier version1 runs (seeds13/14/269, both child backends) share the exact parent key
and pass 126 fresh-process cases. Corresponding parent artifacts match byte for
byte across child backends. Parent requests took 3.87–4.06s, fresh verification
9.7–11.8ms, and maximum RSS about655–656MiB. Proofs are92,779–96,390bytes.
These are individual development observations, not production benchmarks.
`detached-parent-v1-measurements.json` separates preparation, fixed-key commitment,
remaining proving/serialization, process wall time and verification. The
remaining proving phase is3.19–3.37s; further attribution is needed before naming
its dominant operation. Compilation remains separate (producer about1min,
verifier44s in the retained builds).

For the next recursive consumer, run
`test-recursive-segment-v2-detached-parent-capture` under the CPU integration.
Set `STWO_DETACHED_PARENT_BUNDLE`, `STWO_DETACHED_PARENT_KEY_SHA256` and
`STWO_DETACHED_PARENT_EXPECTED_ROOT` to the retained bundle, independent pin and
expected-root path. Missing inputs fail the gate. It verifies the actual parent,
destroys the caller inputs, then replays its recorded composition and PCS/FRI
arithmetic with45 claim/sample mutations. The retained run takes882ms at17MiB
RSS after compilation. It does not generate a next-layer proof.

The current version2 publication includes the436-word span/session/lineage
statement. Its key explicitly binds `root` or `intermediate` mode. Six root runs
pass150 fresh-process cases under the same key; an intermediate-mode run passes
25 additional cases, using the same complete two-segment job (not yet a partial
four-segment subtree). Current timings are in `detached-parent-v2-measurements.json`.
The gate defaults to root acceptance; intermediate acceptance must explicitly use
`--publication-mode intermediate` and its separately admitted key.

## Retained native-assisted benchmark route

The earlier CPU and Metal measurements below use one guest fixture, native Poseidon protocol,
canonical serialization, and fresh CPU native verification. Both then run the
same 39-component, 47-domain CPU outer proof. This is the existing q1/native,
q3/outer development profile, not the secure CSP profile or a detached root.
Native producer allocations are destroyed before decoding its proof. The outer
verifier still requires the separately admitted native input.

## Fast semantic gate

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv \
  test-poseidon-merkle -Doptimize=ReleaseSafe --summary all
```

This checks scalar/SIMD permutation and leaf parity, every layer of mixed-domain
and streaming Merkle trees, and scratch allocation failure cleanup. It avoids
compiling the native and recursive prover graphs.

## Complete CPU proof

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  run-recursive-segment-v2-concrete-outer-proof -Doptimize=ReleaseSafe \
  --summary all -- --native-steps 64 --native-backend cpu
```

Sizes are 1, 4, 16, and 64 instructions of the same finite counter-loop ELF.
`--check-workload` validates all execution prefixes and their 16-cycle
continuations without proving. Omitting arguments runs the broader mutation and
downstream replay gate. The continuation defines the fixture endpoint; this
example proves the first child, not a pair of children or a whole block.

## Complete proof with Metal native proving

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal \
  run-recursive-segment-v2-concrete-outer-proof -Doptimize=ReleaseSafe \
  --summary all -- --native-steps 64 --native-backend metal \
  --aot-bundle /absolute/path/to/core-v2-bundle \
  --aot-manifest-sha256 MANIFEST_SHA256
```

The runtime admits the pinned `core_v2` AOT bundle, checks actual Poseidon device
dispatch, and shuts down before fresh CPU verification and outer construction.
A missing/mismatched bundle fails before proving. CPU builds do not import Metal.
The retained local `.git/local-ethereum/aot-m4` bundle and its digest are recorded
in the September 8 native fixed-cost evidence. They are local artifacts, not a
portable dependency. To produce a bundle elsewhere:

```sh
python3 scripts/zig_serial_build.py metal-core-aot -Doptimize=ReleaseSafe
zig-out/bin/metal-core-aot build --output-dir /absolute/new/bundle
```

## Measurements and memory ladder

Build once, then use `scripts/riscv_small_recursive_benchmark.py --binary PATH
--backend cpu --out NEW_DIRECTORY`. It runs three fresh processes per instruction
size, retains logs/binary hashes, and checks complete-proof success. Metal also
requires the two AOT arguments above. Complete-request time includes process
startup, runtime initialization, both proofs and verification, and teardown;
compilation is separate. Source patches captured by the runner describe the
invoking worktree; retain the corresponding build log/source receipt to bind an
older binary to its build source.

For the separate memory ladder, select `--memory --sizes 1 4 16`. The runner uses
64 instructions in every case while varying 1/4/16 distinct word addresses,
initially zero and spaced 128 bytes apart. The ELF length stays fixed. This
changes sparse memory paths as addresses increase; initializing the same
contiguous words in every case would conceal that cost.
It independently checks each load/store and final state, including a store
pending across the 16-cycle continuation. `--check-memory-workload` runs those
execution and corruption checks without proving.

For diagnostic runs, set `STWO_RISCV_NATIVE_PROFILE=1`, `STWO_ZIG_PCS_TIMING=1`,
and `STWO_ZIG_PCS_COLUMN_HISTOGRAM=1`. CPU/Metal composition timing is available
through `STWO_ZIG_RISCV_CPU_COMPOSITION_TIMING=1` and
`STWO_ZIG_RISCV_METAL_COMPOSITION_TIMING=1`. Stage/task recording can perturb
scheduling, so the repeated timing runner removes diagnostic flags. Do not add
overlapping worker spans to coordinator wall time.

Native allocator counters cover caller-allocator payload, excluding size-routed
Merkle mmap buffers and device allocations. Process RSS is recorded separately;
task reservations and source/LDE payload estimates are not measured live memory.

The unchanged 16-case CPU/Metal CSP comparison now lives in
`scripts/riscv_csp_paired_benchmark.py`. Its clean snapshot inputs, workers=16,
secure protocol, alternating rounds, fresh verification and per-case identity
checks remain required. A repeated latency or memory regression blocks promotion.

## Actual segmented execution ladder

The same memory fixture and child producer now accept `--segment-count 2|4|8`
with `--segments-output NEW_DIRECTORY`. Full segments retire64 instructions;
complete jobs retire98,227,482 instructions respectively. The last segment
observes the terminal self-loop. This produces individual detached child
candidates; it does not construct the larger recursive tree.

For the everyday execution and admission check, avoid compiling the prover:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  run-recursive-segment-v2-workload -Doptimize=ReleaseSafe --summary all
```

This checks all nine combinations of2/4/8 segments and1/4/16 addresses, including
cross-sibling execution boundaries, canonical wires, mutation rejection and a
complete balanced host fold. Execution adjacency must accept segments1→2 while
binary parent folding still rejects that pair as misaligned. The retained first
ladder failure exposed that distinction in the shared V2 boundary authority.

Independently regenerate expected statements without importing a prover:

```sh
src/integrations/riscv_cpu/zig-out/bin/recursive-segment-v2-workload \
  --export-segment-inputs 4 1 13 NEW_EXPECTED_DIRECTORY
```

Arguments are segment count, distinct addresses, initial memory word and a new
output directory. These are workload-derived inputs; this command grants no
verification-key admission. Review and pin each candidate's explicit development
profile separately, then run `scripts/riscv_segment_v2_detached_gate.py` for each
child with the independent expected file. Existing `--two-segment-output` remains
an alias of the same producer, preserving the maintained two-child lifecycle gate.

The initial CPU ladder took7.73/15.24/30.45s for2/4/8 child production, with168
fresh-process acceptance/mutation cases passing. These individual observations
include native ingress and child wrapper production, exclude parent aggregation,
and use the development q1/native and q3/outer profiles. All eight artifacts of
the two-segment reference are byte-identical after consolidation. The separate
workload executable compiled in7s/614MiB and its full execution gate ran in less
than a second. Evidence is retained under `small-detached-recursion-v1/segment-ladder-*`.

Metal native production of the same ladder took6.95/12.17/24.93s, with168 further
fresh-process cases passing and all child artifacts matching CPU byte for byte.
CPU process RSS was about1.0GiB across sizes. Metal process RSS was0.55–0.58GiB,
while its separately reported peak footprint was1.32–1.35GiB; RSS alone does not
represent its total memory cost. These are initial observations, not repeated
quiet-host performance admission.

The actual first aggregation layer is also available:2 intermediate STARKs for
the four-segment job and4 for the eight-segment job. Each parent takes3.85–3.90s,
about655–656MiB RSS and10–11ms core fresh verification. All150 parent cases pass.
For pairs after the initial pair, explicitly select producer profile
`tiny-memory-continuation-span-v2`, which retains entry clocks on both children.
The maintained parent lifecycle gate accepts `--publication-mode intermediate
--memory-profile continuation`; a Metal-origin four-segment partial parent passed
all25 cases under the independently pinned CPU-origin parent key and matches its
artifact bytes.

## Recursive parents and complete small trees

The shared capture owner now supports both segment proofs and parent proofs.
Transcript ordering still comes from each admitted protocol; shared payload
markers allow the recursive consumer to authenticate dynamic words without
maintaining a parallel transcript description. Parent public inputs retain their
existing split-u16 encoding. The active boundary AIR reconstructs all436 words,
range-checks both limbs and rejects the modulus as an alternative encoding of
zero. Shared span/session/lineage constraints compose these words into the next
parent. Native-only boundary expansion applies only at the first layer.

For two admitted intermediate parents, derive the expected statement from their
independent public inputs, before producing any candidate:

```sh
"$proof_bins/recursive-segment-v2-detached-parent-verify" --fold-root \
  LEFT_EXPECTED_SPAN.json RIGHT_EXPECTED_SPAN.json NEW_EXPECTED_ROOT.json
```

Use `--fold-span` for another intermediate layer. The maintained complete-proof
command above accepts `--child-family parent` and the same independently pinned
child/key/expected arguments. It selects `tiny-parent-root-v2`, or
`tiny-parent-span-v2` with `--publication-mode intermediate`. Both require the
producer to exit before standalone verification and run the same25-case gate.
Keys and expected inputs must be admitted outside the new output directory.

Actual four/eight-segment trees now have three/seven parent STARKs, respectively,
and one standalone root. Final aggregation observations:

| Segments | Preparation | Root request | Root verification | Proof bytes | Peak RSS |
|---|---:|---:|---:|---:|---:|
|4|378ms|3.91s|12.38ms|90,169|656MiB|
|8|384ms|3.92s|9.78ms|85,923|656MiB|

These are development-profile observations. Root request means only the final
aggregation, excluding its already-proved children. The sum of separately
observed CPU leaf and aggregation stages is26.91s for four segments and57.75s
for eight; it is not a single controller wall-time measurement. See
`small-detached-recursion-v1/segment-ladder-root-measurements.json` for stage
counts, preparation/key/proof costs, verifier receipts and memory measurements.

The four-segment seed14 run reuses all seven seed13 verification keys, changes
memory/public statements and passes all48 child and75 parent fresh-process cases.
The focused parent capture gate checks the actual eight-segment root after input
destruction, including436 coherent public-word mutations, the noncanonical zero
case,45 composition mutations and all872 dynamic public transcript limbs. It
runs in one second with36MiB RSS; optimized compilation still takes50s.
The complete eight-segment Metal-origin replay passes175 parent cases under the
same admitted CPU keys; all seven parent artifacts match byte for byte. A shared
statement gate additionally rejects45 coherent mutations directly in the
parent-of-parent AIR, bypassing host admission, including swaps, duplicates,
coverage, clocks and machine state. These gates retain actual proof inputs.

## Measured parent opening optimization

The existing stage recorder is available through
`STWO_RISCV_RECURSIVE_PARENT_PROFILE=1`, with task capture disabled. It covers
fixed preprocessing, main columns, exact closure, interaction generation and
commitments, then the shared engine composition/PCS stages. The ordinary route
allocates no recorder nodes. Profiling on/off preserves exact key/proof bytes
and passes50 fresh cases.

The first profile attributed1.373s to sampled-value evaluation,743ms to exact
lookup closure and389ms to composition. The small parent had explicitly
discarded coefficients already computed for commitments. Retaining them reduced
sampled-value evaluation to16.96ms, about98.8%. Three alternating A/B rounds on
the same eight-segment final root reduced median request time from3.8748s to
2.5528s (34.1%), while peak RSS rose from655.6MiB to703.5MiB. All175 fresh cases
pass and key, claims, proof and expected-word bytes remain identical. This uses
the established PCS retention policy only in the small detached parent; CSP
and native-child defaults are unchanged. Detailed source/binary pins, phase
profiles, process memory and all rounds are in `small-detached-recursion-v1/parent-coefficients-ab.json`
and the adjacent build/patch records.

The remaining dominant measured phase is exact tuple closure, approximately
749ms, followed by composition at394ms. Further work should optimize that actual
finalization boundary without replacing authenticated ownership with a cached
validation flag. The complete tree now works; production-security measurements
and formal CSP promotion are still outstanding.

## Shared compact closure and range-column finalization

The small parent now reuses the existing compact exact tuple ledger. The owner
is consolidated in `recursive_compact_tuple_ledger_v1.zig`; Ethereum consumers
use the same implementation. The ordinary diagnostic ledger used by CSP keeps
its existing behavior. Both ledgers group non-range tuples by the same canonical
SHA-256 digest; compact range entries use exact canonical table indices and
preserve malformed-input and allocation-failure rejection before cancellation.
No protocol, AIR constraint, key identity or worker policy changed.

A focused `test-recursive-compact-tuple-ledger` command now runs all seven existing
parity/provider-phase/allocation-failure checks, using the previously unwired
small test root. Initial compilation took6s/538MiB, execution267ms/4MiB; the later
cached run took23ms. The genuine parent preparation gate retains identical exact
closure of1,437,799 contributions, while its process peak fell511→356MiB.

Three alternating complete-root A/B rounds show median request2.573→2.253s
(12.4%); peak RSS703.5→693.0MiB. Closure itself was406ms, down from749ms. Every
proof/key byte matches the original independently admitted root and all175 fresh
cases pass. The first compact round was slower at2.838s; subsequent rounds were
2.243s and2.253s. These local observations are retained in `parent-ledger-ab.json`
and do not establish quiet-host or CSP performance promotion.

The finalization regression additionally exposed that the old audit read the
range provider's retained counter without comparing its generated main column.
Changing the actual multiplicity still reported closure; the failing run is in
`parent-range-main-regression-first.log`. The fix compares every physical range
multiplicity with the owned counter before allocating the ledger. The fixed
regression and all ledger checks pass in `parent-range-main-regression-fixed.log`.
This is an audit-boundary defect, not evidence of a forged STARK being accepted.
The final producer is checked with both native-child and recursive-parent-child
Metal-origin inputs, using the existing keys and independent verifier.

The first two measured optimizations are now implemented. The next critical
milestones are the separately admitted production-security route and formal CSP
preservation, before further scale or broad optimization.

## Explicit native security ingress

The existing CPU/Metal small-proof driver also accepts
`--memory-addresses 1 --native-ingress-profile protocol_v1`. This selects the
frozen recursion protocol's native PCS parameters (193 queries, fold step 4,
PCS PoW 16); native interaction PoW remains 10. `development_q1` runs the same
boundary under the existing one-query/fold-two/PCS-PoW-zero configuration.
Neither option constructs an outer proof or establishes recursive-root security.
They reject combination with segment output or instruction-only workloads.

Both selections execute the first 64-instruction segment of the existing
98-instruction, one-address memory fixture. The shared ingress serializes the
native proof, destroys its producer allocations, preflights and decodes the wire,
then independently verifies on CPU and constructs owned recursive preparation.
`SEGMENT_V2_NATIVE_PROFILE` separates proving, transport, verification and
preparation; the final status explicitly says `outer_proof_created=false`.
Existing callers and CSP defaults are unchanged.

Initial CPU observations: protocol V1 takes 4.48s overall (2.28s proving,
0.45s verification, 0.99s recursive preparation), versus 2.57s for development
(2.02s, 0.41s, 0.13s respectively). Both peak near 1.0GiB RSS. The stronger
native proof is 1,323,023 bytes and requires 58,865 verifier-core Poseidon calls;
development is 29,002 bytes and 315 calls. These are single local measurements,
not a performance promotion. They identify the input geometry for the next
wrapper; its complete stronger-profile STARK remains a separate required gate.

Evidence is in `small-detached-recursion-v1/native-{secure,development}-ingress-*`
under the reset report. The CPU build took 163s/about 7GiB; five invalid
profile/workload combinations reject before proving. This command narrows the
runtime feedback loop but does not yet narrow the full driver's compilation.

The same stronger native profile passes with authenticated Metal AOT: 3.38s
complete ingress, including 1.07s proving, 0.47s fresh CPU verification and 1.01s
recursive preparation. Process RSS is 531MiB; this does not include a separate
Metal device-footprint measurement. Metal development ingress takes 1.73s.
Both backends produce the same native proof length and verifier geometry; byte
parity of the stronger native proofs is not established by these observations.
`native-security-ingress-measurements.json` collects all four observations with
binary pins and explicit endpoint limitations.

## First complete q193 child wrappers

`--memory-addresses 1 --segments-output NEW_DIRECTORY --initial-memory-word 13
--proof-profile recursive_q193_v1` selects the frozen stronger parameters for
both native input and detached outer proof. The producer rejects weaker native
PCS input before allocating the cohort. The independently pinned key admits the
native query schedule and outer PCS configuration; the shared transcript requires
interaction PoW 10 before drawing lookup relations. Legacy q3 keys and claims keep
their original byte encoding. This q193 route remains experimental until stronger
recursive-parent consumption, final root and preservation admission pass.

Two adjacent CPU-origin child wrappers now freshly verify. Production takes 33.13s
for the pair; outer proving is 9.73/10.19s, after 2.66/2.62s cohort and fixed-key
preparation. Peak process RSS is 2.43GiB. The admitted input columns require exactly
540,806,144 bytes before PCS expansion and commitment buffers. The first wrapper
is 2,487,266 bytes and freshly verifies in 83.6ms. These are local observations.

Both keys are reused byte-for-byte for initial memory 14; both changed proofs
freshly verify against independently retained expected statements. The four
individual child gates pass 56 cases and the initial pair gate passes 18, including
missing/changed interaction nonce and malformed PCS input. The measured producer
has exited before every standalone acceptance gate.

A retained one-second sample catches sampled-value evaluation reconstructing
openings under the leaf's existing coefficient-discard policy. This is the same
class of work already removed from the small parent, but the sample does not
measure its whole-phase share. Prioritize the stronger recursive root before
another optimization round. Full proof artifacts, build/source pins and the
sample live beside `q193-child-cpu-seed13-first-accepted.json` in the report.

The same two stronger wrappers also pass with Metal-produced native inputs:
32.88s production, then 18 fresh-process cases after producer exit. Both keys,
claims, statements and proof bytes match CPU exactly. Initial memory 14 reuses
both CPU-admitted keys. The existing development route additionally passes
34 fresh cases across CPU and Metal, retaining exact baseline artifact bytes.
All measurements and parity hashes are in `q193-child-measurements.json`.

## Independently verified q193 two-child root

The separately admitted `recursive_q193_v1` parent now verifies both real q193
child wrappers inside its AIR and yields one freshly verified root. Interaction
PoW shares its claim encoding and transcript step between leaf and parent; the
prefix carries its temporary draw, work check, frame and nonce through the
existing typed AIR rows. A genuine invalid-work mutation keeps the word/bit
decomposition consistent and is rejected by the direct AIR constraints. The
original prefix failure remains in `q193-parent-prepare-before-pow.log`.

The first parent process takes29.05s, including6.16s preparation,3.69s fixed-key
preparation and18.15s subsequent proving/serialization. Its2,563,834-byte root
verifies in73.3ms, with6.24GiB peak producer RSS. These are single local
observations, not performance promotion. Stage profiling assigns5.09s to exact
lookup closure,3.29s main commitment,2.01s interaction filling,2.08s interaction
commitment and3.54s composition. Sampled-value evaluation is246ms; the previous
coefficient-retention improvement remains active. Preparation and closure are
separate measured phases; do not conflate either with STARK verification.

A different initial memory value (13→14) produces a different accepted proof
under the identical complete parent key. Actual Metal-origin native children
also produce identical parent proof/key/claim/publication bytes, with27.73s
parent production and79.0ms fresh verification. All aggregation remains CPU.
These three strong runs pass81 fresh-process cases. The default q3 replay adds
26 cases and preserves every old artifact byte. A real weak-child invocation
rejects in41ms before output creation and before parent AIR preparation.

The next recursive consumer also passes its genuine capture, shared prefix,
composition and PCS checks after input destruction:436 coherent public-word
mutations, noncanonical zero and45 claim/sample mutations reject. This focused
check runs in3s, with49s compilation. The combined child/command/producer/verifier
build takes221s; its real stronger-child replay runs in16s and the four command
checks in255ms. Four shared transcript checks and the parent capture add five
more passing focused tests. See [q193 parent measurements](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-parent-measurements.json), admission review,
complete-proof gate reports and retained build/source/binary identities.

This completes the first q193 two-child root, not the whole goal. Formal
production-security admission and CSP preservation remain open; no stronger
four/eight-segment root or Ethereum block benchmark is claimed. The next backend
milestone is full Metal proving of leaves, wrappers and every parent level under
the same admitted protocol, with fresh independent CPU verification and actual
per-proof GPU dispatch evidence. Then finish the stronger2/4/8-tree measurements
and optimize the largest remaining measured costs.
