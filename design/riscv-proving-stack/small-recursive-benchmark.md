# Small native and recursive proof loop

The supported optimized route is the four-segment q193 tree described below:
four native proofs, four detached wrappers, two intermediate parents and one
root, with CPU or Metal proving and fresh independent CPU verification. It uses
newly admitted recursive arithmetic and Poseidon AIRs. Earlier 2/4/8-tree results
remain historical evidence; their parent keys require their matching frozen
producers. The standalone leaf route remains valid.

These are tiny RISC-V memory workloads, not Ethereum blocks. q193 names the FRI
query count and remains an experimental security profile. See the
[specialization results](recursive-air-specialization.md),
[current measurement index](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-measurements.json)
and [progress report](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/progress.md)
for gate status and measured timings.

## Current four-segment CPU and Metal tree

The from-source qualification command builds every executable into a new output
directory, pins the reviewed key/statement inputs, and rejects source changes
during the run. It requires Zig 0.15.2. Metal additionally requires a physical
Mac and the full Xcode Metal toolchain; the command builds its own authenticated
`recursive-framework-v1` bundle.

```sh
python3 scripts/riscv_recursive_product.py --backend cpu --output zig-out/recursive-cpu-1
python3 scripts/riscv_recursive_product.py --backend metal --output zig-out/recursive-metal-1
```

Each command exits all producers before fresh verification and runs malformed
proof and same-key, same-geometry statement-substitution controls. `product.json`
records source hashes, build logs, executable pins and the final gate status.
It returns failure on a failed stage; outputs remain available for diagnosis.
The profile remains experimental and the Metal route is explicitly hybrid.
The initial CPU qualification passed 192 cases with all 21 retained artifacts
unchanged; see [the receipt](../../vectors/reports/recursive-product-20260917/cpu-v1/summary.json).

Selected-lane preparation is now active in production. Its complete
[CPU](../../vectors/reports/recursive-product-20260917/cpu-selected-v1/summary.json)
and [hybrid Metal](../../vectors/reports/recursive-product-20260917/metal-selected-v1/summary.json)
qualification runs each passed 192 cases, with all 21 serialized artifacts
identical to the baseline and each other. Production sums were 67.43 and 52.30
seconds respectively; these are single observations, not repeated optimization
medians. The discarded-lane implementation remains an independent test oracle
and cannot be selected in a production build. Six row families still generate
both lanes, and full authority/padded scratch remains.

The real-AOT native-table gate also compares all columns and claims for six
tables, including selector/pole rejection and recovery; see
[its receipt](../../vectors/reports/recursive-product-20260917/interaction-aot-v1.json).
This does not establish producer integration of GPU interactions or strict
end-to-end Metal coverage. Required repository-wide checks remain unresolved.

### Historical frozen-binary reproduction

The session-binary commands below are historical reproduction instructions.

Run the maintained controller from the repository root. The reviewed seed13
manifest is `tree-admissions/air-fusion-q193-4.json`, SHA256
`91a52ebe8c56977c9d589284e2d03bf4bf749b9310272c2a409b14980ce78d6a`.
It retains the existing four leaf keys and independently expected statements,
and selects the new `air-fusion-admission/{pair-0,pair-1,root}-key.json` parent
keys. This complete-tree root key differs from `root-from-legacy-key.json`,
which is only for the paired root benchmark consuming older parent proofs.

The complete-tree root key SHA256 is
`9125f8f140c1c7cacd4d4770adb12463ed7ccf27ec14a0c07900cc667eaeccf9`.
The CPU and Metal seed13 trees each pass 136 fresh acceptance/rejection cases.
Their native-plus-wrapper and parent production sums are 79.768 and 65.835
seconds; complete gates including hostile cases take 83.351 and 69.507 seconds.
These are individual full-tree observations, not paired timing medians. Reports:
[CPU tree](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/complete-tree-q193-cpu-4-seed13-air-fusion/report.json),
[Metal tree](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/complete-tree-q193-metal-4-seed13-air-fusion/report.json).

The commands below use the reviewed local frozen binaries. Their SHA256 pins
are checked before producing output. Each output directory must be new.

```sh
tree_bins="$PWD/.git/local-riscv-proving-stack/small-detached-recursion-v1"
tree_evidence="$PWD/vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1"
python3 scripts/riscv_segment_v2_detached_tree_gate.py \
  --backend cpu \
  --admission "$tree_evidence/tree-admissions/air-fusion-q193-4.json" \
  --admission-sha256 91a52ebe8c56977c9d589284e2d03bf4bf749b9310272c2a409b14980ce78d6a \
  --leaf-producer "$tree_bins/air-fusion-final-leaf-prove" \
  --leaf-producer-sha256 4657c1219b634dfb659d63e1059c94a959963dad52e6e1eb7a5055425c32cce2 \
  --parent-producer "$tree_bins/air-fusion-final-cpu-prove" \
  --parent-producer-sha256 54934a68624af972f81645726eb68d2328255ee129ed5f5c09a7c5638d542dbc \
  --leaf-verifier "$tree_bins/q193-child-first-verify" \
  --leaf-verifier-sha256 0720755fb784af9bd18f003453440c4c8d4a4d87fe02ff115ba0c373709079a9 \
  --parent-verifier "$tree_bins/air-fusion-final-cpu-verify" \
  --parent-verifier-sha256 9e0b05c7709133f75419a581c15ebcef3a49334c3c2a08f0b44f3a0c754b1223 \
  --output "$PWD/.git/local-riscv-proving-stack/air-fusion-tree-cpu-4"
```

The same leaf producer supports both backends. Metal changes the parent producer
and supplies the admitted AOT bundle; every native, wrapper and parent proof
selects Metal, while fresh verification stays on CPU:

```sh
python3 scripts/riscv_segment_v2_detached_tree_gate.py \
  --backend metal \
  --admission "$tree_evidence/tree-admissions/air-fusion-q193-4.json" \
  --admission-sha256 91a52ebe8c56977c9d589284e2d03bf4bf749b9310272c2a409b14980ce78d6a \
  --leaf-producer "$tree_bins/air-fusion-final-leaf-prove" \
  --leaf-producer-sha256 4657c1219b634dfb659d63e1059c94a959963dad52e6e1eb7a5055425c32cce2 \
  --parent-producer "$tree_bins/air-fusion-final-metal-prove" \
  --parent-producer-sha256 cbb776e999a266a6d6c1310627cf59f46a9343478c8381adbb980cb8fb84958f \
  --leaf-verifier "$tree_bins/q193-child-first-verify" \
  --leaf-verifier-sha256 0720755fb784af9bd18f003453440c4c8d4a4d87fe02ff115ba0c373709079a9 \
  --parent-verifier "$tree_bins/air-fusion-final-cpu-verify" \
  --parent-verifier-sha256 9e0b05c7709133f75419a581c15ebcef3a49334c3c2a08f0b44f3a0c754b1223 \
  --aot-bundle "$PWD/.git/local-ethereum/aot-m4" \
  --aot-manifest-sha256 21332158b1e1202b9c4171b057d4fb3fbd43d96c22d50012267f55e45e2193e5 \
  --output "$PWD/.git/local-riscv-proving-stack/air-fusion-tree-metal-4"
```

For changed-memory admission with the same seven keys, replace the manifest with
`tree-admissions/air-fusion-q193-4-seed14.json` and pin
`c7b278867cee07a660be4e2ec16f71db78f1bb7dd51ed74cf26e2c683dea4b07`,
then choose another new output directory. The retained CPU seed14 tree passes
all 136 cases under the same seven keys, with all seven proof bytes changed.
The controller derives the seed from the admitted manifest; no producer-created
key or expected statement is trusted.
Each run retains `report.json`, per-node lifecycle receipts, fresh acceptance and
mutation cases, timings and memory. Metal dispatch is required at each proving
stage, but recursive composition still uses its admitted host evaluator.

Build provenance for the frozen binaries is retained in the
[CPU parent receipt](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-integration-cpu-final.json),
[Metal parent receipt](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-integration-metal-final.json),
[shared leaf receipt](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-final-leaf-build.json)
and [source pins](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-final-source.json).
The leaf verifier keeps its preceding independently reviewed binary pin.
Frozen executables and AOT directories are local artifacts, not portable source
dependencies. On another laptop, rebuild the maintained targets:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  build-recursive-segment-v2-detached-parent-producer \
  build-recursive-segment-v2-detached-parent-verifier \
  build-recursive-segment-v2-detached-verifier -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal \
  build-recursive-segment-v2-concrete-outer-proof \
  build-recursive-segment-v2-detached-parent-producer -Doptimize=ReleaseSafe --summary all
```

Use those build receipts to review the installed executable paths and replacement
binary pins before invoking the same controller. Keep the admitted key/statement
manifest unchanged for equivalent source and protocol. Generate and pin the
Metal AOT bundle with the maintained commands below. A hash of an unrelated
executable is not a substitute for its build provenance.

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
use that directory's installed producer with `--native-backend metal` and
`--recursive-backend metal`, and add
`--aot-bundle PATH --aot-manifest-sha256 SHA256`. Keep the CPU verifier and the
same independent pins and expected statements. The gate checks real Metal
dispatch for both children. AOT generation is described below.

Omit `--producer` to replay existing artifacts without taking the heavy-job
lock. This keeps the small verification loop usable during a separate build.
The retained complete commands passed all 17 cases in 8.076 seconds on CPU and
6.282 seconds with Metal native proving. These are development observations,
excluding compilation, and do not establish a production-security benchmark.

## Historical parent command: legacy AIR admission

The commands and parent key below describe the pre-specialization producer.
Use its matching frozen producer to reproduce them; a newly built parent
producer uses the specialized AIR and rejects this old admission. The current
four-segment commands above select the new parent keys. Existing legacy proofs
remain independently verifiable, and the leaf command above is unchanged.

Build `build-recursive-segment-v2-detached-parent-producer` and
`build-recursive-segment-v2-detached-parent-verifier` under the CPU integration
with the serial build command above. Both CPU- and Metal-produced child bundles
can use the shared CPU parent route or the Metal parent producer described below.

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
is consolidated in `frontends/riscv/recursion/compact_tuple_ledger_v1.zig`; Ethereum consumers
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

## Historical q193 two-child root

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

## Historical first Metal parent proving

The parent proof transaction now takes an engine at its backend boundary. CPU
remains the default; the Metal runner uses the same AIR, transcript, parameters,
key admission and serialization. Its authenticated core AOT runtime must dispatch
Metal work and Poseidon commitments, release all call leases and shut down before
reporting success. The independent CPU verifier and admitted CPU keys are reused.

Both q3 and q193 parent proofs pass their fresh-process gates (26+27 cases), with
all four artifact files byte-identical to their CPU baselines. The q193 parent
process takes23.36s, versus the earlier29.05s CPU observation, and verifies in
77.7ms. Its RSS is5.61GiB, separate from device footprint. Telemetry records95
Metal dispatches and10 Poseidon commitments. No CPU fallback counter is recorded;
this does not mean scheduled host work disappears. Combined fixed/main/interaction
commitment phases fall from9.06s to3.66s. Exact closure remains5.02s and composition
3.69s. These are single observations, not a controlled performance promotion.

The default CPU producer is rebuilt through the same generic transaction, freshly
verified and byte-identical to its old output; four command checks pass. Metal
compilation is100s; the CPU producer plus command checks take98s. Evidence is
indexed in `metal-parent-measurements.json` and the adjacent complete-proof reports.
The maintained Metal target is `build-recursive-segment-v2-detached-parent-producer`
in `src/integrations/riscv_metal`. The shared complete-proof gate accepts explicit
`--metal-aot-bundle` and `--metal-aot-manifest-sha256` with its normal producer/key/
expected-statement pins, and checks dispatch/shutdown evidence before verification.

The complete controller below supersedes this initial parent-only checkpoint:
native children, detached wrappers and every parent now select Metal together.
Production-security admission and formal CSP preservation remain open.

## Tree controller and historical development admissions

For current producer binaries, use the four-segment specialized admission and
exact commands at the top of this document. The earlier development manifests
and binary receipts described in this section remain historical reproductions.

`scripts/riscv_segment_v2_detached_tree_gate.py` is the maintained serial command
for the small 2/4/8 fixtures. `--admission` and `--admission-sha256` select a pinned
manifest in `tree-admissions/`; it contains every key and independently expected
statement. Supply explicit paths and SHA256 pins for `--leaf-producer`,
`--parent-producer`, `--leaf-verifier` and `--parent-verifier`, plus a new `--output`
and `--backend cpu|metal`. Metal also requires the admitted AOT bundle and pin.
The executable command lines are retained in
`complete-tree-development-ladder-first.json`. No key is admitted from a newly
produced proof. Wrong admission or binary pins reject before creating output.

Each producer exits before independent verification. The controller reuses the
existing child/parent gates, including their hostile cases; all protocol meaning
remains in the shared Zig implementation. Metal runtime telemetry must show GPU
and Poseidon commitment dispatch for every native child, wrapper and parent.
Host preparation and planned host composition remain: this is end-to-end Metal
backend selection, not a claim that all operations run on the GPU.

The first complete development ladder passes on both backends with identical
key, claims, proof and publication bytes across CPU/Metal. Complete gate times
(including hostile cases) for 2/4/8 segments are 10.592/23.693/49.762s on CPU and
7.823/17.806/38.055s on Metal. Leaf production is 7.696/15.375/30.833s versus
5.189/10.301/20.774s; parent production sums are 2.297/6.918/15.987s versus
2.030/6.105/14.258s. Peak process RSS stays below 1.03GiB CPU and 0.72GiB Metal;
these measurements do not separately account for GPU allocation.

The separate `q193-two-full-metal-first.json` records a complete stronger
98-instruction tree: both native proofs, both wrappers and the root use Metal,
then independent CPU verification passes all 45 acceptance/rejection cases.
It takes 44.54s including those cases, with 6.59GiB peak process RSS. Artifact
bytes match the CPU route. The later stronger 4/8 runs are recorded below;
production-security admission and formal CSP promotion remain open.

## Wrapper coefficient retention comparison

`wrapper-retention-measurements.json` indexes three alternating unprofiled A/B
rounds for both profiles and backends, plus separate diagnostic phase runs.
`wrapper-retention-ab/report.json` retains all commands, binary pins, timings,
RSS, byte hashes and 560 fresh acceptance/rejection cases. Both binaries include
the same opt-in profiler; the experimental difference is coefficient retention.
Every proof, key, claim and expected statement matches its pre-change reference.

| Profile | CPU wrapper median, before → after | CPU two-child producer, before → after |
| --- | ---: | ---: |
| Development | 0.978 → 0.619s (36.7% lower) | 7.834 → 7.170s |
| q193 | 9.999 → 6.396s (36.0% lower) | 32.554 → 25.364s |

CPU opening evaluation changes from barycentric evaluation over the committed
columns to direct evaluation of already-computed coefficients. Its diagnostic
phase falls from 374–375ms to 5.1–5.2ms in development, and 3.67–3.70s to
52.6–52.9ms in q193. PCS releases the coefficients after evaluation; this is not
a cross-request cache. Stronger CPU process RSS rises from 2.426 to 2.696GiB.

Metal's existing GPU evaluation takes only 28–31ms for stronger openings. Keeping
coefficients does not improve it: wrapper median rises 5.126 to 5.248s and RSS
rises 2.366 to 2.967GiB. That candidate is rejected for Metal. Development Metal
request variation occurs primarily outside the modified wrapper and is not
claimed as a retention speedup. The final shared transaction selects retention
for CPU and preserves Metal's existing policy; admission and transcript remain
identical. These local observations do not replace formal CSP preservation.

Set `STWO_RISCV_RECURSIVE_WRAPPER_PROFILE=1` for the existing complete-proof
commands to record cohort construction, fixed/main/interaction phases, closure,
component assembly, composition, openings, FRI and serialization. Leave it unset
for timing comparisons. The complete native-plus-wrapper producer also records
native ingress, outer preparation and producer destruction independently.

The final backend policy passes all eight complete-tree runs: CPU/Metal 2/4/8
in development and CPU/Metal 2 in q193. Their 1,014 fresh acceptance/rejection
cases pass, as do all artifact parity and immutable-input checks. Exact commands
and the final source/binary pins are in `wrapper-retention-final-trees.json`;
`wrapper-retention-final-tree-measurements.json` collects endpoint measurements.
Final development complete gates take 9.805/21.916/46.895s on CPU and
7.770/18.727/38.060s on Metal. These single reruns include hostile cases and are
correctness/scaling observations, not additional paired performance claims.
The q193 final trees take 55.709s CPU and 43.594s Metal, including fresh cases.

`wrapper-retention-final-phases.json` attributes the remaining stronger wrapper:
cohort construction about 1.9s, interaction generation 2.6–2.8s, and composition
about 1.1s. A one-second sample during the first Metal wrapper locates interaction
work in `NativeSegmentCoreV2.prepareInteractions`, then `fillInteractionImpl`
and `auditPreparedDomainSums`: row-pair evaluation and batch inversion are
repeated for domain audits after interaction-column generation. Sampling overlaps
the diagnostic Metal run, which is excluded from the alternating comparison.

The next bounded optimization candidate is this repeated interaction arithmetic
on both backends. Preserve the audit's per-domain values, total, logical-row and
event counts, zero-denominator rejection, and independent cold diagnostic.
Compare a shared generation/audit implementation against the existing audit on
real prepared rows, then require the same complete-proof and artifact-parity
gates. Do not substitute a cached validation flag or remove boundary checks.

## Shared interaction generation and domain claims

The wrapper now uses `Framework.generatePreparedIntoWithDomainSums` for all
16 native-core components. That existing typed-AIR operation writes directly to
the admitted Tree2 columns and derives domain claims from its retained inverse
plane. It replaces 16 allocating generate/copy/cold-audit sequences with one
internal helper. The separate cold audit stays available; exact tuple-ledger
contributions and domain/row/event counts are preserved. No frontend production
algorithm, protocol parameter, CSP default or worker policy changes.

The diagnostic `STWO_RISCV_RECURSIVE_INTERACTION_AUDIT=1` compares every domain
value, total, logical-row count and event count against independently recomputed
cold results on genuine prepared rows. CPU/Metal and both profiles pass 128 such
component comparisons and 70 fresh proof cases, with identical artifact bytes.
The stronger fixture's two wrappers cover 1,815,246/1,760,907 logical rows and
10,200,101/9,896,712 event terms in these components. These are recursive verifier
relations, not counts of executed RISC-V instructions.

The focused workspace check is now directly runnable:

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv \
  test-recursion-framework-interaction -Doptimize=ReleaseSafe --summary all
```

It checks column/domain parity, no additional workspace allocation, alias
rejection and unchanged destination bytes on zero-denominator failure. Three
checks pass in 272ms after a six-second compile. This previously inventoried
focused root now has its own maintained build step and test-count floor.

Three alternating, unprofiled A/B rounds pass another 560 fresh cases. Stronger
CPU wrapper median improves 6.393→5.666s (11.4%), and the complete two-child
producer improves 25.422→23.896s (6.0%). Metal wrapper median improves
5.156→4.348s (15.7%), and its producer improves 20.348→18.671s (8.2%). Peak RSS
is stable at about 2.70GiB CPU and 2.37GiB Metal. Separate diagnostic runs locate
the saving in interaction generation: approximately 2.6–2.7→1.9s per wrapper.

Development wrapper medians improve by 3–4%, but the complete CPU request is
7.117→7.138s, within local variation; no whole-request development CPU speedup is
claimed. These are local measurements, not formal quiet-host CSP promotion.
Evidence: `wrapper-interaction-direct-measurements.json`,
`wrapper-interaction-ab/`, `wrapper-interaction-direct-cold/`, and
`wrapper-interaction-framework-checks-first.{json,log}`. Producer compilation
is 181s; source/binary pins are retained with its build report. Later frontend
changes are test-only plus the focused build-step wiring.

All eight complete trees also pass 1,014 fresh cases after this change:
CPU/Metal development 2/4/8 and stronger 2-segment trees. Every key, claim, proof,
expected statement and parent publication matches the preceding checkpoint.
`wrapper-interaction-direct-trees.json` contains the commands and binary pin;
`wrapper-interaction-direct-tree-measurements.json` records endpoint timing,
root verification and memory. These reruns establish complete-route correctness
and scaling observations, not additional paired timing claims. The subsequent
stronger 4/8 route is recorded below; formal CSP preservation remains open.

## Historical stronger ladder

These 2/4/8 results and admissions predate AIR specialization. Reproducing them
requires their matching frozen parent producers; the current parent producer
must use newly reviewed admissions such as `air-fusion-q193-4.json` above.

The same tree controller completes the experimental q193 profile at 2/4/8
segments on both backends. Each N-segment run generates N native proofs, N
detached wrapper proofs and N-1 aggregation proofs. Workloads contain only
98/227/482 retired RISC-V instructions, respectively, with one memory address.

| Segments | Backend | Native + wrappers (s) | Aggregation (s) | Sum (s) | Root STARK verification (ms) | Peak RSS (GiB) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 2 | CPU | 24.00 | 28.74 | 52.74 | 78.38 | 6.41 |
| 2 | Metal | 18.45 | 22.38 | 40.82 | 79.77 | 5.93 |
| 4 | CPU | 43.88 | 83.76 | 127.64 | 72.29 | 6.66 |
| 4 | Metal | 36.73 | 66.21 | 102.94 | 80.97 | 7.06 |
| 8 | CPU | 89.70 | 189.95 | 279.65 | 76.95 | 6.66 |
| 8 | Metal | 73.65 | 154.58 | 228.24 | 80.38 | 7.13 |

These are single observations from serial producer processes, excluding lock
waiting and hostile verification cases. Complete-gate wall time includes both
and must not be substituted for the production sum. RSS is process memory, not
a separate device allocation measurement. The four/eight-segment final proofs
remain approximately 2.43MB. This ladder demonstrates bounded scaling at these
small geometries, not Ethereum-block performance or production security.

Historical tree commands used these manifest pins:

- `tree-admissions/q193-4.json`:
  `ea8ba2941e859af36d516c62adc1c33b38835874688973015cade10dea201fad`.
- `tree-admissions/q193-8.json`:
  `6d7bbd731204e18f786543ab69bd43647369e9ec929d699db1cc59a5be302e36`.

Every full-tree report retains the executable command, independent input pins,
producer exit evidence, per-node fresh proof gates and backend lifecycle checks.
All 28 four-tree and 60 eight-tree artifact files match between CPU and Metal.
Changing the initial memory word from 13 to 14 reuses all seven four-tree and
all fifteen eight-tree keys unchanged; every proof and expected statement
changes and freshly verifies. Independent execution supplies the expected
statements before the new proofs are produced. See the
[four-tree reuse evidence](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-four-tree-measurements.json)
and [eight-tree summary](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-ladder-8-summary.json).
The [ladder measurements](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-complete-ladder-measurements.json)
link the six exact reports and distinguish native, wrapper and parent counts.

## Historical stronger parent-of-parent cost attribution

The four-segment q193 root now consumes two genuine intermediate parent proofs.
Separate diagnostic runs reproduce identical CPU/Metal artifacts and pass all
27 fresh verifier cases on each backend. They use the existing
`STWO_RISCV_RECURSIVE_PARENT_PROFILE=1` recorder; they are single observations,
not a paired performance claim.

| Root operation | CPU seconds | Metal seconds |
| --- | ---: | ---: |
| Recursive preparation | 5.908 | 5.944 |
| Fixed columns and admission | 3.577 | 1.218 |
| Exact lookup closure | 5.233 | 4.884 |
| Main commitment | 2.950 | 1.336 |
| Interaction filling | 1.940 | 1.939 |
| Interaction commitment | 1.789 | 0.637 |
| Composition evaluation | 3.362 | 3.433 |
| Sampled openings | 0.154 | 0.242 |
| Complete producer request | 27.665 | 21.835 |

These rows expose the material phases rather than partition every remaining
millisecond; see the full recorder for the smaller phases. Metal accelerates
commitments, while preparation, exact closure and composition remain substantial
host work. Selecting the Metal backend at every tree node does not mean every
operation runs on the GPU. The removed CPU opening cost is no longer dominant.

The next measured optimization target is repeated preparation/closure work in
the shared parent route. Preserve exact lookup semantics, independent key
admission and complete-proof parity. Do not widen the instruction frontend or
change security parameters to reduce these timings.

Evidence: [root stage profiles](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-four-root-stage-profiles.json),
[consuming-AIR check](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-four-intermediate-capture.json),
and [genuine weak-child rejections](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-genuine-weak-child-rejections.json).

The next-level intermediate also passes the same focused check in three seconds
(708 MiB test RSS; cached compilation took 63ms). From the repository root:

```sh
proof_fixture="$PWD/vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1"
STWO_DETACHED_PARENT_BUNDLE="$proof_fixture/q193-ladder-8-level2-0-cpu-bootstrap" \
STWO_DETACHED_PARENT_KEY_SHA256=128e6b2ce19528caa737b56ab9d16168cf298f38d217dfff712a8b230cf2c2ad \
STWO_DETACHED_PARENT_EXPECTED_ROOT="$proof_fixture/q193-ladder-8-admission/level2-0-expected-span.json" \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-recursive-segment-v2-detached-parent-capture -Doptimize=ReleaseSafe --summary all
```

This checks a genuine parent-of-parent proof, destruction of the original inputs,
all 436 public-word mutations, 872 transcript limbs and 45 claim/sample controls.
It does not generate the next consumer proof; use the full tree command for that
gate. Shared-lock waiting is reported separately in the retained log and is not
included in the three-second test runtime.

## Shared parent execution checks

Run these focused checks before rebuilding a complete parent producer:

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv \
  test-recursion-direct-execution test-recursion-structural-hashes \
  test-recursion-quotient-domains -Doptimize=ReleaseSafe --summary all
```

They compare canonical SHA bytes, every active parent AIR's direct roots over
base and extension fields, packed relation challenges, and serial/parallel
quotient columns. The parallel check includes additive accumulation, cancellation
and a genuine row-evaluation failure with all helpers joined. The complete proof
still supplies the key, transcript and serialization acceptance gate.

Parent main finalization now owns one source projection for both range counting
and exact lookup closure. It publishes the range batch only after actual provider
columns and public words close. The retained preparation test compares this with
cold generation and audit, rejects destination aliases and changed statements,
checks zeroed failed outputs, and retries successfully.

GPU evaluation of this recursive catalog remains separate work. See
[the measured Metal composition boundary](recursive-metal-composition.md) for
why the current request uses host composition and which authenticated layout
extensions are needed. Metal commitment dispatches alone do not establish GPU
composition.

CSP benchmarks are excluded from this parent optimization pass at the user's
request. No CSP performance-preservation result is claimed for this pass.

## Historical parent execution optimization before AIR specialization

Three alternating unprofiled A/B rounds use the same retained q193 four-segment
root inputs, admitted key, transcript and proof parameters on each backend.

| Complete parent request | Before median | After median | Reduction |
| --- | ---: | ---: | ---: |
| CPU | 26.252s | 21.364s | 18.6% |
| Metal | 20.805s | 15.046s | 27.7% |

Separate diagnostic observations attribute the change: CPU composition falls
3.362 to 1.423s, Metal 3.433 to 1.534s. Preparation, main generation, exact closure
and composition together fall 14.970 to 8.723s CPU and 14.711 to 8.926s Metal.
These phase observations are not paired medians. Main finalization now includes
range work formerly counted during preparation; the combined group avoids
claiming moved work as a saving.

Canonical SHA serialization is buffered without changing bytes. FRI parameter
projection no longer rematerializes a complete tree. One exact tuple projection
supplies both range counts and closure, with full provider/public-word checks
before publication. The ledger uses one probe to remove closed tuples. Direct
execution skips unreachable pure nodes while recursive graph recording retains
the complete canonical program; relation challenges reuse packed field dot
products. Large quotient domains share the existing bounded row scheduler.
Disjoint writes, fresh/additive accumulation and worker joining have focused
checks. No new AIR equations or backend-specific protocol description were added.

CPU median process RSS is 6.661 to 6.662GiB; Metal is 7.099 to 7.144GiB (maximum
7.132 to 7.144GiB). This is process RSS, not separate device allocation accounting.
The composition sample identifies large linear and multiplication components as
stragglers while other workers wait; sharding removes that scheduling bottleneck.
Preparation and exact tuple processing remain material measured host costs.

All 975 final fresh acceptance/rejection cases pass. Both four-segment development
trees and both q193 trees use newly built leaf and parent producers, then fresh
standalone verifiers. All 28 artifact files match across backends in each profile.
Changing initial memory from 13 to 14 reuses all seven q193 keys; every changed
proof and statement freshly verifies. Stronger four-tree production sums are
103.949s CPU / 82.435s Metal versus the previous 127.641s / 102.940s observations.
These whole-tree sums are individual runs, not additional paired benchmarks.

The focused quotient suite passes ten tests in about one second after an
11-second compile. The separate direct/hash suites pass fourteen tests; the
retained-parent preparation and compact-ledger checks pass nine. Heavy rebuilds
remain separate: final CPU parent 87s, Metal parent about 94s excluding its lock
wait, and the shared leaf driver about 169s excluding its lock wait.

Evidence: [measurement index](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/parent-hotpath-measurements.json),
[artifact audit](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/parent-hotpath-final-artifact-audit.json),
and [final source pins](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/parent-hotpath-final-source.json).
The index contains exact build/binary references, A/B commands, five full-tree
commands and retained proof artifacts. The audit rechecks 180 distinct pins.
CSP benchmarks were excluded at the user's request. Formal q193 production
security admission and GPU composition admission remain open.

### Canonical compact-Poseidon identity migration

New parent keys bind the canonical production equation digest, separately from
source provenance. Retained compact keys admit only the reviewed historical
identity. Both native admission and recursive composition use the same geometry
compatibility check. Preparation uses canonical identity by default; an
independently pinned retained key can select the reviewed legacy identity while
requiring the entire witness-derived manifest seal to match.

Derive a new four-segment admission with
`scripts/riscv_recursive_identity_migration.py`. Supply the historical admission
and its hash, matching parent producer/verifier paths and hashes, the verified
four-leaf bundle directory, and a new output directory. The tool migrates the
two intermediate keys, qualifies their proofs against those independent pins,
and invokes the producer's separate `derive-key` setup command for the root.
Setup verifies both children and commits fixed columns using the same owner as
production, then exits with a key and no root proof. Changed child identities
change constants in root preprocessing, so copying the old root commitment is
invalid even when all column geometry is unchanged.

The receipt records the final admission digest. Pass that exact digest and the
output `admission.json` to the complete-proof command using `--admission` and
`--admission-sha256`, with either backend. All expected public input artifacts,
PCS parameters and geometry remain unchanged. Intermediate preprocessing is
preserved; root preprocessing is derived again from the newly admitted child
keys. Qualification of the complete root remains a separate gate. The default
complete-proof command retains the historical admission as a compatibility
regression.

Focused iteration on this boundary:

```sh
python3 scripts/zig_protocol_test.py src/frontends/riscv/poseidon2_protocol_identity_test_root.zig -O ReleaseSafe --test-filter canonical
```
