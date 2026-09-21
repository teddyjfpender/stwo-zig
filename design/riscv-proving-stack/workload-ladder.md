# Existing RISC-V complete-proof workload ladder

Read-only inventory at checkpoint `87a3965f`, 2026-09-08. No build or proof was run for this inventory. Commands below run from the repository root. Use the existing serialized build wrapper; do not overlap them with the retained Ethereum diagnostic.

The smallest focused **full RISC-V test root** to run next is `segment_v2_native_proof_test.zig`. The smallest existing **production artifact lifecycle** is the CLI smoke's 144-step `branch_fib`: the prover process exits before a new verifier process reads the artifact. Use both existing boundaries; a new framework is unnecessary.

## Ordered ladder

| Order | Existing workload and acceptance | What it establishes | Remaining boundary |
|---|---|---|---|
| 1 | `test-riscv-segment-v2-native-proof`, guarded 2 tests | Tiny real nonfinal/final segment proofs, shared program commitment and continuation; rebased leaf-local V3 without widening RV32 AIR | Fresh verifier channels/captures, but original producer/session and original positive proof remain live. Not a serialized, producer-destroyed lifecycle. |
| 2 | CLI `branch_fib`, 144 steps, then `memcpy_loop`, 2,126 steps | Complete production RV proof, branch control flow, mutable load/store memory; durable artifact followed by a separate verifier process with bound statement/transcript/implementation identity | Functional protocol, not the admitted Ethereum recursive profile. No cross-segment continuation from these two programs. |
| 3 | `test-riscv-lookup-v2-native-proof`, guarded 1 test | Real `buildAllFamilies()` RV32IM execution with LW **and SW**, arithmetic, branches, multiply/divide and jumps. Full proofs under compatibility and authenticated lookup layouts; cross-layout rejection | Positive verification uses original proofs while producer state remains live. Cross-layout negative cases currently accept any returned error; infrastructure failure is not a useful cryptographic rejection receipt. |
| 4 | `test-main-witness-poseidon2-combined-receipt`, guarded 1 test; `test-ethereum-zero-family-proof`; `test-ethereum-precompile-proof` | Full VM guest Poseidon call; canonical empty Ethereum extension geometry; then actual Keccak and signer-recovery calls | Tests freshly verify but retain producer state. Poseidon receipt test explicitly uses two workers: label this instead of comparing it with worker1. |
| 5 | `test-ethereum-segment-v2-zero-proof`, then `test-ethereum-segment-v2-signer-proof` | Real nonfinal continuation with empty and active Ethereum extension families; count-sensitive provider geometry | Native segment proofs, not one recursive block root. Positive artifact/capture roundtrips elsewhere in this test file still retain session/producer ownership. |
| 6 | Remaining CLI smoke `multi_shard_addi`, 131,078 steps; `sha2_input_128B`, 14,034 steps | Cross-shard state/LogUp placement; wider ordinary crypto execution and higher polynomial logs; full separate-process lifecycle | SHA2 guest execution is not the Keccak/ECDSA precompile route. Cross-shard execution is not an independently verified Ethereum continuation bundle. |
| 7 | Existing retained native Ethereum segment19 diagnostic in `native-replay.md` | Real declared program, large mutable-memory snapshot, continuation, fixed-program/provider commitments, Metal proving and fresh CPU verification | This is the measured large-route check. Recursive wrapper/parent and whole-block acceptance remain separate milestones. |

All tiny test-root configurations inspected use development PCS parameters (one or three queries and no PoW). They are full proofs of their selected workloads, not evidence of the security or shape of the real Ethereum profile. Preserve production/CSP defaults and protocol identities.

## Exact commands

First separate semantic compilation from execution so compile wall time is not called proving time:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  check-riscv-segment-v2-native-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-riscv-segment-v2-native-proof -Doptimize=ReleaseSafe --summary all
```

Existing guarded deeper roots, only when the preceding rung or changed code requires them:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-riscv-lookup-v2-native-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-main-witness-poseidon2-combined-receipt -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-zero-family-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-precompile-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-segment-v2-zero-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-segment-v2-signer-proof -Doptimize=ReleaseSafe --summary all
```

For changes to composition evaluation, the existing all-family parity root is particularly relevant: it compares generated/reference full proof bytes and terminal transcript, rather than only checking an arithmetic result.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-riscv-generated-composition-native-proof -Doptimize=ReleaseSafe --summary all
```

Production artifact lifecycle, using the documented focused product (one build, then reusable binary). The smoke runner creates its artifact directory exclusively, so choose a new run directory each time. Its clean-tree policy is intentional: finish the reset source checkpoint before executing; do not hide source changes with `--allow-dirty`.

```sh
python3 scripts/zig_serial_build.py \
  test-riscv-cpu-product stwo-zig-riscv-cpu -Doptimize=ReleaseFast --summary all
python3 - <<'PY'
import subprocess
from scripts.zig_serial_build import build_lock
with build_lock(label='riscv-reset-small-artifact-lifecycle'):
    subprocess.run([
        'python3', 'scripts/riscv_pr_proof_smoke.py',
        '--cli', 'zig-out/bin/stwo-zig-riscv-cpu',
        '--artifact-dir', 'zig-out/riscv-reset-small-v1',
        '--report-out', 'zig-out/riscv-reset-small-v1.json',
        '--workload', 'branch_fib', '--workload', 'memcpy_loop',
    ], check=True)
PY
```

For the full existing mandatory PR smoke, use a fresh artifact/report path and omit the two `--workload` selections, then run `python3 scripts/riscv_trace_vectors.py`. The two-workload developer subset does not replace that four-workload promotion gate. The script imposes a 120-second limit per prove/verify subprocess; a timeout is a failure, not a benchmark.

## Compile boundaries already present

`build_proof_steps.zig` gives native continuation, lookup and generated-composition distinct test roots with exact filters and `ProofTestGuard`; the run steps have side effects so an old success cannot replace a new test receipt. These roots consume core, prover API/engine, CPU backend, frontend, integration and postcard. Lookup alone adds its small layout-selection backend. They do not require instantiating the giant Ethereum genuine-wrapper test route.

`src/integrations/riscv_cpu/build.zig` already declares those package boundaries; integration still imports a broad facade. Measure which reachable generic instantiations dominate a selected compile before moving files. Use `check-*` and `test-*` for the same root to distinguish compilation, warm execution and external-input work. Do not run the integration's umbrella `test` to answer a two-test question. The focused CLI is CPU-only; Metal uses its existing separate product/integration boundary.

The small `test-ethereum-small-composition-proof` is useful for PCS serialization/destruction/fresh verification, but is a mixed-degree AIR proof, not a RISC-V program. Likewise `test-riscv-stack-swap-proof` explicitly needs external base tables and is not production eligible. Keccak/secp256k1 shard harnesses are useful component gates, not complete RV proofs. `memory_provider_shard_proof_test.zig` contains genuine full-core-plus-ordered-provider closure, but no existing build consumer was found in this inventory; do not advertise an invented command. Its full-core fixture is ADDI-only, so it would not replace the real LW/SW workload anyway.

## Measurements and the large-input boundary

Small native/lookup/precompile/CLI wall times at checkpoint `87a3965f` are **unmeasured here**. Tests print prove/verify timing, and CLI smoke retains separate subprocess durations. The PR contract's warm-runner goal of under one minute is a target, not a result from this laptop.

Existing measured evidence provides scale, not a new reset speedup:

| Existing receipt | Measured result | Scope |
|---|---|---|
| Reset `../../vectors/reports/riscv-proving-stack-reset-20260908/baseline.json`, retained native segment19 | 544.138 s complete request; 351.930 s proving; 259.336 s composition; 31,859,924,488 B peak footprint | Historical Metal native route, not a current-head rerun; nested phases must not be summed |
| `.git/local-ethereum/devex-preparation-gates-v20/root-production-compile-execution.json` | 134.088 s, exit0 | Large root-production compile only, zero test execution |
| `.git/local-ethereum/devex-real-cohort-replay-v8/execution.json` | 1204.295 s request including compile, exit0 | Real native-input cohort reconstruction/Tree2/cold closure, **no PCS or root proving** |
| `.git/local-ethereum/real-wrapper-segment2-devex-v4/acceptance-v1.json` | 110.779 ms verification; 198.666 ms verifier request; 0.517 s process; 3,028,338 B proof | Accepted detached ordinary wrapper2, ten independent positive/hostile cases; not a whole-block root |

The retained Ethereum campaign has 121 segments with a 2,097,152-cycle leaf budget, a large declared ELF and large sparse mutable-memory entry snapshots. It combines repeated program/memory hashing, active precompiles, noninitial global clocks and continuation, count-sensitive provider shards, and a recursive verifier with 193 queries. The ordinary wrapper has 36 components and 444,865 queried values; tiny one-query proofs cannot reproduce that transcript/Poseidon or allocation volume merely by adding a few instructions.

Use the ladder to localize functional and ownership failures, then the existing segment19 input to measure composition/host preparation under the real shape. Retain the real shape and failing inputs; do not manufacture a new miniature Ethereum geometry or reinterpret a tiny development proof as block acceptance. Promotion still needs the unchanged 16-case CSP CPU/Metal A/B checks and the actual whole-block/recursive milestones.

Source anchors: `conformance/riscv-pr-proof-gate.md`; `scripts/riscv_pr_proof_smoke.py`; `src/frontends/riscv/runner/guest_precompile/test_elf.zig`; `src/integrations/riscv_cpu/{build_proof_steps,build_ethereum_leaf_steps,segment_v2_native_proof_test,lookup_v2_native_proof_test,generated_composition_native_proof_test,guest_precompile_proof_test,ethereum_precompile_proof_test}.zig`.

## First executed small lifecycle — 2026-09-08

Clean source71206f8b, existing CPU CLI ReleaseFast. Product build91.59s;
`branch_fib` plus `memcpy_loop` smoke passed with separate producer/verifier
processes in1.573s total. Branch proving0.558s, memory-copy proving0.525s;
fresh verifier subprocesses0.116s and0.119s. This is the CLI functional profile,
not the Ethereum production security profile or CSP promotion. Both reports
bind the clean source, ELF, statement, transcript, executable and proof identity.
Evidence: `../../vectors/reports/riscv-proving-stack-reset-20260908/small-cli-smoke/`.

The next focused Keccak lifecycle uses the existing canonical Ethereum artifact
codec and allocation tracker. It avoids the older precompile test root's forced
omitted-route instantiation. Both focused targets passed: one-call1/1, scaling1/4/16-call3/3. The scaling
request took96.75s including compilation, with15s of test execution. Complete
lifecycles took4.976/5.018/5.254s; proving4.048/4.082/4.318s and fresh decode plus
verification0.923/0.931/0.932s. Tracked producer peaks762.2/764.9/781.4MB and
verifier peaks132.8/132.8/132.9MB are allocator measurements, not process RSS.
Both owners reached zero live bytes in every case. The verifier is a fresh
transaction within the test process, unlike the CLI smoke's separate process.
These use development PCS with3queries, no PoW and worker1. They exercise the
same Keccak AIR but do not reproduce the retained segment's524,288 evaluation
rows. Evidence: `../../vectors/reports/riscv-proving-stack-reset-20260908/small-keccak-lifecycle/`.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-riscv-keccak-one-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-riscv-keccak-scaling-proof -Doptimize=ReleaseSafe --summary all
```

## Complete small recursive loop — 2026-09-08

The existing `run-recursive-segment-v2-concrete-outer-proof` executable now
serializes and freshly decodes its actual recursive AIR proof after outer
producer allocations reach zero. The child executes one real RISC-V step;
all39 outer components and47 relation domains participate. The native prepared
leaf remains verifier admission input, so this is native-assisted verification,
not the detached Ethereum root endpoint. Native q1 / outer q3 / no PoW are
explicit development profiles. The outer worker count is1.

| Check | First request, including build | Warm request | Scope |
|---|---:|---:|---|
| Shared Keccak row, Debug | 4.48s | 3.21s | Scalar values/degrees and lazy failure order; 2 tests including import discovery |
| Ethereum VM composition program, Debug | 17.64s | 3.91s | 3 named checks plus 2 discovery tests: recording scalar, production masks, compiler mutation rejection |
| Tiny recursive example, ReleaseSafe | 181.75s | 16.87s | Real native child, recursive proof, serialization/destruction/fresh decode, codec rejection and subsequent recording checks |

The tiny executable itself took13s. Its first outer transaction took3.872s:
producer preparation0.407s, proving1.749s, canonicalization0.004s, producer
destruction0.001s, verifier preparation0.418s and verification work1.289s.
The STARK verifier itself took0.006475s **inside** that1.289s, and publication
0.004s is also included. Do not add these nested intervals to the total.
The canonical outer proof is90,173B; tracked outer producer peak90,592,036B;
producer live bytes after destruction0. These are separate from the complete
example's roughly1GB process RSS and its native-child preparation.

Warm compilation was cached. These results establish useful runtime loops,
not fast incremental optimized compilation or a production-security speedup.
The broad Keccak regression still required246.78s including optimized compile,
although all335 tests ran in about1s. The consolidated complete Keccak proof
passed1/1 with5.009s lifecycle, matching the previous small workload's scale;
no retained-segment or CSP performance promotion is claimed.

Raw evidence is under
`vectors/reports/riscv-proving-stack-reset-20260908/shared-keccak-row-v1/` and
`vectors/reports/riscv-proving-stack-reset-20260908/small-recursive-lifecycle-v1/`.
Commands and lifetime boundaries are documented beside the frontend in
`src/frontends/riscv/README.md`.

## Recursive admission reduction — 2026-09-08

Three complete process runs per binary, in ABBAAB order, confirm the following
medians. Builds and the sampled attribution run are excluded. Each run freshly
verified the real serialized 39-component/47-domain proof with one worker.

| Interval | Before | After | Reduction |
|---|---:|---:|---:|
| Outer proving | 1.784 s | 1.169 s | 34.5% |
| Outer verification body and cleanup | 1.310 s | 0.623 s | 52.5% |
| Fresh verifier including cohort preparation and decode | 1.735 s | 0.958 s | 44.8% |
| Complete outer transaction | 3.946 s | 2.474 s | 37.3% |
| Complete example process, including native child and subsequent checks | 13.849 s | 12.064 s | 12.9% |

The STARK verifier itself is essentially unchanged: 6.411 ms before and 6.492 ms
after, nested inside outer verification. The canonical proof stays 90, 173 B;
tracked producer peak stays 90, 592, 036 B, with zero live producer bytes before
decode. Proof size equality is not a proof-byte identity comparison.

The removed work was synchronous duplicate source admission, duplicate closure
collection, separately audited boundary getters, and checks immediately repeated
by admitted constructors/generators. Public mutable-input checks remain, as does
fresh verifier reconstruction. The two unused core boundary getters were removed;
the existing combined transcript export now owns that boundary projection.
The structural/closure mutation suite passed 357 tests with 1 skipped. All six
complete A/B processes passed, including codec rejection and downstream replay.

The remaining verifier body costs include interaction reconstruction 165.5 ms,
preprocessing-root reconstruction 112.7 ms, component preparation 85.4 ms,
publication derivation 62.5 ms and closure 54.3 ms. Cohort preparation 335.3 ms
is separate. Phase medians describe attribution and need not sum exactly; each
individual raw record's phase accounting was checked exactly.

Optimized changed-source builds still take minutes; this patch establishes no
compilation speedup. The small CPU development fixture does not establish Metal,
retained-segment, production-security or CSP 16 performance promotion.

Evidence, exact commands, source/binary pins, raw timings and paired-run receipt:
`../../vectors/reports/riscv-proving-stack-reset-20260908/small-recursive-profile-v 1/`.

## Measured second round and bounded scaling — 2026-09-08

All results below use ReleaseSafe on an M 4 Max, native q 1 / outer q 3 / no PoW.
The original broad one-step example is kept for before/after comparison; the
size ladder uses a different, fixed finite counter-loop ELF at every size.
Do not compare the two fixtures as an optimization A/B.

Three fresh broad runs per version show a modest second-round improvement:

| Interval | Before | After | Reduction |
|---|---:|---:|---:|
| Producer cohort preparation | 0.329 s | 0.308 s | 6.3% |
| Verifier cohort preparation | 0.336 s | 0.310 s | 7.6% |
| Outer verification | 0.618 s | 0.599 s | 3.2% |
| Complete outer transaction | 2.457 s | 2.399 s | 2.4% |

Outer proving was effectively unchanged (1.167 s →1.173 s), as was its tracked
90.6 MB producer peak. Changes consolidate preflight ownership, core/manifest
admission, and publication-boundary derivation; three new real-source mutation
checks pass in the broad gate. This does not complete immutable V 2 preparation.

The counter-loop ladder passed three complete fresh processes per size:

| Native cycles | Native proving | Outer proving | Outer verification | Full request | Peak process RSS |
|---:|---:|---:|---:|---:|---:|
| 1 | 4.664 s | 1.199 s | 0.615 s | 8.158 s | 0.967 GiB |
| 4 | 5.266 s | 1.235 s | 0.651 s | 9.006 s | 0.967 GiB |
| 16 | 5.280 s | 1.238 s | 0.651 s | 9.018 s | 0.967 GiB |
| 64 | 5.266 s | 1.235 s | 0.646 s | 8.979 s | 0.967 GiB |

Every run proved all 39 outer components, checked all 47 relation domains,
serialized, destroyed the outer producer and freshly verified. The full request
also includes native verification, recursive admission, both cohort preparations
and teardown. The reported STARK-only outer verifier remains approximately
5–6 ms inside the enclosing outer verification. Outer producer allocation peaks
are 91.4–95.0 MB, separate from approximately 0.967 GiB process RSS.

The 1→4 transition introduces BNE alongside ADDI. Canonical outer rows 1 and 2
(transcript AIR/binding) grow from log 10 to 11; row 23 (trace Merkle) grows from
log 8 to 9. All 39 outer component logs are then identical at 4, 16 and 64 cycles;
row 34 remains log 11 and row 35 remains log 16. Native captured tree heights
remain 21 throughout. This plateau is evidence of padded/fixed geometry, not
evidence of a linear marginal cost that extrapolates to larger workloads.
Rows1/2 pad the transcript sponge-call count; row23 pads trace-query leaf
hashing chunks determined by opened column width. Identical padded logs do not
establish identical logical work. Raw per-frame call attribution is not yet
recorded by this ladder.

The native registry always includes schema-sized lookup tables, including
log 20 tables (`src/frontends/riscv/prover/statement_geometry.zig`,
`describeLookupTables`). That source fact is consistent with the observed
height 21 commitment floor. It does not by itself assign the entire native
proving time to lookup tables: per-table preparation, commitment and composition
attribution is the next measurement needed. Then compare a small load/store
loop at fixed cycles with increasing distinct addresses; this counter loop does
not test memory-opening growth. Preserve proof/profile identities when trying
fixed-column reuse or zero-column specialization.

A genuine fixture failure is retained: the original self-loop marked completion
and retired only 3 instructions when 4 were requested. The corrected finite loop
shares execution checks with its proof path. `--check-workload` verifies exact
cycles, instructions, PCs, registers and continuations for every size before
proving; its warm command took 0.13 s (2 ms executable). The changed-source build
still took 159.71 s. The failed source is exactly reconstructable from its retained
patch; no failure was hidden by weakening the requested-cycle check.

Commands, raw logs, source/binary pins, failure reproduction and machine-readable
medians: `../../vectors/reports/riscv-proving-stack-reset-20260908/small-recursive-scaling-v 2/`.
These are small CPU development proofs, not detached roots, Metal scaling or
CSP 16 promotion.
