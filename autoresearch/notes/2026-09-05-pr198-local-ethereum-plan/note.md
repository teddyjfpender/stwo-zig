# PR #198: local Ethereum proving on Mac CPU and Metal

Current remaining-work contract: [unified goal, implementation order and critical-path gates](unified-goal.md).
The dated checkpoints below are historical; use the unified goal for execution order.

Latest checkpoint (2026-09-07): schema7 raw clocks and program-bound key admission passed the complete native-assisted wrapper lifecycle (3/3) and separate-process replay (1/1). Standalone root/global admission and the real block route remain unfinished. CSP functional A/B passed 128 reports; performance promotion still needs a quiet host. See the [current progress record](progress.md#2026-09-07-schema7-complete-proof-and-separate-process-replay-pass); older observations below retain their historical scope.

Investigation date: 2026-09-05. Inspected head:
`6b7f08af51204dc8e96252879c772a8bed874748`, branch
`autoresearch/metal-ecdsa-subsecond-20260829`.

Objective: demonstrate complete Ethereum block proving locally on CPU and Metal,
compare fairly with local ZisK, then reduce verified end-to-end latency. Preserve
the existing RV32 CSP products, semantics, and performance. RV64 is a separate
frontend decision, not a prerequisite assumed by this plan.

## What is actually available

| Area | Evidence at the inspected head | Remaining boundary |
| --- | --- | --- |
| PR | Open, 1,524 changed files, 480,842 additions, 6,336 deletions | Far broader than the omitted-leaf title; needs a review map and working gates |
| Ethereum input | Mainnet block 24,628,607; 66 transactions; 7,372,614 gas; versioned input projection and benchmark manifest | Manifest still withholds matched-guest-statement promotion |
| RV32 execution | Repository notes report complete combined Keccak/recovery execution: 880,760,229 cycles, 210 segments, correct output, 70.49 s | Historical execution measurement, not a current-machine block proof |
| Native leaf | Notes report one Metal leaf transaction at 191.84–234.17 s, CPU fresh verify 21.35–24.29 s, peak footprint about 21.2 GB | Does not establish all-leaf coverage |
| D5 provider | Notes report about 3.2–3.8 s Stage A plus proving for 26 shards / 6,671,301 calls | Standalone provider timing excludes the full leaf and block |
| Omitted provider | STWIOL01 codec, engine-generic prove/fresh-verify route, shared relation closure, Metal command opt-in exist | `COMPLETE_LEAF_PROOF`, production and recursive-capture gates remain false; no real-route benchmark reproduced here |
| Campaign | CAS, resumable scheduler, native leaf worker and temporal proof infrastructure exist | Omitted-leaf worker returns `NativeOmittedLeafBridgeUnavailable`; existing worker is CPU; adapter parallelism is one |
| Recursion | Secure parent proving and reconstruction modules exist | Production/child-admission gates remain false; no complete independently verified Ethereum root established here |
| CSP | Existing 16-case CPU/Metal A/B harness and native/recursion isolation checks | Latest-head products and timings must be re-established before further shared changes |

Source anchors:

- [Execution and two completion milestones](../2026-08-30-rv32-ethereum-minimal-trace/note.md).
- [Measured leaf and provider stages](../2026-09-03-d5-leaf-metal-host-throughput/note.md).
- [Omitted route](../../../src/integrations/riscv_cpu/ethereum_incremental_omitted_leaf_route_v1.zig)
  and [Metal entry](../../../src/integrations/riscv_metal/stage101_leaf_degree5_provider_v1.zig).
- [Unavailable campaign adapter](../../../src/integrations/riscv_cpu/recursive_pipeline_worker_native_omitted_leaf_v1.zig).
- [Comparison contract](../../benchmarks/ETHEREUM_BLOCK.md)
  and [matrix contract](../../benchmarks/ethereum_block_benchmark_matrix_contract.py).

These timings are checked-in campaign records, not fresh performance verification.
The referenced `/private/tmp` campaign artifacts were not present in the locations
checked. No ZisK executable was found on PATH, and `~/.zisk` is absent. Restore
artifacts and tool custody before treating historical results as reproducible here.

## Corrections to the previous roadmap

1. **This is a different machine.** Live `sysctl` reports Apple M4 Max, 14 CPUs,
   38,654,705,664 bytes (36 GiB). The earlier campaign and matrix hardware policy
   specify M5 Max, 18 CPUs and 64 GiB. Create a new host-bound comparison cohort;
   do not overwrite or reuse its hardware claims.
2. **210 segments can cover the entire block.** The 389-segment / 1,630,632,307-cycle
   result used software signer recovery. The combined guest's complete recorded
   execution is 210 segments / 880,760,229 cycles. Do not make 512-leaf transport
   a prerequisite solely because the older roadmap confused those workloads.
   Exact segment-count pins still prevent general block support.
3. **The global-clock limit remains real.** `PublicDataV2.metadataFromView` checks
   `segment_v2.MAX_GLOBAL_CYCLES = 2^24`; access-clock bounds also depend on that
   range. Local replay clocks do not establish globally authenticated coverage.
   Trace this through late and terminal leaves, not only segment 1.
4. **The resource profile does not fit this host's capacity.**
   `ProviderOmissionPinsV1` fixes a 48 GiB host budget, 8 GiB reserve, 18 execution
   owners and retained Stage-A commitments. These are identity-bound pins, not
   arbitrary environment knobs. Their budget exceeds physical memory here.
5. **Security is a prerequisite to a security-matched comparison.**
   `memory_commitment/poseidon2.zig::hashPair` returns one M31 lane; continuation
   and program commitments retain scalar roots. Review and version the complete
   commitment construction. The previous suggestion of four M31 lanes is not
   by itself a 128-bit collision-security design: output size, sponge capacity,
   domain separation and composition all need an explicit security budget.

## Ordered engineering work

### 0. Restore a usable baseline and durable inputs

- Repair module ownership at the product boundary. The live RISC-V CPU CI log
  fails because `resource_usage.zig` is reached through both `riscv_adapter` and
  `stwo_riscv_cpu_integration`, and through both the test root and integration
  module. Reuse one module owner; inspect all consumers before changing imports.
- Triage the other failing package, integration, aggregate, script and refinement
  checks. Do not describe all failures as inherited without comparing their base.
- Build CPU and Metal products through `scripts/zig_serial_build.py`, one heavy
  build at a time. Start with a 16 GiB build scheduling budget on this host;
  `--maxrss` is build scheduling policy, not an operating-system RSS guarantee.
- Restore the pinned guest, source overlays, witness, AOT bundle, tool binaries,
  keys and receipts into durable local storage. Reuse the CAS and
  `restore_campaign_inputs.py`; avoid using purgeable `/tmp` as the only copy.
- Seal current-head CSP baselines on both backends. The existing reports in
  `vectors/reports` date from July/August and are not PR-head measurements.
- Obtain and verify a bounded ZisK example first, then the pinned block. Record
  an explicit resource failure if this machine cannot complete it.

Exit: clean builds and relevant gates, recoverable inputs, same-host CSP receipts,
and known local ZisK prove/verify capability. Update the PR review map around the
actual branch scope; do not add another broad performance campaign first.

### 1. Freeze the comparison statement and a viable Ethereum profile

- Keep block 24,628,607 as the first acceptance fixture. Reuse the existing
  semantic input projection; independently check fork rules, parent/pre-state,
  post-state, transactions, receipts, gas, withdrawals/requests where applicable,
  and normalized public output. Correct block-hash output alone is insufficient.
- Version the Ethereum statement's global cycle/access-clock representation while
  keeping per-leaf rows and allocations bounded. Bind local/global offsets in
  constraints and the verifier; add boundary, overflow and late-leaf tests.
- Widen and domain-separate memory/program commitments through tree construction,
  AIR tuples, public IO, codecs, continuation equality and recursion. Obtain an
  explicit conservative end-to-end security target before selecting parameters.
  Never widen only the wire or trust a host-computed strong hash of a weak root.
- Establish a low-memory omitted-provider profile for this Mac. Preserve shard
  geometry/security where possible; reduce active owners and retained live state.
  Version/reseal any changed identity-bound pins rather than pretending old proof
  identity survives. Measure Stage-A recomputation versus retention if required.
- Generalize the exact-210 transport only where needed: bind actual segment count,
  enforce an explicit maximum and authenticate padding. A 210-leaf binary tree
  can use 256 positions; 512 is needed only for a workload that exceeds 256.

Exit: first, middle and terminal leaves of the selected full execution are
admissible under one explicit statement/security/resource profile; mutations of
global offsets, program roots and continuation state fail verification.

### 2. Demonstrate one complete omitted-provider leaf on CPU and Metal

- Reuse `RouteV1(ProverEngine, VerifierEngine)` and STWIOL01. Complete the current
  route's outstanding completeness/admission obligations; false activation flags
  are not fixed by toggling them.
- Run the existing focused codec, route, transcript and orchestration gates.
  Produce real leaf bytes, destroy producer objects, and verify from bytes in a
  fresh process. Instantiate CPU proving and authenticated Metal proving against
  the same frontend statement and security profile.
- Prove core plus all provider shards under the shared transcript/PoW/relation
  context. Reject missing, duplicated, reordered and foreign shards; mutated
  public IO; bad completion; and nonzero bus residuals.
- Benchmark representative first, middle, heavy and terminal segments. Report
  admission, replay, witness, Stage A, core/shard proving, serialization, fresh
  verification, total request, peak footprint and declared device placements.
  A 3.4-second provider sweep is not the leaf acceptance criterion.

Exit: complete real-leaf receipts for both backends with resource usage that
fits this Mac, and a measured before/after against the corresponding native leaf.

### 3. Produce and independently verify the whole block bundle

- Wire the admitted route into the existing omitted-leaf worker and controller;
  add an explicit Metal worker composition alongside CPU. Reuse the existing
  scheduler, store and receipts rather than introducing another orchestration layer.
- Start with one leaf in flight. Amortize admitted ELF/program/campaign preparation
  once per block. Bound producer, GPU, verification and artifact queues together.
- Prove every segment of the actual capture. A fresh bundle verifier opens each
  leaf, verifies it, checks exact ordered CPU/memory/global-clock adjacency, binds
  the first input and final output, and rejects omission, duplication and gaps.
- Retain the complete artifact set plus one immutable ordered manifest. Report
  this milestone as a **verified full-block proof bundle**. It is a useful local
  proof demonstration, with linear verification and multiple proof artifacts.

Exit: the same pinned Ethereum block completes on CPU and on Metal, with all
proofs freshly checked and measured whole-request time. Compare bundle metrics
only with equivalent ZisK base-proof coverage; do not label a bundle faster than
ZisK's final recursive proof by omitting Stwo aggregation.

### 4. Close succinct recursive verification and the final comparison

- Reuse the existing secure parent/temporal AIR. Map the unavailable child
  capture/admission path, then require in-circuit verification of the actual
  omitted-leaf envelope and its shared-provider closure.
- Prove a real pair, an uneven tree with authenticated empty leaves, then the
  whole block. Parent native pre-verification or a signed/hashed manifest cannot
  replace constraints that verify child proofs.
- Require one root whose public statement binds the full block and coverage.
  A fresh verifier must work from root bytes and public verification material
  without campaign leases, producer caches or transitive native leaf reopening.
- Run ZisK to the matching endpoint: pinned final proof format and independent
  fresh verification. The repository's VADCOP evidence tooling deliberately marks
  a historically contended/unpartitioned result nonpromotable; recover and verify
  its artifacts for correctness, then remeasure rather than reuse its timing.

Exit: complete input-to-fresh-final-verdict measurements for Stwo CPU, Stwo Metal
and ZisK on this Mac at the same conservative security target. No hosted prover,
remote GPU or x86 emulation silently substitutes for local native capability.

### 5. Reduce measured latency, then broaden the corpus

Optimize after each completed milestone, keeping the complete request as the
decision metric. Start with these hypotheses in order; re-rank using fresh data:

1. Remove repeated campaign/ELF preparation and redundant artifact opening.
2. Reduce live witness, retained commitment and composition memory; stream leaves.
3. Improve the real leaf's dominant Merkle/quotient/FRI work and GPU wait overhead.
4. Overlap replay and verification with proving within measured memory headroom.
   Make registry request/lease state thread-safe before raising worker concurrency.
   Two old 21.2 GB leaves already exceed this 36 GiB host, before OS/GPU overhead.
5. Complete the minimal-capture/parallel-replay path through proof verification;
   its replay-only rates exclude capture, precompiles and proof construction.
6. Add only profiled, fully constrained precompile optimizations. Small operations
   may remain explicitly on CPU where Metal dispatch overhead costs more.

Use latency milestones of under one minute, then ten seconds, then the existing
five-second corpus goal as engineering targets, not forecasts. The recorded
roughly 74.49M-cycle/s capture rate alone implies about 11.8 s for the historical
880.76M-cycle guest, before replay/proving: sub-ten requires changing that measured
floor too. This arithmetic is a historical model, not an M4 measurement.

After the first block is complete, use the existing five-block corpus for varied
gas, memory, precompile and EVM mixes. Keep the original all-five final-proof
promotion contract; introduce a host/backend dimension for CPU, Metal and ZisK
rather than copying or relabeling one system row. Do not average incomplete runs.

## Fair measurement contract

- Same physical Mac, power/thermal envelope, resource ceilings and pinned software.
  Run arms sequentially in balanced order with declared warm/cold state and repeated
  samples. Record wall, user/system CPU, memory, proof bytes and fresh verdicts.
- Same semantic block transition and security target. Fields, ISAs and AIR layouts
  can differ; disclose them. ISA cycles alone are not cross-VM throughput.
- Publish a native-product comparison using each system's real optimizations, and
  label acceleration differences. A separately implementation-normalized lane
  requires matched software operations or equivalent constrained precompile scopes,
  including invalid-result semantics. Do not infer an RV64 advantage from different
  guests, recovery/Keccak implementations or memory systems.
- Count witness generation, serialization, IO and verification exactly once.
  Measure end-to-end directly. For overlapped work, stage durations are work
  attribution and need not sum to wall time; explicitly version the current
  exclusive-bucket report before admitting a pipelined run. Never fabricate buckets
  from ZisK log timestamps when only process-wide totals are known.
- Disclose one-time key/tool/AOT setup separately, plus cold first request and warm
  sustained behavior. Count resumed/reused work explicitly.
- Primary upstream references checked during this investigation:
  [ZisK quickstart](https://0xpolygonhermez.github.io/zisk/getting_started/quickstart.html)
  documents macOS support with unoptimized proof generation and an RV64IMA target;
  [ZisK Ethereum client](https://github.com/0xPolygonHermez/zisk-eth-client) provides
  stateless validators. Verify the pinned implementation locally before assuming
  its large-block path fits 36 GiB.

## CSP is a mandatory acceptance gate

- Keep native RV32 CSP entry points, guest identities, statement/transcript/proof
  identities, security parameters and benchmark worker policy unchanged. Ethereum
  profile, recursion and future RV64 changes must not become CSP defaults.
- Use `scripts/riscv_csp_ab_benchmark.py` for all 16 cases on CPU and Metal against
  the restored PR-head baseline. Retain existing isolation checks for recursion
  environment contamination and product build dependencies.
- Run representative SHA-256, Keccak, Poseidon2 and secp256k1 screens on shared
  prover/backend edits; require the full portfolio before merging a milestone.
  Preserve proof identity for implementation-only changes and fresh-verify every
  measured proof. Provider-only subsecond ECDSA is not the end-to-end CSP result.
- Compare complete request, proof duration, verification, peak memory, host CPU work
  and declared Metal fallback counts. Do not let a geometric mean hide a per-case
  loss. Proposed triage triggers: >3% request/proving loss or >5% memory growth;
  these trigger longer balanced confirmation, not an allowed regression budget.
  Any reproducible regression blocks shared-code promotion until resolved.
- Use new versioned Ethereum commitments/clocks without silently migrating the
  old CSP protocol. If review finds a shared CSP assurance defect, document it and
  measure the secure successor separately; never trade soundness for an old number.

## RV64 decision and isolation

Do not widen RV32 registers, addresses or memory AIR globally. Once equivalent
full-block execution is established, profile 64-bit lowering: limb arithmetic,
loads/stores, pointer/index operations and their actual constrained rows/cells.
Build a bounded guest compilation/execution feasibility experiment to determine
the required ISA/ABI (including whether atomics or compressed instructions are
actually used), Rust dependencies and memory needs.

If the same guest algorithms still spend a material fraction of end-to-end cost
on RV32 lowering, implement a separately admitted RV64 frontend/profile with its
own decoder, ELF64 admission, register/memory statement and arithmetic AIR. Reuse
field/prover/backend infrastructure and proven precompile interfaces. Validate
word-operation sign extension, shifts, multiply/divide edges, address ranges and
load/store behavior against an independent ISA oracle before whole-block proving.
Wider limbs increase AIR cost; fewer instructions do not guarantee faster proofs.
Keep the RV32 CSP lane unchanged and gate both lanes through shared backend tests.

## Verification performed for this plan

- Safe PR checkout from a clean `main`; local head equals the inspected PR head.
- Live host identification and source tracing of the route, worker, clock bounds,
  scalar commitments, resource pins, matrix and CSP isolation paths.
- `python3 autoresearch/benchmarks/ethereum_block_comparison.py validate-manifest`:
  valid, schema v6.
- 52 existing Python tests passed: Ethereum benchmark protocol/matrix and CSP
  isolation/A-B harness. Initial three temporary-repository commit errors were
  caused by inherited Git signing. Rerun passed with process-local
  `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false`;
  user and repository Git configuration were not changed.
- Latest sampled PR checks: 50 successful, 12 failed, 3 pending. The CPU duplicate
  module ownership failure was read from the completed job log. CI remained red.
- No fresh Zig build, Metal proof, CSP timing suite, ZisK proof or full block run
  was performed. This is an investigation and implementation plan, not a new
  performance or cryptographic completion receipt.


## 2026-09-07: STARK succeeds; cold geometry rejects the split-two capture

The complete-wrapper retry used frozen source snapshot
`237f9cdea71e6ee2db29808e4d8f0c73f5bc6ffe`, source SHA-256
`fa69c65fba207556e7f88c151d28d47d1bf74ada4e5b07e35f4c5e1be2522ddd`.
STARK generation succeeded in **433.091515875 s**, and native STARK verification
returned successfully. The later `ColdGeometry` admission still expected eight
composition columns from the global split-one default; this wrapper explicitly
admits split two and has sixteen. It rejected the capture with
`InvalidEthereumIncrementalColdGeometryV4`.

The complete gate therefore **failed: 2/3 tests passed, 1/4 build steps passed**.
The whole request took **1348.869591958 s**, with a process-lifetime physical
footprint peak of **52,615,273,088 bytes** (52.62 GB). The earlier retained-
coefficients attempt peaked at 59,835,018,536 bytes and failed OODS finalization;
these runs reached different phases and outcomes. Their peaks are descriptive
observations, not a matched memory or speed comparison.

This is not the first independently verified wrapper lifecycle: cold admission
failed before returning the completed owner, and the final producer-destruction
and independent-verification gate was not reached. No canonical wrapper proof
candidate was retained because its persistence hook followed successful cold
opening. The full log, progress log, live cold-validation sample and source
receipt are retained in
[evidence/2026-09-07-normalized-q2-cold-geometry-failure](evidence/2026-09-07-normalized-q2-cold-geometry-failure),
with hashes and exact scope in `normalized_q2_cold_geometry_checkpoint`.

The next changes address this shared-admission mismatch and retain proof bytes
before cold admission. Later validation changes are not part of the measured
snapshot. Root-only verification, fixed schema-4 admission, whole-block proving
and latest-source CSP promotion remain unfinished. The CSP comparison is
prepared but has not run; its candidate must be refreshed after source changes
stabilize.


## 2026-09-07: first independent wrapper lifecycle passes

Frozen snapshot `804799bc288f8f41904edec7f5a17db22a65b3af` (source SHA-256
`1ad0fdb5e8329f497860389af2003dce61b0773bb27a7f1b4daf5d8b87215939`)
passed the complete lifecycle: **3/3 tests**, canonical serialization, producer
allocator drained to zero, fresh verifier reconstruction, successful cold
verification and all postprocessing/mutation checks. The canonical proof is
3,019,076 bytes, SHA-256
`f404b395543ba08d5b2d0014ef5a71d7653e925b335b0bc5632e3ea179f6ecf3`.
The focused preflight had passed 106 admission/routing tests plus two complete
mixed-degree STARK tests.

This is the small genuine **native-assisted wrapper**, not a whole Ethereum
block or a root-only recursive proof. Active native child admission remains
selected-detailed schema3; field-authority schema4 and parent Ethereum transcript
publication remain unselected. No new CSP promotion or CPU/Metal A/B is claimed.

Measured request: 7,493.155262042 seconds (124.89 minutes), of which
434.685765000 seconds were STARK construction, 1,279.436158666 seconds were the
wrapper prove/cold-open phase, 376.380326416 seconds were independent reopening,
and **5,728.522278083 seconds (95.48 minutes) were postprocessing**. Peak physical
footprint was 52,615,223,816 bytes; peak tracked allocations were 43,963,032,188
bytes. Final tracked ownership was zero. The retained native input proving is
excluded. These are diagnostic timings, not an Ethereum block benchmark.

The proof and logs now allow subsequent verification/ownership changes to be
checked without reproving. Opaque cold-owner and new transcript-route edits
made after the frozen binary launched are a separate, initially unverified
source batch. Evidence: [checkpoint](evidence/2026-09-07-first-independent-wrapper/checkpoint.json)
and [complete log](evidence/2026-09-07-first-independent-wrapper/complete-proof.log).

## 2026-09-07: retained wrapper replay passes

The private-owner replay passed fresh verification and publication/mutation checks in 618.19 s; postprocessing fell from 5,728.52 s to 188.76 s. This remains a native-assisted small wrapper. The checked-view follow-up passed: postprocessing is now 55.86 s and complete retained replay 479.72 s, with additional child-alias regressions. Root-only field admission remains pending; current CSP preservation is running. See [the authoritative progress checkpoint](progress.md#2026-09-07-retained-wrapper-independently-replays-after-ownership-fix) and its linked evidence.
