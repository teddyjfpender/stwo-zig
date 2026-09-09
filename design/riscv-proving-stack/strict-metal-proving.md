# Strict Metal proving: ownership and acceptance contract

This is a source-derived inventory of the supported four-segment route as of
2026-09-09. The existing Metal proofs are correct under their admitted
experimental profile and use GPU kernels, but substantial prover computation
still runs on the CPU. Strict execution guards, recursive composition export
and a small generated-kernel device parity gate now exist. Production AOT and
resident composition integration remain incomplete; these individual gates do
not establish full strict execution.

The route contains four native proofs, four detached leaf wrappers, two
intermediate parents and one root. The controller is
[`riscv_segment_v2_detached_tree_gate.py`](../../scripts/riscv_segment_v2_detached_tree_gate.py).
The supported fixture retires 227 instructions and touches one memory address.
It is not an Ethereum block. Reproduction commands, admitted keys and executable
pins are in [the small complete-proof route](small-recursive-benchmark.md).

## What strict execution means

CPU orchestration may admit inputs and fixed circuit identities, schedule GPU
commands, handle files, mix the small Fiat–Shamir control transcript and
serialize proof bytes. Independent CPU verification is an intentional separate
correctness gate. Its time must be reported separately from production.

Witness expansion, field evaluation across rows, exact lookup closure, lookup
interaction generation, polynomial transforms, Merkle hashing, composition and
FRI are bulk prover work. Graph interpretation and field arithmetic do not
become orchestration because they occur before `Engine.prove`. Large host
copies, repeated validation and allocation also remain measured request costs.
Execution of the guest program should be reported separately from witness
expansion; moving the latter to Metal does not imply GPU guest execution.

Strict mode must reject missing coverage before entering unsupported bulk work.
An unavailable kernel, unsupported geometry or unexportable AIR is an explicit
failure, not permission to invoke a host evaluator. A deliberate tiny-operation
exception would change this contract and require explicit admitted scope and
reported work; thresholds hidden inside primitives are not exceptions.

## Current ownership

Paths below are relative to `src/`. “Mixed” means GPU arithmetic exists but host
bulk work or conditional host paths remain. The evidence column names available
hooks and the additional coverage a strict receipt must establish. None of the
listed counters by itself establishes full-route device execution.

| Operation / scope | Code owner | Current execution | Positive evidence hook | Missing support or coverage |
| --- | --- | --- | --- | --- |
| Tree scheduling, artifact/key admission and fresh verification | `integrations/riscv_cpu/recursive_segment_v2_concrete_outer_proof_runner.zig`, `recursive_segment_v2_detached_parent_producer.zig`; controller above | CPU control; verification CPU intentionally | Per-node lifecycle receipts, admitted key/statement pins, verifier subprocess results | Separate producer child verification/capture cost from final independent verification; neither is a GPU-proving receipt. |
| Native execution materialization and witness construction | `integrations/riscv_cpu/recursive_segment_v2_two_segment_proof_test_support.zig`; `frontends/riscv/prover.zig` → orchestration; `prover/main_trace.zig`, `prover/main_trace_support.zig` | Host construction remains; some backend-specific witness generation support exists elsewhere | Native ingress timer; `metal_trace_generation_dispatch`, synchronization and copyback counters when actually used | Account for all opcode, memory, fixed-program and provider columns in the active SegmentV2 route. Existing trace dispatch elsewhere is insufficient. |
| Leaf verifier graph preparation, main witness and closure | `integrations/riscv_cpu/recursive_segment_v2_leaf_outer.zig`, `recursive_segment_v2_outer_cohort.zig`, `recursive_segment_v2_detached_proof.zig` | CPU: preparation, `fillMainInto`, `auditGlobalClosure` | `detached_prepare_ns`, main/closure phase timing; no complete device witness receipt | Admit immutable graph/layout once, provide device row projection and provider witness generation, and cover the exact closure operation. |
| Parent graph preparation and arithmetic lowering | `integrations/riscv_cpu/recursive_segment_v2_detached_parent_prepare.zig`, `recursive_segment_v2_detached_parent_arithmetic.zig` | CPU graph capture, evaluation, lowering and row construction | Request preparation timing; lane/fusion row counts | Separate immutable schedules from proof-dependent values, reuse admitted schedules, move bulk evaluation/projection behind explicit backend ownership. |
| Parent main rows, compact Poseidon and exact tuple closure | `integrations/riscv_cpu/recursive_segment_v2_detached_parent_cohort.zig`, `recursive_compact_tuple_ledger_v1.zig`; `frontends/riscv/recursion/air/poseidon2_universal_degree3_v1.zig` | CPU in `finalizeMainInto`, including provider rows, range multiplicities and ledger | `parent.main_finalize`; logical-row and provider geometry | Device witness generation and an exact closure implementation with authenticated row/use counts. Avoid repeating the closure ledger upstream. |
| Recursive lookup interactions | `frontends/riscv/recursion/air/framework_interaction.zig`; leaf/parent cohort `fillInteractionInto` | CPU relation evaluation, batch inversion, cumulative scan and bit-reversed scatter | `parent.interaction_fill`; `metal_relation_epoch` exists for other clients | Export this framework's exact equations and parameter bindings; device relation evaluation, inversion and scan. Existing generic LogUp kernels are not proof of matching recurrence. |
| Preprocessed rows and trace storage | Leaf/parent cohort; `integrations/riscv_cpu/recursive_segment_v2_outer_engine_storage.zig` | CPU filling; backend storage/commit mixed | Fixed/preprocessed timings, allocator counters, commit arena alias/upload counters | Immutable prepared/preprocessed ownership and reuse; account for every expanded column, allocation and upload. Cache keys must bind exact admitted profile and geometry. |
| Circle interpolation, evaluation and LDE | `backends/metal/commit_backend.zig`; `runtime/combined_commit.zig`, `runtime/heterogeneous_commit.zig` | GPU supported; domain log-size below 3 has host primitive branches | `metal_circle_transform_dispatch`, `metal_circle_lde_dispatch`; `cpu_small_circle_*` | Device coverage or fail-closed handling for small domains, zero/constant fast paths and all physical slabs. Report host source copies separately. |
| Merkle commitments, including Poseidon | `backends/metal/commit_backend.zig`, `runtime/circle_commit_epoch.m`, commit runtimes | GPU resident paths; small/streaming/unsupported paths can use host hashing | `metal_poseidon2_merkle_commit`, resident commits, heterogeneous epoch dispatch/wait counts; `host_merkle_commit` | Require exact tree/leaf/parent-row coverage and authenticated hash-family kernel. A Poseidon commitment counter says nothing about Poseidon AIR witness generation or composition. |
| Native composition | `backends/metal/runtime/base_polynomial_composition.zig`; `prover/air/component_prover.zig` | Mixed: admitted semantic/lookup batches GPU; other components host; cost crossover can retain small components on host | Eligible component counts plus completed `metal_riscv_*_batch_dispatch`; host component accounting | Cover every component and all random-coefficient ranges; strict mode must reject host placement even when it was never considered a fallback. |
| Leaf/parent recursive composition | Typed component adapters under `frontends/riscv/recursion/air/`; same backend scheduler | Current measured route uses prepared host evaluation | `composition_evaluation`; component-level export/admission and dispatch receipts are being added | Authenticated arbitrary preprocessed bindings, direct constraints, relation parameters, exact framework recurrence, compact Poseidon and range-table coverage. |
| OODS sampled evaluation and FRI quotient | `backends/metal/commit_backend.zig`; `runtime/sampled_coefficient_operations.zig`, `runtime/sampled_barycentric_operations.zig`, `runtime/quotients.m` | GPU routes available; host preparation and conditional sampled-value fallback remain | `metal_sampled_value_dispatch`, `metal_quotient_dispatch`, `cpu_sampled_value_evaluation` | Coverage by polynomial/query batch, not one dispatch per proof; distinguish quotient preparation, execution, copies and waits. |
| FRI folds and fold commitments | `backends/metal/commit_backend_fri.zig`, `runtime/fold_inverses.zig` | Mixed: GPU folds; line-fold path computes inverse arrays on host. Circle folds use resident inverses only above a threshold unless parity checks request host data | Fold dispatches and `FriFoldExecutionLedger.inverse_path`; resident fold/commit receipts | Device inverse preparation for every admitted layer. The cascade fast path admits Blake2s and fold-step 1; it does not cover this Poseidon fold-step 4 profile. Individual fold-and-commit paths must be audited by their actual receipts. |
| Proof of work | `backends/metal/runtime/proof_of_work.zig`; `integrations/riscv_cpu/recursive_segment_v2_detached_proof.zig`, `recursive_segment_v2_detached_parent_proof.zig` | Backend PCS grinding GPU supported; leaf and parent interaction grinding now use shared `pcs.proof_of_work.grindForBackend` | Backend PoW result includes dispatch count/GPU milliseconds; the checked hybrid root records two PoW dispatches | Preserve backend admission for both grinding sites. Prefix setup and final nonce checking are bounded control; nonce search is computation. |
| Query extraction, serialization and cleanup | Shared prover and detached producer/command modules | CPU packing, I/O and resource destruction | Decommit/serialize timers, producer-destroyed receipt and live-resource counts | Separate retained-proof readback/copy bytes from algebra; verify completion before releasing device buffers and preserve producer-destruction gate. |

`backends/metal/telemetry.zig` explicitly distinguishes host placement from
fallback: default host composition historically did not increment
`cpu_composition_evaluation`. Thus `cpu_fallbacks=0`, `requireMetalDispatch`, or
`requireAcceleratedWithoutFallbacks` cannot certify strict execution. The new
host-component counter improves visibility, but full coverage needs the admitted
component roster and operation counts as its denominator.

## Measured priority

The retained [measurement index](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/air-fusion-measurements.json)
contains paired root benchmarks and separate diagnostic observations. The root
A/B consumes retained older parent proofs; it is not a whole-tree A/B.

| Scope | CPU | Metal | Interpretation |
| --- | ---: | ---: | --- |
| Optimized retained-parent root request, paired median | 13.244 s | 10.886 s | Same admitted statement/profile within each comparison |
| Fresh root verification, paired median | 70.089 ms | 70.328 ms | Both verifiers run on CPU; second column describes proof origin |
| Four-segment production sum | 79.768 s | 65.835 s | Individual full-tree observations, not paired medians |
| Four-segment complete hostile-input gate | 83.351 s | 69.507 s | Each passes 136 fresh acceptance/rejection cases |

The diagnostic Metal root took 10.942749 s. These are wall-clock enclosing
phases, not GPU kernel durations:

| Phase | Seconds |
| --- | ---: |
| Preparation | 3.660003 |
| Fixed/preprocessed preparation and commitment | 0.563528 |
| Main allocation | 0.029274 |
| Main filling, range construction and exact closure | 2.641063 |
| Main commitment | 0.659607 |
| Interaction transcript/filling | 1.610844 |
| Interaction commitment | 0.341412 |
| Composition evaluation | 0.944152 |
| Composition interpolation/split and commitment | 0.028266 |
| Sampled evaluation | 0.043437 |
| FRI quotient build/commit | 0.110567 |
| PCS proof of work | 0.005072 |
| FRI and trace decommitment | 0.011808 |
| Serialization | 0.004987 |

Preparation, main finalization and interaction filling together account for
7.911911 s, about 72.3% of this request. Composition is about 8.6%. Removing all
composition time therefore cannot deliver a large overall speedup by itself.
These aggregate measurements do not yet assign all allocation, CPU evaluation,
device execution and wait costs. Strict receipts must make that attribution
possible before calling the entire route GPU resident.

## Proof-level finish gate

1. Enumerate requested work before execution, bound to node identity, circuit
   key, semantic plan digest, commitment/profile parameters and physical
   geometry. Every substantial operation is GPU-supported or rejected before
   entering the host implementation. Tests exercise unsupported geometry and
   missing/incorrect kernel admission, not just a policy enum.
2. Record completed GPU work per operation and component: logical/physical rows,
   columns, batches, coefficient windows and device kernel identity. Compare
   requested coverage against completed coverage; zero work is explicit. One
   unrelated dispatch cannot satisfy another operation. Report host-copy bytes,
   command buffers, waits, allocations and live/resident memory independently.
3. Prove the four native leaves, four wrappers and three recursive parents in
   strict mode. Retain all receipts and final proof bytes, destroy producer
   state, and freshly verify with independently pinned keys and expected
   statements. Preserve existing 136-case acceptance/rejection coverage and
   changed-memory verification under the same admitted keys. Validate CPU/device
   semantic parity before requiring a complete strict route to pass.
4. Report complete-request cold and warm timings, preparation, proof generation,
   independent verification and peak memory. Reuse may remove repeated admitted
   work but cannot silently omit required constraints, change security parameters
   or accept producer-created keys. Failures retain reproducible inputs.
5. Increase instructions, distinct memory addresses and tree size separately.
   Admit resource estimates before allocations; report predictable capacity
   failures and cleanup. Resume Ethereum only after these complete gates catch
   geometry, memory and continuation failures cheaply.

## Focused formal obligations

Reuse the pinned Lean project in
[`formal/riscv-refinement`](../../formal/riscv-refinement/README.md), its M31
definitions, AIR interpretation infrastructure and axiom/source-receipt audit
pattern. Its existing opcode refinement theorems do not establish recursive
verifier soundness. Add isolated recursive obligations with explicit premises;
do not relabel existing opcode coverage as proof of these new AIRs.

* **Fusion:** prove the QM31 multiply-add and four-product accumulator identities
  and preservation of the external wire-event multiset. State topological graph
  and exact-use-count premises, including exported outputs, duplicated operands,
  aliases and adjacent fusion blocks. Internal single-use wires disappear while
  externally used values and their multiplicities remain authenticated. Bind
  the theorem fixture/export to the actual admitted AIR and matcher assumptions;
  algebra alone does not prove the implementation of a graph matcher.
* **Compact Poseidon:** relate the compact degree-three witness to the existing
  permutation at every round and the same input/output relation events. Prove
  witness extension and projection using exact constants and field arithmetic,
  including the intermediate representation of the fifth power. Mutation tests
  for constants, intermediate states and outputs provide nonvacuity checks.
* **Framework recurrence:** prove equivalence of exported CPU/device equations
  to the framework's same-row cumulative batch differences. Only the final
  batch reads the previous row; include the claimed-sum/trace-size shift,
  wraparound, physical bit reversal and chunked prefix-scan composition.
  Denominator nonzero assumptions and transcript-bound relation challenges must
  remain explicit. Check direct roots, lookup tuples and parameter bindings
  against the same authenticated plan rather than hand-maintained equations.

Each formal result needs a maintained small command, exported-source identity,
approved-axiom audit and negative/nonvacuity controls. These local equivalence
results complement fresh proof verification. They do not certify commitment
security, the experimental q193 profile, Fiat–Shamir soundness or the whole
recursive proof system.

## Minimal production composition integration

The source-only generator gate passed 6/6. The subsequent device gate passed
7/7, including 27 cases, 36 completed GPU dispatches and 7,392 checked
coordinates across 1,848 rows. It reused one generated kernel across three
trace sizes, three extension sizes and three profile/challenge/claim variants,
including repeated additive dispatches with a buffer barrier. CPU expected
values use an independent rational oracle, core circle-point shifts and exact
vanishing denominators. The focused run took 454 ms after a roughly four-second
build; these are test timings, not proof timings.

The expanded gate now passes 10/10 tests: four kernel shapes, 108 cases,
144 completed dispatches and 29,568 coordinates across 7,392 rows. It adds
sole singleton/final-pair layouts, mixed arities including 33-word tuples and
five reordered/repeated direct roots. Each shape uses explicit scalar tuple
expressions and rational lookup residuals as its reference. This expanded run
took about one second after a four-second build; production AOT integration
and actual exported-component proof parity remain separate requirements.

```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal \
  test-framework-polynomial-device -Doptimize=ReleaseFast
```

This device test deliberately compiles generated source in an isolated test
runtime. It does not establish production AOT admission, proof-owned input
residency or complete component coverage. A checked hybrid root retained exact
proof-byte parity while recording 31 host composition components and two device
PoW dispatches. That is useful correctness evidence, not strict success.

The next implementation should extend the existing resident composition route:

| Change / owner | Smallest concrete integration |
| --- | --- |
| `prover/air/component_programs.zig` and typed component callback | The new `framework_polynomial_v1` capability already exports an owned program and owned invocation parameters. Export once per component during cold admission, before collecting residency requests; retain that immutable owner for dispatch and receipts. Check `nConstraints == direct.roots.len + batches.len`, trace geometry, actual tree bounds and canonical parameter lengths. Do not export again to count columns or dispatch rows. |
| `backends/metal/runtime/framework_polynomial_codegen.zig` | Keep full placement-bound program identity for job admission. Before growing the AOT roster, separate kernel equation identity from physical placement: current identity includes absolute column indices even though the emitted code uses an offset table. Hash the canonical emitted kernel with a fixed placeholder name, plus emitter/helper/version identity, or an equivalent exact structural projection. Relocating columns should change the job identity but reuse identical kernel code; changing source tree, equations, input-slot order or coefficient order must change kernel identity. Never normalize the admitted program in place or discard its full seal. |
| New framework program/job owner beside `runtime/lookup_polynomial_v2_owner.zig` | Follow its ownership-transfer/error cleanup pattern, but avoid invoking full program validation through every getter. Seal the admitted program plus physical bindings, trace/evaluation logs, constraint count and code identity once. Resolve profile words, canonical per-entry relation challenges and `claimedSumShift()` from the component callback; match its trace log to the admitted component. Values are invocation inputs, not AOT constants. |
| `runtime/base_polynomial_composition.zig`, `composition_device_buckets.zig` | Add a whole-component framework partition and job list. Consume the existing global random-power window in direct-root order followed by one secure residual per batch. Include every exported PP/main/interaction coordinate in residency/expansion planning. Dispatch into the existing per-log output buckets with barriers between additive writers, then merge once. Strict mode rejects an unsupported component before launching host workers; hybrid mode can still use its explicitly measured host path. |
| `runtime/resource_plans.zig`, `runtime/bindings.zig`, `runtime.zig`, new framework `.zig`/`.m` operations | Add the existing 11-buffer kernel ABI as a distinct dispatch type; reuse resident resolution and pipeline ownership rather than pretending it is the old selector/main ABI. A dedicated AOT prepare operation should only resolve the admitted framework prefix. Validate buffer ownership, all descriptor extents, coefficient/parameter windows and denominator geometry before encoding. Do not call source-library preparation in production. |
| `shaders/aot_profile.zig`, generated recursive shader/export roster, `runtime/initialization.m` | Reuse the explicit extension-profile mechanism already used for Ethereum: append a recursive framework source/ABI roster to core in a separate admitted profile. Generate from actual active typed AIR exports and deduplicate by kernel identity. The runtime's additional-name whitelist currently accepts only base/lookup prefixes; add the framework prefix deliberately. Load through `core_aot.admitForProfile` and `Runtime.initFromAotAdmission`, preserving manifest, source, metallib and declaration-digest checks. |
| `runtime/riscv_polynomial_aot_codegen.zig` and maintained export gate | Reuse the existing common preamble and per-program emission pattern for a recursive extension; avoid inserting a second copy of field helpers into one library. Require source regeneration to equal the checked-in extension and its exact exported name/ABI inventory. Enumerate active leaf and parent AIRs, including provider/range components, rather than assuming six exporter fixtures cover the whole tree. |

**Current resident shape supports the three-tree-buffer ABI.**
`TreeStorageForManifest` allocates one backing buffer per tree and transfers it
through `commitWithBacking`. The uniform commit publishes `@[extended]`
(`runtime/circle_commit_epoch.m`), heterogeneous commit publishes `@[arena]`
(`runtime/merkle_epochs.m`), and generic Poseidon commitment publishes
`@[staging]` (`runtime/lifecycle_and_tree.m`). Their per-column maps retain
actual offsets, including the wide offset format; columns need not be packed
contiguously. The typed adapter references placement-local PP/main/interaction
columns. There is no demonstrated need to replace this with a per-column Metal
argument buffer for the current route.

This is a source-derived property, not a license to assume that a logical tree
always means one physical buffer. Reuse
`runtime.m:stwo_zig_polynomial_input_column`, which returns the actual resident
buffer and word offset without uploading a host slice. For each dispatch,
require all coordinates selecting the same shader tree to resolve to the same
`MTLBuffer`; check runtime ownership, source-coordinate association and
`offset + evaluation_rows` within that buffer using checked wide arithmetic.
Reject a mismatch before dispatch. Uploading the small offset/parameter tables
is sufficient; do not repack trace columns.

**Degree expansion is a separate boundary.** The q193 PCS blowup is one bit;
a component's quotient may require more. Existing
`composition_domain_scratch.OwnedV1` evaluates retained coefficients onto the
exact wider domain and admits one evaluation log per owner. It rejects mixed
logs with `MixedCompositionDomainScratchLogSizes`. Group genuine expansion
requests by evaluation log and retain those owners through their dispatches;
do not relabel committed evaluations, enlarge every component to the largest
domain, or repeat expansion merely to force a convenient buffer shape. If a
component's references within one logical tree mix original resident and
scratch buffers, the initial ABI must reject it. Only a demonstrated active
case should trigger an argument-buffer extension. The existing scratch owner
also fills coefficient/zero ranges on the host before its GPU transform; this
remains visible bulk work for the later full strict gate.

Production acceptance for this integration is an authenticated AOT kernel
executing actual exported leaf/parent components against their proof-owned
resident columns, matching the original CPU component evaluator and completing
fresh verification. The following full strict gate must still cover the
separate witness, closure, interaction and FRI obligations listed above.
