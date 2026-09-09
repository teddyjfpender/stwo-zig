# Strict Metal proving: ownership and acceptance contract

This is a source-derived inventory of the supported four-segment route as of
2026-09-09. The existing Metal proofs are correct under their admitted
experimental profile and use GPU kernels, but substantial prover computation
still runs on the CPU. Strict execution guards, recursive composition export
and production AOT/resident execution of the typed recursive framework now
pass the small complete-tree gate. Provider composition and bulk witness work
remain on the host; this does not establish full strict execution.

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
| Parent main rows, compact Poseidon and exact tuple closure | `integrations/riscv_cpu/recursive_segment_v2_detached_parent_cohort.zig`, `recursive_compact_tuple_ledger_v1.zig`; `frontends/riscv/air/memory_commitment/poseidon2_universal_degree3_v1.zig` | CPU in `finalizeMainInto`, including provider rows, range multiplicities and ledger | `parent.main_finalize`; logical-row and provider geometry | Device witness generation and an exact closure implementation with authenticated row/use counts. Avoid repeating the closure ledger upstream. |
| Recursive lookup interactions | `frontends/riscv/recursion/air/framework_interaction.zig`; leaf/parent cohort `fillInteractionInto` | CPU relation evaluation, batch inversion, cumulative scan and bit-reversed scatter | `parent.interaction_fill`; `metal_relation_epoch` exists for other clients | Export this framework's exact equations and parameter bindings; device relation evaluation, inversion and scan. Existing generic LogUp kernels are not proof of matching recurrence. |
| Preprocessed rows and trace storage | Leaf/parent cohort; `integrations/riscv_cpu/recursive_segment_v2_outer_engine_storage.zig` | CPU filling; backend storage/commit mixed | Fixed/preprocessed timings, allocator counters, commit arena alias/upload counters | Immutable prepared/preprocessed ownership and reuse; account for every expanded column, allocation and upload. Cache keys must bind exact admitted profile and geometry. |
| Circle interpolation, evaluation and LDE | `backends/metal/commit_backend.zig`; `runtime/combined_commit.zig`, `runtime/heterogeneous_commit.zig` | GPU supported; domain log-size below 3 has host primitive branches | `metal_circle_transform_dispatch`, `metal_circle_lde_dispatch`; `cpu_small_circle_*` | Device coverage or fail-closed handling for small domains, zero/constant fast paths and all physical slabs. Report host source copies separately. |
| Merkle commitments, including Poseidon | `backends/metal/commit_backend.zig`, `runtime/circle_commit_epoch.m`, commit runtimes | GPU resident paths; small/streaming/unsupported paths can use host hashing | `metal_poseidon2_merkle_commit`, resident commits, heterogeneous epoch dispatch/wait counts; `host_merkle_commit` | Require exact tree/leaf/parent-row coverage and authenticated hash-family kernel. A Poseidon commitment counter says nothing about Poseidon AIR witness generation or composition. |
| Native composition | `backends/metal/runtime/base_polynomial_composition.zig`; `prover/air/component_prover.zig` | Mixed: admitted semantic/lookup batches GPU; other components host; cost crossover can retain small components on host | Eligible component counts plus completed `metal_riscv_*_batch_dispatch`; host component accounting | Cover every component and all random-coefficient ranges; strict mode must reject host placement even when it was never considered a fallback. |
| Leaf/parent recursive composition | Shared AIR catalogs under `frontends/riscv/recursion/air/`; `runtime/framework_polynomial_jobs.zig`, `framework_polynomial_batch.zig` and existing scheduler | Production AOT GPU execution for 37/39 leaf and 29/31 parent components; two providers remain host | `metal_framework_polynomial_dispatch`; resident component/group logs; parent host count is 2 | Compact/legacy universal Poseidon and range providers; GPU coefficient filling during composition-domain expansion. |
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

## Production framework composition checkpoint

The separate `recursive_framework_v1` AOT profile contains 41 kernels generated
from the exact shared leaf and parent typed AIR catalogs. Native integration
consumes those same catalogs. The maintained source gate authenticates every
export, deduplicates equation-identical programs and checks the generated source,
declaration inventory and explicit coverage file. The original core profile
remains unchanged.

`framework_polynomial_jobs.Job` owns the exported program, invocation parameters,
physical column bindings and random-coefficient window. Kernel identity hashes
canonical executable equations plus emitter/helper identity; relocating columns
changes admission identity without needlessly generating another kernel. Runtime
parameters and statement-dependent values remain checked invocation inputs.

Production dispatch resolves pipelines only from the admitted AOT roster. It
checks runtime ownership, exact logical tree selection, resident extents and
parameter windows before submission, binding existing tree buffers directly.
Small offset/parameter tables are uploaded; trace columns are not repacked by
this dispatch. Additive writers use barriers and existing per-domain buckets.

The active geometry needs composition domains larger than some commitments.
`framework_polynomial_batch` groups work by evaluation size and closes expansion
over every referenced column in a logical tree, including already-sized columns,
so one logical tree resolves to one resident buffer. It evaluates retained
coefficients on the exact domain and borrows the existing twiddle subtree.
Coefficient filling still performs host work and is guarded in strict mode.
Simultaneous legacy scratch ownership and new framework expansion currently
reject with `MixedFrameworkCompositionScratch`; this is an explicit unsupported
mixed graph, not an alternate evaluation path.

### Passed gates

- Isolated generated-kernel device parity: 108 cases, 144 dispatches and
  29,568 checked coordinates across four kernel shapes.
- Actual exported arithmetic AIR through production AOT and resident committed
  buffers: two additive dispatches, all 64 coordinates equal native evaluation,
  six invalid binding/parameter cases rejected without output mutation.
- Full four-segment production with CPU composition parity enabled: 136 fresh
  positive/negative verifier cases pass; all 21 serialized proof/key/claim
  artifacts equal the retained baseline. Leaf wrappers dispatch 37 framework
  components; parents dispatch 29, retaining two host provider components.
- Mixed-domain scratch, borrowed twiddle views and explicit AOT profile routing
  have focused regression checks. Source regeneration must reproduce the exact
  checked-in extension.

The leaf receipt's legacy `composition_dispatches` counts the old semantic and
lookup batches only; it can be zero while framework composition runs on Metal.
The new framework event contributes to total dispatches and has a separate
telemetry counter and resident component/group log. Until the leaf receipt
exports that counter explicitly, use these positive framework logs and the
admitted coverage roster together; the legacy zero is not a coverage verdict.

Commands, executable/bundle pins, retained failures and complete-tree observations
are recorded in [the resident checkpoint](../../vectors/reports/riscv-proving-stack-reset-20260908/framework-resident-v1/README.md).
The CPU parity run intentionally repeats computation and is not a performance
measurement. Full strict acceptance still requires every operation in the
inventory above.

### Next provider boundary

The remaining Poseidon and range providers use independent per-batch running
sums and claims. They cannot consume the framework's same-row-prefix recurrence.
Legacy universal Poseidon already exports its direct and lookup equations;
its direct kernels need AOT coverage before enabling that capability. Compact
universal Poseidon should generalize the existing native-evaluator-backed
exporter. The range provider needs mapped preprocessing/main inputs and zero
direct roots, with its exact independent-prefix relation preserved. Reuse the
existing authenticated range relation plan and native recurrence; do not add
fake direct constraints or silently reinterpret a lookup layout.
