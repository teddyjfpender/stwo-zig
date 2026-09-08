# Bounded RISC-V proving-stack reset

## Outcome

Make native RISC-V proving cost explainable and its complete-proof development
loop small, reproducible and representative before expanding Ethereum production.
Preserve checkpoint `87a3965f`; resume the existing unified block-to-root goal when
this bounded reset passes. No whole-block or large retained-wrapper producer is currently queued.

This is ordinary proving-stack development. Maintained code belongs in `src/`,
operational checks and report tools in `scripts/`, and development guidance here
or beside the owning library. Retained measurements live under
`vectors/reports/riscv-proving-stack-reset-20260908/`. `autoresearch/` contains
historical evidence only and is not a source dependency for this work.

The immediate recursive feedback loop uses the smallest existing real RISC-V
child, then an actual recursive AIR proof. First complete serialization,
outer-producer destruction and fresh decode/verification on that route; measure
preparation, proving, publication and verification separately before expanding
the workload. Its current verifier still requires admitted native-child data;
that is a distinct boundary from the detached Ethereum key-and-proof root.

## Baseline and limits

- Retained Metal segment19: 2,097,152 cycles; proving351.929739s,
  composition259.335809s, producer387.470817s, full request544.138102s.
  Composition is73.69% of proving. Semantic/lookup GPU batches86.391/18.585ms
  describe only device intervals, not the enclosing composition wall time.
- Peak producer footprint31,859,924,488B; source columns10,704,092,792B;
  retained-LDE lower bound21,408,185,584B. Source/LDE estimates exclude major
  temporary and commitment storage and are not process RSS.
- Accepted CPU wrapper3 complete request3323.982147s, final STARK phase1034.602076s,
  peak44,456,659,856B. Fresh independent verification111.247917ms.
  Wrapping is a separate recursive-verifier workload, not native instruction throughput.
- Prior retained preparation replay:1623.176s to305.264s; complete request4357.108s
  to1204.295s. Compilation about105s, not materially improved.
- These are individual retained results, not current CSP A/B or multi-block medians.

Native baseline source evidence:
`../../autoresearch/notes/2026-09-05-pr198-local-ethereum-plan/progress.md` and the pinned local campaign
`.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/metal-field5-block-v2/attempts/leaf-000019-0000/`.
Wrapper acceptance is committed under the existing plan's
`../../vectors/reports/riscv-proving-stack-reset-20260908/2026-09-08-wrapper3-complete-lifecycle/`.

## Ordered gates

1. **Native attribution.** Reuse the exact retained segment and profile. Preserve
   the ordinary scheduler while collecting opt-in per-component host timings,
   device intervals, preparation, joins and final reduction. Reconcile wall
   intervals without summing overlapping worker/device times. Identify all costs
   above5% of composition wall time and explicitly report any remaining residual.
   Associate large allocations with owners/geometry; distinguish measured process
   peak, simultaneous live allocation estimates and cumulative allocated bytes.
   Do not infer the dominant component from GPU dispatch counts.
2. **Representative workload ladder.** Reuse existing complete proof fixtures for
   instruction execution, growing mutable memory, lookup/precompile use and
   continuation. Vary size geometrically and record rows, columns, operations,
   preparation/proving/verification time and peak footprint. Include retained
   real input features that previously exposed geometry or ownership failures.
   Each selected supported route serializes, destroys producer ownership, and
   freshly verifies expected statements. Structural tests alone do not pass.
3. **Boundaries.** Execution owns finalized witness data; AIR owns constraints and
   authenticated layout; backends consume admitted execution plans; orchestration
   owns artifacts/scheduling. Select changes from measured repeated validation,
   dependency fan-out or allocation lifetime evidence. Local reads must not
   trigger upstream audits. Keep ingress/finalization/fresh verification checks.
   Remove superseded routes only after replacement passes complete proofs.
4. **Scaling repair.** Fix the highest complete-request saving per implementation
   effort supported by attribution. Demonstrate the change on its small complete
   reproducer and retained native segment. Run the existing16-case CPU/Metal CSP
   A/B suite with unchanged protocol identities and worker policy; per-case
   reproducible latency/memory regression blocks promotion. No arbitrary90/99%
   target is an acceptance claim. Capture before/after build and runtime costs.
5. **Return to delivery.** Publish runnable local checks, small complete proof
   command, measured scaling/resource limits and one retained-segment proof with
   fresh verification. Resolve dominant identified problems or record an explicit
   bounded disposition based on evidence. Resume native121-segment delivery and
   the already accepted2/3 wrapper parent without redoing accepted work.

## Required consolidation and removal policy

User clarification: frontend concerns must each have one canonical source of
truth, and obsolete code/routes must be removed as replacements pass. This is
an acceptance requirement throughout the reset, not optional later cleanup.

- Instruction/extension identities, encodings and admitted semantics have named
  shared definitions. Runner, AIR and tooling consume those definitions;
  independent ISA/reference checks remain independent correctness evidence.
- AIR constraints, lookup ordering/batches, column and row layouts, public claims,
  transcript order and profile admission each have one owning definition.
  CPU, Metal, native and recursive consumers derive their plans from it; an
  optimization must not introduce another hand-maintained protocol description.
- Backend execution strategies may differ. Their field operations, index maps,
  layout bindings and outputs must match the shared admitted AIR and complete
  proof gate. A benchmark flag is never a second protocol authority.
- New focused proof checks reuse canonical ELF construction, production artifact
  codecs and verification. Remove older duplicate helpers/forced compilation
  paths when their surviving owner and complete gate are identified and pass.
- Delete superseded implementations, stale exports/build wiring and obsolete
  commands together; update user-facing entry points in the same change. Retain
  versioned protocol readers when real supported artifacts still require them,
  and retain genuine failing input evidence. File count alone is not a reason
  to remove a correctness boundary or independent reference implementation.

Every consolidation records the prior competing owner, surviving authority,
removed callers/routes and the proof/check that establishes replacement coverage.
No unbounded mechanical restructuring campaign precedes the measured Keccak work.

## Development and resource policy

Local semantic checks in seconds, representative small complete proofs in tens of
seconds, and measured incremental compilation for a change limited to one library
are targets to verify. Measure cold build, unchanged build and changed-module build
separately. Prefer narrower existing build roots before module extraction.

Use the existing serial heavy-job lock. Only the previously admitted bounded
standalone native verifier has its separate lane. No universal16GiB ceiling;
use actual host budgets and report memory before allocating. No new job on a
live job's observation timeout. Keep source and failing input identities durable.
RV64 remains a separate future frontend/profile; CSP's RV32 path stays intact.

## Current status

- Checkpoints committed; no scaling optimization or CSP performance promotion is claimed.
- Opt-in ordinary-route composition timing implemented in two existing backend
  files. Focused gate passed14/14 in15.96s (compile7s, runtime5s); instrumented
  native producer build110.00s. Reports separate wall phases, host spans, device
  milliseconds and process footprint. Default scheduling/protocol unchanged;
  CSP promotion still pending.
- Existing workload ladder and exact native replay documented. Actual isolated
  native19 diagnostic passed standalone verification with byte-identical proof.
  Keccak AIR took278.718s:89.39% of311.786s composition and67.86% of410.730s
  proving. Complete request531.174s; separate verification64.651s. This is
  attribution, not an A/B speedup. Peak31,878,078,080B. Retained evidence under `../../vectors/reports/riscv-proving-stack-reset-20260908/`; no speedup claimed.
- Small CLI branch and memory-copy lifecycle passed2/2 in1.573s after91.59s
  product build. Keccak1/4/16-call lifecycle passed3/3 in15s runtime; each
  serializes, destroys producer allocations and freshly verifies using the
  production codec. Development PCS only; see `workload-ladder.md` and evidence.
- Removed the duplicate170-line omitted-route instantiation test, its forced
  general-proof-root import and two build targets. Unique admission/default
  assertions now live in the existing dedicated route gate:6/6 passed in30.264s;
  affected general zero-family full proof1/1 passed in86.111s. This reduces
  duplicate compilation ownership; no controlled build-speed A/B is claimed.
  Evidence: `../../vectors/reports/riscv-proving-stack-reset-20260908/omitted-route-consolidation-v1/`.
- `frontend-authority.md` identifies remaining active overlap in relation schemas,
  Ethereum challenge projections, infrastructure geometry and Keccak mask
  projection. Native and recursive Keccak row order now has one shared evaluator. These are consolidation work, not a claim of completed repository-wide
  cleanup. Independent oracles and supported versioned readers remain required.
- Small recursive lifecycle now passes: one real native step,39 outer components,
 47 domains, serialization, outer producer destruction, fresh decode/verification
 and truncated/trailing-byte rejection. Whole executable13s; warm request16.87s;
 outer transaction3.872s; inner STARK verification6.475ms. Native-child admission
 is still required by this verifier. See `workload-ladder.md` for scope and phases.
- Local scalar check4.48s first /3.21s warm; recursive compiler check17.64s first
 /3.91s warm. Optimized incremental compilation and large-input allocation-owner
 attribution remain open. Broader CSP preservation and detached-root work remain.
- Native21/121, accepted ordinary wrappers2/3, no actual parent or whole-block root.

## First diagnostic conclusion

The active Ethereum Keccak shard has no Metal composition capability or parallel
CPU evaluator. Its eval_log19 gives524,288 rows; each row includes1,041 LogUp
pair constraints. One component accounts for the dominant measured time. Build
a small complete-RV Keccak reproducer from existing guest/proof helpers before
changing this evaluator or its backend capability. Keep the ordinary protected
CSP suite distinct from separate historical precompile workloads; verify their
actual execution routes rather than infer coverage from a benchmark name.

Process memory snapshots do not establish allocation ownership: that portion of
the first gate remains open. The known time concentration is sufficient to select
the small reproducer; no instruction-frontend replacement is justified by this run.


## Current small-recursion checkpoint and next boundary

The small complete recursive lifecycle is working. Three paired CPU development
measurements reduce median outer verification from 1.310 s to 0.623 s and the
complete outer transaction from 3.946 s to 2.474 s through synchronous admission
and closure deduplication. See `workload-ladder.md` for nested timing boundaries,
unchanged proof size/memory, correctness gates and retained source evidence.
This is a local measured optimization; CSP promotion and real-block scaling
remain open.

The next larger ownership improvement must address actual borrowed V 2 state,
not add a validation flag. The VM row 18 operational source still borrows
preprocessing rows, schedule values and profile/digest metadata. An owned
projection must copy those values and route every operational consumer through
it, retaining explicit cold comparison with the original native capture.
Existing `PreparedInputsV 4` already owns several other needed inputs, but its
presence also selects V 4 interaction generation. Separate ownership readiness
from profile/algorithm selection before extending it to V 2; preserve V 2 queries,
claims, row 18 tuples, transcript identity and zero-denominator rejection.

Acceptance includes mutation and destruction of original source data: owned
operational results must stay identical, while explicit source audits reject
changed inputs. Cover allocation failure and actual serialized proof verification.
Core ownership alone will not eliminate noncore validation's descent into the
prepared native leaf, so measure both owners before attributing all remaining
time to one. This is the next bounded design task, not a completed ownership
migration or evidence of an orders-of-magnitude whole-prover gain.
