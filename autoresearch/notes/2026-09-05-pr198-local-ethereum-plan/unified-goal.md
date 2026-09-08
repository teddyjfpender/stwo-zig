# Unified goal: finish real Ethereum block proving end to end

## Outcome and priority

Deliver a reproducible real Ethereum block benchmark using our RV32 frontend on
Mac CPU and Metal. Prove every core and provider shard, serialize the complete
block bundle, and independently verify its execution statement, exact coverage
and continuation. Then produce one independently verifiable succinct block root
whose AIR verifies actual child proofs. Compare equivalent endpoints with local
Zisk, preserving CSP performance and protocol identities throughout.

**Implementation order: verified native block bundle → verified recursive block
root → deeper optimization.** Publish the first backend's accepted bundle and
runnable benchmark as an intermediate delivery; finish the other backend and
final-root comparison without waiting for a speedup target.

A slow, correct complete result is the baseline we need. A further 90% reduction
and the broader 99% ambition are optimization targets, never acceptance conditions
for that first result. Progress means independently accepted proof artifacts
advancing this sequence. Compilation, component tests, new abstractions and
isolated speedups support delivery; they do not substitute for it.

This document owns implementation order and acceptance criteria. Keep current
results, exact commands, timings, failures and artifact identities in the
[progress record](progress.md); the original [plan](note.md) is historical context.
Reuse accepted work rather than restarting an older checklist.

## Current priority: bounded RISC-V proving-stack reset — 2026-09-08

The user explicitly paused expansion of native whole-block and recursive proving
in favor of the [bounded proving-stack reset](../2026-09-08-riscv-proving-stack-reset/plan.md).
This supersedes the delivery-first decision rule and optimization stop rule below
**until the reset acceptance criteria pass**. The block bundle, recursive root,
CPU/Metal benchmark, CSP preservation and equivalent local Zisk endpoint remain
the ultimate outcome. Do not widen shared RV32 types or replace the instruction
frontend without evidence that it is the limiting cost.

Checkpoint `87a3965f` preserves 21/121 accepted Metal native segments, accepted
ordinary wrappers 2/3, retained failures and preparation ownership repairs.
The actual parent request is prepared but unlaunched. The prior preparation
detour passed its consuming wrapper3 proof and ten-case independent verification;
preparation improved from 27.1 to 5.1 minutes on the retained replay, but the
remaining feedback cost warrants this separately authorized reset.

Implementation order now:

1. Attribute one retained native segment's composition time and memory to actual
   components and operations, distinguishing CPU/GPU preparation, execution and waits.
2. Establish a small complete-proof workload ladder that exercises instruction,
   mutable-memory, lookup/precompile and continuation scaling.
3. Enforce execution/witness, AIR, backend and orchestration ownership boundaries
   where they eliminate demonstrated coupling, repeated work or compilation cost.
4. Repair the measured dominant scaling problems; validate on the small reproducer
   and retained native segment, with unchanged security and CSP A/B preservation.
5. Resume the delivery queue below with predictable resource use and proof checks
   that expose failures before hour-long production runs.

Use existing libraries and harnesses first. No mechanical file-splitting campaign,
new generic orchestration framework, unconditional cache or repeated full wrapper
run is a prerequisite. Record actual evidence and missing coverage in the reset
plan and progress record. Targets of seconds for local checks and tens of seconds
for a small complete proof are targets, not claims or reasons to weaken checks.

## Delivery queue after the reset

1. **Finish the running native campaign.** Keep producing and freshly verifying
   its remaining segments with the accepted implementation. As soon as all are
   available, run independent whole-block verification and deliver the bundle,
   receipt and reproducible benchmark command. Do not wait for recursion or a
   faster leaf to publish this result.
2. **Unblock one real ordinary wrapper, then consume it.** Limit prerequisite
   work to the observed failure preventing wrapper 2 from completing. Test the
   repaired route with the small complete-proof command, then run the real
   wrapper. Freshly verify it, produce compatible wrapper 3, and prove their
   actual parent before undertaking any broader recursive redesign.
3. **Carry that working composition to the block root.** Complete actual initial
   and terminal admission, wrap the remaining segments, aggregate all of them,
   and independently verify the final root. A working ordinary pair is an
   intermediate artifact, not permission to leave the boundary cases unfinished.
4. **Complete the comparison and promotion gates.** Finish both CPU and Metal
   results, equivalent local Zisk endpoints and CSP preservation. Then optimize
   the complete route against its measured baseline.

Maintain two tracks: native campaign delivery and recursive completion. Each has
one next proof artifact and at most one active integration blocker. Parallel work
must unblock one of these artifacts; do not open a third optimization or redesign
track. Shared changes must not force compatible accepted artifacts to be reproduced.

**Schedule proof delivery explicitly.** Heavy jobs share the existing lock, one
at a time. Fresh verification of a completed candidate comes before another
expensive production attempt. Reserve the next required wrapper/parent slot
alongside native production; neither track may be indefinitely displaced by
compilation or diagnostics. Optional work never displaces an admitted producer
or required verifier. Reuse accepted binaries and frozen builds.

The next recursive queue is **wrapper 2 acceptance → wrapper 3 geometry check →
wrapper 3 acceptance → actual parent acceptance**. Source changes and small tests
feed this queue; they are not additional milestones. Complete the ordinary parent
before expanding the recursive design. Carry the accepted composition through
the mandatory initial/terminal cases and all segments to the block root.

## Optimization stop rule

The initial two choices are **narrow Poseidon AIR** and **removing repeated
fixed-program hashing**. The initial optimization allowance is spent. Use their
accepted, pinned implementation, complete only its required acceptance checks,
and advance. Do not search for two more optimizations or keep refining these to
reach 90%. If a compatible, already admitted route works, its disappointing
performance is not a reason to delay production.

Any unfinished acceptance work gets one focused implementation and end-to-end
measurement pass. Keep a verified useful improvement regardless of percentage;
otherwise retain the failure and use the last accepted compatible implementation
where available. Neither optimization becomes a new dependency for a functioning
route. A disappointing percentage or an attractive new idea does not extend the
allowance. Rank later speedups by complete-request savings versus implementation
effort, not by an isolated component's share.

Before the bundle and root pass, another performance change is allowed only when
a demonstrated resource failure prevents the next required proof from completing.
Retain the failure, identify the limiting phase, and make the smallest sufficient
fix. A memory estimate is a preflight warning; distinguish it from measured peak
memory and an observed failure. Do not repeat a failed expensive run unchanged.
There is no universal 16 GiB ceiling: use explicit host-appropriate budgets and
retain a practical serial route for this laptop and other laptops.

A resource repair must name the blocked proof, retained failure, one hypothesis,
smallest sufficient fix and complete-proof acceptance command. Once the repair
and consuming proof pass, stop tuning that phase. Failure requires a changed
diagnosis or admitted fallback, not an open-ended performance project. Distinguish
an unexplained process kill from a confirmed memory failure.

Correctness repairs remain mandatory. Never weaken security, statement binding,
exact lookup closure or independent verification to shorten the route.

## Delivery sequence and acceptance gates

| Order | Deliverable | Acceptance evidence |
| --- | --- | --- |
| 1 | One complete native block bundle on the first backend | All 121 segment proofs, every provider shard, and fresh-process whole-block verification against the expected statement. |
| Alongside 1 | Real ordinary wrappers 2 and 3 | Each serialized, producer destroyed, independently verified under compatible admitted geometry. |
| 2 | Parent of those actual sibling wrappers | AIR verifies both child proofs; serialized parent freshly verifies and substituted children are rejected. |
| 3 | Initial and terminal wrappers, then the complete recursive block root | Actual segments 0 and 120 accepted; aggregation covers every segment; one root verifies independently. |
| 4 | Complete benchmark delivery | CPU and Metal block evidence, root evidence, CSP preservation, reproducible commands and equivalent local Zisk comparisons. |
| After delivery | Further optimization and five-block corpus | Improvements measured against the accepted complete route; unsuccessful experiments closed promptly. |

### 1. Finish the native block campaign

Continue the explicit retained 121-segment campaign with one leaf in flight.
Use accepted real CPU/Metal leaf evidence and the resumable controller. Recover
identity-matching successful candidates and freshly verify them instead of
reproving them. Do not restart a campaign to adopt an optional speed improvement.
If a correctness or resource blocker requires a new admitted product/profile,
make migration explicit and import only independently reverified compatible
artifacts; preserve their original production receipts.

The deliverable is a manifest, every referenced proof, and a successful independent
whole-block verification receipt. Worker success or a running controller is not
whole-block acceptance. The verifier must reject missing, duplicate, reordered
or substituted segments, incorrect global positions, broken continuation and
incorrect initial/terminal conditions. It must bind the required Ethereum
execution semantics and expected public output, not merely a reported block hash.
Resume must reject mixed input, program, profile or campaign identities.

Report complete block wall time, preparation, proving, fresh verification, proof
sizes and measured peak memory. Distinguish cold setup from amortized preparation,
queue waits from compute time, and a resumed campaign from an uninterrupted
benchmark. Deliver the first accepted backend promptly; recursion is not a
prerequisite for native bundle production.

### 2. Make the real wrapper and its first parent work

Reuse the smallest complete-proof development command and shared native/recursive
protocol definitions. Advance through real wrappers **2 and 3**, using retained
native contexts **2/3 and 3/4**, then their actual sibling parent immediately.
Check admitted child geometry compatibility before paying for the second proof.
Pair 1/2 is diagnostic evidence; do not produce an unused wrapper 1 or relabel
positions to make nonsiblings fit the aggregation schedule.

For each wrapper, require authenticated dynamic statement and boundary inputs,
global block position, continuation, full-program identity, active field
transcript admission, typed AIR checks and exact lookup closure. Keep fixed
circuit structure in explicit versioned admission; proof-dependent values enter
through authenticated relations. Native and recursive paths consume the same
transcript ordering, claim layouts, provider windows and commitment policy.

The acceptance command must prove, serialize, destroy producer state and verify
in a fresh process using independently admitted key and expected public inputs.
Retain wrong-key, changed-profile, altered-statement/boundary and corrupted-proof
cases. Crashes, resource errors and unrelated failures do not count as successful
tamper rejections. A fixture pass leads directly to its real proof; it does not
finish this gate.

The next artifact is the parent of those two actual proofs. Require child-proof
verification in the AIR, including the relevant transcript, commitment, FRI and
composition checks. Serialize the parent, destroy producers, freshly verify it
and reject substituted children. Host-side child verification, an aggregation
adapter or a circuit estimate does not meet this gate. Generalize the working
composition only after this concrete parent passes.

### 3. Finish initial/terminal admission and whole-block recursion

Complete the actual initial segment 0 and terminal segment 120 wrappers. Segment
0 has 675,173 public input words: this requires an explicit scalable admission
route, not simply higher caps on a quadratic graph. Authenticate every input's
value, position, memory contribution and commitment through the shared protocol,
with exact closure. Preserve existing defaults. Initial and terminal work may
proceed alongside the ordinary pair, but cannot postpone its first parent.

Apply the accepted fold across all real-leaf wrappers. Authenticate child
key/profile admission, public claims, exact coverage and continuation at every
boundary. Handle different admitted initial/ordinary/terminal shapes explicitly.

Accept this milestone only when one serialized block root verifies independently
against its admitted key and expected public statement after producers are gone.
The final verifier must not need native proofs, witnesses or controller state.
Retain rejection evidence for changed children, keys, coverage and continuation.
Measure aggregation and final verification separately and include both in the
complete block-to-root request. Report bundle and succinct-root endpoints separately.

### 4. Deliver the benchmark and preservation evidence

Complete outstanding CPU and Metal campaigns and document commands that reproduce
accepted proof production and independent verification. Pin source, binaries,
inputs, program, profile, campaign, proof hashes and worker policy. Record actual
hardware and backend placement; distinguish measured results from estimates.

Run the existing **16-case CPU/Metal CSP A/B suite** with unchanged protocol
identities, defaults, RV32 execution and worker policy. Check latency and memory
per case. A reproducible regression blocks promotion; aggregate Ethereum gains
cannot hide it. Run targeted preservation checks when shared code changes and
the full suite before promotion. Keep RV64 a separate future frontend/profile.

Compare local Zisk only at explicitly matched execution statements, security
parameters and proof endpoints. Include preparation, required proving/aggregation
and verification; disclose exclusions, amortization and variability. A native
bundle comparison cannot stand in for the equivalent final-proof comparison.

### 5. Optimize the functioning route

After the bundle and root pass, rank measured bottlenecks by expected complete
request savings relative to implementation effort. Take the strongest two
concrete candidates per iteration. Give each one bounded implementation and
measurement pass; accept an evidenced improvement or close the unsuccessful
experiment. Do not keep digging to satisfy a required percentage.

Explicit follow-ups include the historical 37.6-second capture admission and
69-second verifier investigation. Separate validation and circuit/Tree0 preparation
from actual transcript, composition, Merkle and FRI verification before attributing
those times to the STARK verifier. Investigate the prior CSP issue without assuming
a common cause. Also measure repeated preparation, retained memory, commitment,
quotient/FRI work and GPU waits. Add concurrency only when measured memory permits
it. Expand to the existing five-block corpus using the accepted route.

Reuse must preserve authenticated immutable ownership and explicit input admission,
mutable-state finalization and proof verification. Retained hostile cases and CSP
gates still apply. Every claimed reduction names its baseline, endpoint, profile,
machine and worker policy; allocation estimates are not end-to-end speedups.

## Rules against expanding the prerequisite list

- Every task names the next real proof it unblocks and its accepting command.
  If it cannot, defer it. Subagents own bounded work across separate files for
  that artifact; integrate ready work before expanding its scope.
- After a focused fix passes, run its complete proof. After acceptance, advance
  to its consumer. Do not broaden the repair or repeat passing checks without
  a relevant change.
- Diagnose one hypothesis at a time. A failed check must change the next action.
  Never repeat an unchanged expensive failure. After two failed real attempts
  at the same boundary, explicitly reassess the route and admitted fallbacks
  before a third; further tuning is not the default.
- Cleanup, compilation work and consolidation before delivery must remove a
  demonstrated blocker to the next proof. Defer general frameworks, mechanical
  file splitting and unrelated improvements.
- Before an expensive job, record its artifact, source/input pins, prerequisites
  and the decision it enables. Afterwards, record acceptance or concrete failure
  before launching another job.
- Keep promising leaf optimizations, verifier speedups and repository improvements
  in an explicit deferred list. Reopen one before delivery only if a retained
  failure demonstrates that it blocks the next required proof.

Each checkpoint reports **independently accepted segments / 121; native bundle
status; accepted real wrappers and parents; root status; next accepting command
and blocker per track**. Separate waiting, compiling, preparing, proving and
verifying. Each track's handoff records its bounded next action and fallback.
If no complete proof was accepted, say so and identify the observed blocker and
next discriminating action. Additional scaffolding is not a milestone.

The first delivery is an independently verified whole-block bundle. This proving
and benchmark goal finishes with that bundle, an independently verified succinct
root, both backend results, CSP preservation and documented equivalent endpoint
comparisons. Further optimization and corpus expansion follow that delivery;
unmet 90%/99% targets cannot postpone it or replace it.
