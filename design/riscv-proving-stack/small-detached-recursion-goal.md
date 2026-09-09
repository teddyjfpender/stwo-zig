# Small detached recursion and measured scaling

Work window: 2026-09-08 18:27:59 UTC through 2026-09-09 06:27:59 UTC.
The user authorized sustained implementation, optimization and repository cleanup
through this window, followed by the next larger useful proving milestone once
the initial sequence works. This document records acceptance; a passing subset
does not close the full goal.

## Current checkpoint, 2026-09-09

Items 1 and 2 have complete proof evidence. Actual 2/4/8-segment development jobs
produce every native child, detached wrapper, intermediate parent and one root
on CPU or Metal. Each serialized proof verifies in a fresh CPU process after
producer exit. All artifact bytes match across backends. These are small RISC-V
memory workloads; Ethereum block proving has not resumed.

The separately admitted experimental q193 profile now also completes 2/4/8 trees
on CPU and Metal, including every recursive parent. Here q193 means 193 FRI
queries. A stronger profile is not itself production-security certification;
formal production admission remains open. The shared parent statement
authenticates 436 public
words, session and endpoint lineage; existing changed-memory runs reuse complete
admitted keys. Focused capture checks cover all 872 transcript limbs, canonical
field encoding and coherent public-word mutations.

The maintained small-tree controller and exact pinned commands are documented in
[the benchmark guide](small-recursive-benchmark.md#complete-cpu-and-metal-tree-controller).
The first complete development gate takes 10.59/23.69/49.76s on CPU and
7.82/17.81/38.05s on Metal for 2/4/8 segments, including hostile cases.
Native production, wrapper preparation/proving, parent production, root
verification and RSS are recorded separately.

A focused wrapper optimization now has three alternating A/B rounds on both
backends and profiles. Reusing CPU commitment coefficients removes about 98.6%
of sampled-opening time. Median CPU wrapper proving falls 0.978 to 0.619s in the
development profile and 9.999 to 6.396s in q193. The stronger two-child producer
falls 32.554 to 25.364s. All 560 fresh cases pass with unchanged artifact bytes.
Metal already evaluates these openings efficiently on the GPU; retention adds
memory without a wrapper improvement, so its existing policy is preserved.

Earlier parent optimizations retain coefficients and use the shared compact
tuple ledger. The final policy passes all eight complete-tree runs and 1,014 fresh cases.
Expanded phase attribution identified repeated domain-audit arithmetic, addressed
by the shared direct-writer pass below. Maintain the
small complete-proof loop; do not use an Ethereum-sized replay as the development
gate. Formal quiet-host CSP preservation remains open; no CSP default, worker
policy or shared RV32 execution path changes in this wrapper optimization.

The next interaction pass now also has measured savings on both backends.
All 16 native-core components consume the existing typed-AIR direct writer and
its per-domain results. Independent cold replay agrees on all 128 component
comparisons; 560 alternating proof checks preserve exact artifacts. Stronger
wrapper medians improve another 11.4% CPU and 15.7% Metal, with stable memory.
Complete two-child medians are 23.896s CPU and 18.671s Metal. The focused
framework gate runs in 272ms after a six-second compile.

All eight full-tree reruns pass 1,014 fresh cases with identical artifacts.
The subsequent stronger 4/8-segment milestone now also passes on both backends.
Its four-segment producer sums are 127.64s CPU / 102.94s Metal; eight segments
take 279.65s CPU / 228.24s Metal. Each aggregate contains N-1 actual parent proofs.
Final root STARK verification stays at 72–81ms, and peak process RSS remains
about 6.7GiB CPU / 7.1GiB Metal for four and eight segments. These are single
observations, not an A/B promotion claim; device allocation memory remains a
separate measurement obligation. See `q193-complete-ladder-measurements.json`.

Changed initial memory now reuses all seven four-tree and all fifteen eight-tree
keys unchanged; every new proof and statement verifies independently. Both
depths also pass the consuming-AIR mutation check, including all 436 public
words. The deeper cached check runs in three seconds. Genuine weaker segment and
parent proofs are rejected before q193 AIR allocation.

Formal CSP preservation, independent production circuit/security admission and
separate device-memory measurement remain open. Keep the existing per-segment
workload small. Do not
extend leaf optimization indefinitely or substitute development-profile trees
for the separately admitted stronger route.

## Required implementation order

1. Make the current small wrapper independently verifiable. A fresh process
   accepts an independently admitted verification key, expected public statement
   and canonical serialized proof. Child verification and statement binding are
   enforced by the AIR. No native capture, native preparation, producer receipt
   or witness-derived validation flag supplies verifier authority.
2. Prove the continuation as a second child and compose both children into an
   actual recursive proof. Authenticate clocks, memory boundaries and exact
   coverage. Reject altered boundaries, swapped children, gaps and duplicates.
   Exercise native children produced by both CPU and Metal.
3. Measure 2/4/8 segments while keeping individual segments small. Separate leaf,
   aggregation, final verification and process-memory costs. Optimize the largest
   measured contributor. Measure an explicitly admitted production-security
   profile separately from the existing development profile.
4. Prove the complete tree on Metal as explicitly requested: native leaves,
   detached recursive wrappers, every intermediate parent and the final root.
   Reuse the same admitted AIR, transcript and verification keys across CPU and
   Metal; retain independent fresh CPU verification as a cross-backend check.
   Require actual GPU execution evidence for recursion, CPU/Metal proof parity,
   and separate end-to-end 2/4/8-tree timings, phase costs, RSS and device memory.
   Native Metal children with CPU aggregation do not satisfy this milestone.
   Finish the stronger CPU two-child root first, then port that working route.
5. Continue into larger recursive proving and measured optimization as the
   preceding gates permit. Consolidate shared admission/transcript definitions,
   remove superseded routes after replacement proof gates pass, and reduce
   compilation dependencies where measurements justify it. Preserve one owner
   for each frontend/protocol fact and backend-specific execution strategies.

The original requested sequence is the attachment `pasted-text-1.txt` supplied
with the active goal. The list above retains every numbered deliverable and the
additional twelve-hour optimization/cleanup direction.

## Admission and correctness requirements

- A key's structural validation or a prover-supplied hash is not independent key
  admission. Reuse the existing pinned, owned key transport where applicable.
- Classify circuit structure, parameters and preprocessing separately from
  statement values, native claims/challenges, openings and other proof inputs.
  A reusable profile must accept distinct proofs under the same admitted key;
  exporting a witness-specific circuit is insufficient.
- Preserve all 39 small-route components, all auxiliary provider claims and
  the 47-domain relation contract. Ethereum ordinary36/Initial38 catalogs are
  different contracts and cannot be substituted by matching row numbers.
- Claims arrive as untrusted proof data and become authenticated through the
  transcript and STARK constraints. Free audit decompositions or host-only child
  verification cannot establish recursive proof acceptance.
- Each child closes independently before canonical adjacent-span composition;
  cross-child cancellation must not repair an invalid child.
- Producer and native-preparation ownership must be destroyed before the fresh
  verifier runs. Retain genuine failure inputs and canonical serialized artifacts
  so the complete proof gate is reproducible outside the producer process.
- Keep CSP defaults, protocol identities and worker policy unchanged. The
  existing 16-case CPU/Metal A/B check and per-case latency/memory review remain
  required for promotion. A repeated regression blocks it. The prior diagnostic
  passed proof/policy checks but did not meet quiet-host admission.
- Keep RV64 a separately admitted future frontend/profile. No shared RV32
  widening or CSP execution-path change is part of this work.

### Stronger recursive admission boundary

The q193 parent-of-parent review found a shared verifier/transcript route, not a
second protocol implementation. Capture consumes the standalone verifier;
`recursive_segment_v2_detached_prefix.zig` owns admission, claim and interaction
PoW ordering. All 436 parent public words enter canonical split-u16 relations.
Session, endpoint lineage and adjacent spans use the shared continuation rules.

Successful experimental trees do not close production admission. The independent
key hash authenticates the selected bytes; structural key validation does not
certify that Tree0 encodes the intended circuit. Production admission must retain
reproducible fixed-circuit/Tree0 generation and reviewed transitive child pins at
every level. Parent-family construction relies on those child proofs to enforce
child semantics. The configured q193 parameters also need an explicit security
argument covering FRI assumptions, algebraic and lookup error, hash assumptions,
and composition across the admitted depth. `DEVELOPMENT_ONLY` remains true.

For each new experimental tree, require unchanged keys across initial-memory
values, CPU/Metal artifact parity, freshly verified intermediate/root proofs,
and the existing consuming-AIR public-word mutation gate. Retain genuine weak
segment and weak parent inputs that fail a q193 parent before AIR allocation;
mutating a transport header alone does not cover that admission boundary.

### Next bounded optimization candidate

The stronger four-segment root profile isolates one duplicate source projection.
`recursive_segment_v2_detached_parent_cohort.zig` evaluates every logical row's
`relation_plan.preparedEntries` during admission to build only the range counter.
Exact closure later projects the same owned rows again. The existing compact
tuple ledger already owns a source range counter.

A candidate main-finalization operation can append source tuples once, derive
the range batch from that counter, fill provider columns and close the actual
provider/public tuples before commitment. Keep direct-constraint admission,
canonicality, destination/alias checks, provider column agreement and the cold
mutated-main audit. Keep the ledger local to finalization rather than extending
its retained lifetime. This is a candidate, not an implemented improvement.

The entire measured graph-to-prepared snapshot interval is only 1.416s CPU and
1.372s Metal; the removable traversal is a subset of it. Therefore this alone
cannot save more than roughly 5–6% of the root request. Measure preparation plus
finalization together so relocated work cannot masquerade as savings. Larger
reductions require separate evidence about graph construction and exact-ledger
aggregation; do not promise an order-of-magnitude gain from this fusion.

## Starting evidence and immediate boundary

Starting clean checkpoint: `51646b44`. The previous native fixed-cost round has
84 small complete-proof runs, a 19-test semantic gate and a 128-launch CSP
diagnostic; see [its evidence index](../../vectors/reports/riscv-proving-stack-reset-20260908/native-fixed-cost-v1/README.md).
The small wrapper remains native-assisted: the outer engine rebuilds a full
cohort from `PreparedNativeV2LeafOuter` during verification, including interaction
generation, authority identities and host closure audits.

Existing detached Ethereum machinery supplies useful pinned key ownership,
canonical proof transport, typed verifier construction and fold consumers. Its
catalog, field transcript and secure profile differ from the small route and
must remain explicitly admitted. The first implementation seam is a witness-free
39-component factory, followed by fixed/dynamic admission and authenticated
public inputs. The native-assisted route remains a parity oracle until the
detached complete-proof gate replaces its operational role.

## Design references

- [Clement Walter research baseline](../typed-air/notes/2026-08-04-research-baseline.md):
  design provenance, reproduced experiment and limits; compiler reuse is not a
  substitute for soundness or measured trace cost.
- [Typed-AIR architecture](../typed-air/ARCHITECTURE.md): immutable owned IR,
  versioned lowering/layout and component boundaries.
- Typed-AIR ADRs 0039, 0040 and 0041: authenticated auxiliary claims, temporal
  composition and complete physical claim layout. Their recorded proposal or
  acceptance status must be distinguished from actual current implementation.

All maintained implementation stays in `src/`, tools in `scripts/`, guidance in
`design/` and evidence in `vectors/reports/`. Heavy jobs use the existing shared
lock; observing a timeout never authorizes starting a replacement producer.

## Verified progress at the detached-child checkpoint

- Two distinct tiny register statements prove under one identical serialized
  key and verify in fresh processes. Memory digest binding and indexed
  statement-hash calls are active in those proofs.
- Both actual segments of a completed 98-instruction memory workload prove with
  native CPU and native Metal. Their outer proofs, keys and expected public
  words are byte-identical across backends. Fresh bundle verification checks
  complete coverage, sparse memory, boundary clocks and lineage; 17-case gates
  reject swapped, duplicated and missing children as well as proof tampering.
- The shared verifier can record the exact child transcript without native
  preparation. Real-capture parity, caller destruction and complete symbolic
  composition evaluation pass on a retained genuine proof. All 41 claim slots
  and four composition-sample limbs are exercised by rejection checks.
- Shared allocation-failure cleanup is committed as `bc0ed210`. The focused
  allocation sweep and real-proof evidence are retained in the same report.

This does not complete item 2: the succinct temporal parent still needs active
AIR binding of the detached transcript's public wire, derived context/hash
boundaries, claims and openings. That is the next critical-path step. The
2/4/8-segment recursive ladder, production-security profile and formal quiet-host
CSP promotion remain outstanding. Detailed evidence:
[detached-child progress](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/progress.md).

## Verified two-child parent checkpoint, 2026-09-09

The next checkpoint now supersedes the outstanding item2 statement above: two
actual children are verified inside the parent AIR, including transcript,
composition, PCS/FRI, dynamic expected wire, sparse memory and clocks. One
serialized parent STARK is independently verified from its admitted key and
expected root. The child retains its existing39-component protocol; the parent
uses its separately versioned30-active-component cohort and47 relation domains.
Six runs cover three memory values and both CPU/Metal native child backends under
one unchanged parent key. All126 fresh-process parent cases pass. The parent
itself is CPU-proved. The maintained parent gate also exercises producer exit
before verification, with independently pinned inputs and retained negative cases.

Parent requests are3.87–4.06s, verification9.7–11.8ms, with roughly655–656MiB RSS
in these development observations. The complete small route is now the boundary
for further changes; a passing preparation check alone no longer replaces it.

Item3 remains open. The immediate larger-tree seam is an authenticated
intermediate statement retaining session and entry/exit lineage, with explicit
non-root versus whole-root admission. Then capture and recursively verify actual
parent proofs using the shared transcript and PCS/composition machinery. Prove
4→2→1 and8→4→2→1 trees; do not count flat bundles or repeated two-child examples
as that ladder. Measure the production-security profile separately and complete
the unchanged CSP preservation gate before performance promotion.

## Complete CPU and Metal tree checkpoint

The earlier CPU-wrapper limitation is now closed: actual 2/4/8 development trees
prove native children, wrappers and all recursive parents with the selected
backend. Every root freshly verifies on CPU; artifact bytes match across
backends. The separately admitted q193 two-segment full Metal route also passes.
These remain tiny RISC-V fixtures, not Ethereum blocks or production-security
certification. See the [current command and measurements](small-recursive-benchmark.md#complete-cpu-and-metal-tree-controller).

The sampled-opening pass is complete: CPU wrappers improve about 36%, while
Metal retains its lower-memory existing policy. The direct-writer pass also removes a repeated batch inversion from domain
auditing, improving both backends. Stronger 4/8 admission and formal CSP
preservation remain open.
