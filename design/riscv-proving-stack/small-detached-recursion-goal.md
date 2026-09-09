# Small detached recursion and measured scaling

Work window: 2026-09-08 18:27:59 UTC through 2026-09-09 06:27:59 UTC.
The user authorized sustained implementation, optimization and repository cleanup
through this window, followed by the next larger useful proving milestone once
the initial sequence works. This document records acceptance; a passing subset
does not close the full goal.

## Current checkpoint, 2026-09-09

Items1 and2 have complete development-proof evidence. The version2 parent binds
436 public words, including session and endpoint lineage, under explicit root or
intermediate admission. Item3 is partially complete: actual2/4/8-segment jobs now
produce freshly verified CPU/Metal native children and detached wrappers; the
four/eight-segment jobs additionally have2/4 freshly verified intermediate STARKs.
The next required result is one root proving verification of those intermediate
proofs, then the complete8→4→2→1 tree. A collection of intermediate proofs does
not complete that milestone.

The execution-only ladder runs in under a second and compiles in7s. Initial leaf
production observations are7.73/15.24/30.45s on CPU and6.95/12.17/24.93s with Metal
native proving, excluding aggregation. Intermediate parents take3.85–3.90s each;
core verification takes10–11ms. Current evidence includes336 fresh child cases,
150 partial-parent cases and a25-case Metal-origin partial-parent lifecycle.
These are development-profile observations; production-security measurement,
optimization of the measured whole tree and formal CSP promotion remain open.

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
4. Continue into larger recursive proving and measured optimization as the
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
