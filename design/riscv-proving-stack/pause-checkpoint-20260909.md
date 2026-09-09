# Paused checkpoint: strict Metal and small-tree performance

Paused at the user's request on 2026-09-09. The objective in
[strict-metal-goal.md](strict-metal-goal.md) is unchanged and incomplete.
Resume solo unless the user changes their instruction about subagents.

## Last complete-tree result

The provider-resident checkpoint (`a8f1c054`) produced the four-segment hybrid
Metal tree in 61.206 seconds, passing 136 fresh acceptance/rejection cases with
all 21 proof/key/claim artifacts identical to the retained baseline. This is a
227-instruction, one-address fixture, not Ethereum or a production-security
claim. All recursive composition components ran on Metal, but bulk witness,
preparation and interactions remained on CPU. Native composition still had
nine host components in that measured binary.

Do not attribute this complete-tree timing to the newer source checkpoint below.

## New work retained

- **Shared strict scratch admission:** host coefficient filling is rejected at
  the common owner before allocation/runtime access; every composition caller
  uses that boundary. Already committed in `a8f1c054`, with 20 focused tests.
- **Native fixed-table composition:** all six tables now export their existing
  native relation through one native-owned independent-prefix backend program.
  Export tests pass 5/5, including 384 native field-point comparisons, binding
  and challenge rejection, and allocation cleanup. Existing table interaction
  tests pass 226/226. New full native Metal proof dispatch is not yet observed.
- **Device interaction building block:** shared generated fractions plus GPU
  scans produce independent-prefix columns and claims. Its private admitted
  state copies routing/ABI metadata; preparation requires the selected AOT
  profile and all four required exports. Source-compiled device tests cover
  five geometries, independent claims, padding, pole/selector/canonical-input
  rejection, immutable source snapshots, descriptor errors and recovery.
  Final focused backend/codegen gate passes 15/15. This is not yet a real AOT
  interaction run or integration into a proof producer.
- **AOT source catalog:** 61 kernels, including the prior 54 composition kernels
  unchanged plus four table-fraction shapes and three scan kernels. The current
  files match retained generation exactly. Loader/profile admission recognizes
  the new names. No new 61-kernel metallib, matching producer build or real AOT
  interaction gate was completed before the pause.
- **Parent interaction and attribution:** the parent now selects the existing
  chunked batch-inversion writer under the existing worker policy, preserving
  native pole errors. Optional phase timings separate tuple projection, closure
  and typed/provider interaction generation.
- **Selected-lane preparation candidate:** four existing bulk writers can skip
  discarded-lane hashes while retaining their metadata, validation and ordering.
  Writer gates pass 5/5; a genuine retained child compares every old/selected
  PCS view, metadata and provider output in both lanes and passes. Production
  still explicitly selects the old path in `OwnedV1.init`; no complete proof
  with selected-lane production has been run.

## Measurements and what they mean

Three alternating CPU root pairs, each in a fresh process with 28 fresh
acceptance/rejection cases, have request medians of 13.551693 seconds before and
13.483111 seconds after the parent interaction change. Every proof/key/claim
artifact is byte-identical. The approximately 0.5% difference is not a material
performance win. Metal A/B for this change remains pending.

One candidate CPU root attributes 2.121 seconds to source tuple projection,
1.474 seconds to typed interaction generation and only 0.0167 seconds to
Poseidon interaction filling. These are observations, not repeated phase medians.
They put typed interactions and projection ahead of more Poseidon-writer tuning.

The selected-lane retained-child check observes row materialization at
418–427 ms before and 361–362 ms after in its two lanes. It still constructs the
full authority and padded scratch, and six other row families still generate
both lanes. Do not claim elimination of all duplicated preparation or translate
these observations into a complete-proof speedup.

## Resume order

1. Build the current 61-kernel AOT bundle and prove real AOT interaction
   preparation/execution with native table columns/claims, without the test-only
   source compiler. Preserve explicit false pipeline/strict coverage markers.
2. Build matching CPU/Metal producers from frozen source. Repeat fresh root/tree
   gates before attributing new native-table GPU coverage or Metal timings.
3. Activate selected-lane preparation only after its exact-view gates, then
   require a complete proof and artifact parity. Remove the superseded route
   after that gate; retain the independent reference in tests as needed.
4. Implement shared same-row-prefix/normalized typed interactions on Metal,
   preserving authenticated padding and zero-denominator behavior. Independent
   table interactions alone do not address the measured 1.47-second typed phase.
5. Measure one versus two proofs in flight. The present leaf loop and parent
   loop are sequential. Separate elapsed wall time from summed job durations,
   measure aggregate live memory and GPU utilization, and preserve per-proof
   admission/telemetry and fresh verification. The rough 28–30-second ideal
   overlap estimate is not a measured result. No concurrency change was made.
6. Continue remaining witness/preparation/native GPU coverage, immutable reuse,
   targeted formal/security hardening and gradual scaling under the full goal.

## Evidence and known failed attempts

- [Provider/device/source logs](../../vectors/reports/riscv-proving-stack-reset-20260908/provider-resident-v1/)
- [CPU paired root receipts and replay](../../vectors/reports/riscv-proving-stack-reset-20260908/parent-interaction-v1/)
- The first parent CPU binary overlapped a temporary edit to identity-bound
  Poseidon source. It failed `DetachedParentManifestMismatch` immediately and
  is excluded from results. The rebuilt v2 binary passes all six paired gates.
- The initial selected-lane full child check used a continuation statement of
  a different length as its negative fixture (680 versus 676 words). The
  corrected check uses a genuine same-geometry seed14 statement and passes.
- Initial export/device compile failures and corrected logs are retained.
- Formal source correspondence passes unchanged. This checkpoint establishes
  no new whole-prover soundness theorem and does not certify experimental q193.
