# Compact sampled-value scheduling

The compact PCS drops column LDE values after committing while retaining native
coefficients. `largestTreeIndex` previously estimated work with `values.len`.
Large compact MAIN/INTER trees therefore scored zero, so only the wrong tree
received inner coefficient parallelism. The other expensive trees ran on one
worker each. The work estimate now uses retained coefficient lengths and sample
counts; ties and output ordering remain deterministic.

The coefficient-only host route reuses the existing cooperative work queue and
the proof's existing scoped pool. One tree owns planning/basis scratch at a
time; every admitted worker helps its disjoint native-width column batches.
Neither split-basis nor counted/full-basis kernels acquire a second lease or
publish nested batches. The wave joins before scratch or coefficients can be
released. Worker failure is observed only after all admitted jobs drain. A
fully held pool falls back to a live one-thread wave without creating a pool.

The scheduler does not change coefficient arithmetic, tree/column/sample output
slots, the transcript, shape or proof protocol. Backend coefficient dispatch and
mixed barycentric paths retain their earlier authority. No FFT expansion cache,
per-column full-domain cache or global worker pool is added. The existing
split-product basis is shared per plan/point, not rebuilt for each leaf job.
Planning admits only one tree, so simultaneous planning/basis scratch does not
multiply across trees. Immutable coefficient storage remains live for the same
later quotient/opening obligations as before.

`STWO_ZIG_LEGACY_SAMPLED_TREE_SCHEDULE=1` restores the old tree scheduler and old
work estimate for exact same-binary A/B runs. `STWO_ZIG_PROFILE_SAMPLED_QUEUE=1`
prints leased threads, trees and split-task counts; this is telemetry only.

## Qualification

The focused PCS sampled-value suite passes33 tests in ReleaseSafe and
ReleaseFast. New tests cover real compact owners, multiple tree heights,
ragged columns, zero polynomials, empty/multiple sample masks, point lifting,
exact-work capture, one/two/seven-worker pools and fully held leases. An
injected failed item still joins all other disjoint leaf slots and restores
pool availability. Existing allocation/shape cleanup tests remain enabled.

A same-binary prefix A/B on four real CPU shards and three service truths
produced byte-identical eleven artifacts, including all seven proofs. Separate
fresh receivers accepted both. Debug dispatch confirmed all four PCS trees
retain coefficients, so the new queue actually ran on every proof. Eight
existing workers were admitted; one CPU proof published28 batches/280 tasks.

| Prefix metric | Legacy schedule | Cooperative coefficient wave |
|---|---:|---:|
| Summed sampled evaluation |0.815s|0.550s|
| Sampled lane user CPU |1.703s|1.843s|
| Effective sampled lane cores |2.09|3.35|
| Sampled lane system CPU |0.0073s|0.0230s|
| Whole-process wall |19.24s|18.65s|
| Driver proving interval |14.26s|14.40s|
| Maximum RSS |22.316GB|22.315GB|
| Whole-process system CPU |8.312s|8.277s|

This is a single engineering pair, not a controlled whole-block speed claim.
The stage improved1.48x while the complete proving interval did not improve;
full integration measurements must determine the wall-time effect. Whole-
process stage fault snapshots overlap between lanes and must not be summed as
an attributed per-stage fault total. The receipt preserves whole-process
faults and individual per-proof usage separately.

The stage still averages3.35 of8 cores. Serial plan construction/zero scans,
small column groups and basis construction remain candidates for measurement;
this change does not claim saturation. Security remains the nominal96 control
for this qualification. No128-bit whole-protocol or GPU qualification follows.
Exact logs, source hashes, artifact hashes and fresh receipts are recorded in
`vectors/reports/rv64-word16-execution-20261101/sampled-value-queue-v1.json`.
