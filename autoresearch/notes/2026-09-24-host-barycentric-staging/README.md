# Bounded host-column barycentric evaluation on Metal

The preceding goal turn made verified progress on shared base-field lookup
visitation. Profiling then attributed about 4.0 of 5.3 native-parent core seconds
to sampled-value evaluation. Streaming commitments retain host-owned evaluation
columns and no coefficients; the existing device sampler required resident tree
handles and therefore fell back to CPU.

## Implementation

PCS preflights complete epoch eligibility before building plans or recording
their work. A backend capability admits host columns up to 64 MiB each.
Larger columns retain the existing CPU fallback. An optional null resident handle
explicitly selects host staging; mixed epochs stage all their columns.

The resident C entrypoint retains its tree ownership and pointer-membership
checks. A separate host entrypoint shares the numerical kernels, normalization
validation, exact output roster and work accounting. It stages whole columns
through one slab capped at 64 MiB. Every run completes before that slab is
overwritten. Domain and barycentric weights remain on device across runs and
matching cross-tree point plans are deduplicated. Device failures drain before
return; caller result slices are populated only after the full epoch and receipt validate.

The staging bound applies to column uploads, not all GPU memory: domain,
numerator and weight scratch still scale with the maximum supported domain.
Commitments stay streaming; the implementation does not retain the complete
trace on device or recreate coefficients. No shader, AIR, transcript or security
parameter changes.

STWO_ZIG_CPU_HOST_BARYCENTRIC=1 is a same-binary diagnostic control, disabling
host staging while preserving all other GPU proving stages.

## Focused validation

Ten ReleaseSafe tests pass, including exact planner normalization, sampled-domain
point rejection and all-allocation-failure cleanup. The resident multi-tree,
multi-point numerical test also exercises mixed host/resident input.

A dedicated test evaluates 300 columns at two points (75 MiB of logical columns
per point) through the 64 MiB slab. Three distinct repeating column patterns
cross the slab boundary at different offsets, checking overwrite and indexing
behavior against independent CPU barycentric evaluation. Telemetry records
600 evaluations, two unique point plans, four commands and 67,108,864 staging
bytes. Existing resident receipt validation still requires one command/wait;
host receipts require positive, matching command/wait counts.

The initial canonical native Metal parent qualification passes all seven
selected/imported tests with the unchanged 857591-byte artifact SHA-256
87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b.
Child and parent retain 70 queries / 26 PoW bits, with independent verification,
transcript replay, rekey, fixed-plan reuse and output-lifetime checks.
Its initial sampled-value stage is 0.364 s and core stage 1.597 s; these single
observations are diagnostic, not a complete-tree latency claim.

Matched parent and CSP results are recorded below after final preflight cleanup.
Full CSP baseline recovery, tree scheduling, deeper PCS/DEEP fusion and the
separately reviewed recursion parameter experiment remain open.

## Mixed storage and dispatch qualification

The first CSP gate incorrectly assumed every workload would use host staging.
The retained probes show that ECDSA and SHA256/128 already retain coefficients
for all four trees and use the existing device coefficient sampler. They have
no barycentric fallback to remove. Those initial probes verified successfully
but are excluded from the matched result.

SHA256/2048 and Keccak/128 exceed the coefficient cache budget for their
interaction tree. The old all-or-nothing sampler sent the entire mixed epoch to
CPU. A new borrowed partition passes evaluation-form trees to barycentric
evaluation and coefficient-form trees to the existing device coefficient kernels.
Empty sample partitions are skipped. No owning tree is copied or deinitialized;
coefficients are released by the original owner only after both partitions finish.

Twenty-three focused PCS ReleaseSafe tests pass, including the new mixed
partition test for output ordering, declined outputs, empty partitions, borrowed
ownership and allocation failures. The final canonical parent also passes all
seven tests after the mixed integration, with identical artifact bytes.

STWO_ZIG_PROFILE_SAMPLED_DISPATCH=1 records concrete backend capabilities and
per-tree storage forms. The final CSP gate checks new dispatch only when those
forms require barycentric evaluation; all-coefficient cases must keep their
existing fallback count.

## Matched native parent result

Same frozen binary, serial control/candidate/candidate/control, two observations
per arm. This comparison predates the mixed partition addition; parent-source
and parent-test retain that exact source/binary. final-parent.log independently
qualifies the final implementation; candidate-source and final-parent-test
record that final state. The native fixture uses evaluation-form trees throughout.

| Metric | CPU sampling control | Bounded GPU staging |
| --- | ---: | ---: |
| Complete fixture wall median | 23.914989 s | 20.034625 s |
| Recorded parent stages median | 11.014086 s | 7.388716 s |
| Sampled-value evaluation median | 3.995100 s | 0.352992 s |
| Core stage median | 5.259111 s | 1.596922 s |
| Peak resident set | 20,886,093,824 B | 20,883,980,288 B |
| Peak physical footprint | 27,381,543,104 B | 27,759,407,632 B |

Sampling is 11.3x faster; complete fixture time improves 16.2%. Physical peak
increases 377,864,528 bytes (about 360 MiB / 1.4%), while RSS is flat. This is
additional device scratch, not a claim of lower total memory. The 64 MiB limit
covers staged column data; it excludes domain, weight and numerator scratch.

The fixture includes child proving, parent preparation, admission, independent
verification and teardown. It is not production root latency or full-tree
throughput. No subsecond or whole-system 10x claim follows from the sampled stage.

## Matched Metal CSP result

| Workload | Complete median (s), control → candidate | Interpretation | Candidate execution+witness+prove mean (s) |
| --- | ---: | --- | ---: |
| ECDSA precompile / 32 | 0.658878 → 0.656465 | Unchanged route; effectively flat | 0.513404 |
| SHA256 / 128 | 1.496055 → 1.498202 | Unchanged route; effectively flat | 1.042104 |
| SHA256 / 2048 | 2.463129 → 2.352676 | 4.5% faster | 1.755999 |
| Keccak / 128 | 2.384991 → 2.269827 | 4.8% faster | 1.703684 |

Same frozen ReleaseFast binary, 16 workers, canonical 70 queries / 26 PoW bits,
blowup 1, fold step 1 and last-layer degree 0. Six samples per arm, in three-sample
control/candidate/candidate/control blocks; zero warmups. All 48 timed proofs and
16 fresh artifact verifications pass. Guest/input/output/config identity and
proof bytes match the preceding qualified implementation.

SHA256/2048 sampled-value time drops 0.183 to 0.081 s, and Keccak/128 drops
0.180 to 0.076 s. CSP physical peaks remain effectively unchanged. The complete
median includes admission, encoding and fresh verification; the last column
uses the historical execution+witness+prove timing scope.

This four-case Metal comparison does not supersede the full original Poseidon
CPU/Metal basket. Final full-basket qualification, recursive scheduling overlap,
deeper PCS/DEEP fusion, remaining intermediate witness storage and the separately
reviewed recursion-parameter experiment remain open.

Reproduction: measure-parent.py, measure-csp.py and summarize-csp.py use the
retained frozen artifacts. Raw reports, logs, profiles, binaries, AOT bundle
and source snapshots are covered by SHA256SUMS.
