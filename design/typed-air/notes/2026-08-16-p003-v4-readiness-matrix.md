# P-003 V4 exact-work readiness matrix

**Updated:** 2026-08-24
**Status:** schema-9 CPU and Metal producer closure is 16/16; a publishable
R-006 scaling capture remains gated by a fresh admitted host preflight

## Decision

The typed planned/completed ledger is the deletion-resistant runtime authority;
the sixteen-family matrix remains the broader promotion authority. Both now
close: every CPU and Metal family is complete and all 23 typed producer sites
have real completion paths. This authorizes R-006 to attempt a scaling capture;
it does not turn an inadmissible host run into publishable evidence.

The checkout now has 23 typed sites, all with production completion paths. AIR
composition retains its authenticated CPU and Metal receipts. Dynamic OODS
mask/constraint vtables now publish component-owned, digest-bound cold profiles
only after the real calls succeed. The Blake2s PCS shell has an exhaustive
zero-field receipt spanning pre-opening root mixes, sampled-value transcript,
FRI root/terminal mixes, PoW, query/decommitment construction, commitment-root
materialization, and proof-object assembly. Unknown suites fail closed.
External serialization is explicitly excluded by the frozen counter partition.

## Inventory delta

Schema 9 appends `pcs_transcript_shell` at stable ordinal 22; schema 8's
`air_composition_on_domain` remains ordinal 21 and all earlier ordinals are
unchanged. The new site is planned before the native opening shell and can
complete only from the Blake2s suite classifier plus all exhaustive phase and
root-custody receipts.

| Site/family delta | CPU | Metal | Evidence state |
| --- | --- | --- | --- |
| `relation_challenges_and_interaction_traces` | complete | complete | CPU sequential and prepared `N=1/2/4` receipts agree; real-device Debug and ReleaseFast Metal proofs complete the receipt exactly once |
| `quotient_sample_preparation` | complete | complete | completed typed preparation geometry and independent receipt validation |
| `quotient_row_execution` | complete | complete | completed scalar/tiled/Metal execution geometry and receipt validation |
| `air_composition_on_domain` | complete | complete | Debug and ReleaseFast proofs complete the authenticated receipt exactly once; CPU `N=1/2/4` full-production receipts are identical |
| `oods_mask_points` | complete | complete | post-success dynamic-vtable observations aggregate source-identical component authorities; missing, malformed, duplicate, or overflowing profiles cannot publish |
| `oods_constraint_evaluation` | complete | complete | one-row evaluator authority, point/coset work, quotient division, and split-composition reconstruction close at distinct component/coordinator boundaries |
| `pcs_transcript_shell` | complete | complete | Blake2s-only exhaustive phase receipt binds actual pre-opening and FRI root-mix custody; unknown transcript/Merkle suites fail closed |

All prior FFT, Merkle, FRI, main-witness, sparse/guest-Poseidon,
sampled-evaluation, cold-twiddle, and OODS seed-to-point sites retain their
existing exact completion paths.

## AIR-composition authority

The composition producer is split at the real ownership boundary:

- every frontend component exposes an optional cold
  `composition_work_profile` derived from the evaluator or exported polynomial
  program it actually uses;
- the profile binds component kind, domain geometry, constraint count,
  expression work, root weighting, and a source-authority digest;
- the CPU packed backend adds the work it owns: random powers, quotient
  denominators, packed pair/bucket folds, host and accelerated merges, and the
  exact selected finalize path;
- the Metal resident/hybrid backend adds its per-job denominator work, physical
  four-coordinate output folds, host/device bucket collisions, and exact
  finalize path; and
- the proof boundary publishes counters only after result construction and
  receipt validation both succeed. Declines, missing callbacks, duplicate
  publication, malformed geometry, overflow, and unsupported device stages
  leave the profile incomplete.

The ordinary unprofiled path does not invoke a component callback, allocate a
receipt, or branch inside a row/SIMD/Metal kernel. This preserves normal proof
and benchmark behavior; the profiler pays the cold receipt cost only when a
work recorder is explicitly present.

The receipt counts logical operations in the field where each operation is
executed. A QM31 multiplication is one secure-field multiplication. A backend
that physically merges four M31 coordinate arrays reports four M31 additions
per row. Algebraic constraint degree is not treated as runtime complexity.

## Normative closure

The schema-9 matrix independently recomputes to:

- CPU: **16 complete / 0 partial / 0 absent**;
- Metal: **16 complete / 0 partial / 0 absent**; and
- joint CPU+Metal: **16 complete / 0 partial / 0 absent**.

The canonical matrix digest is
`b1eef5ccf8405de9373c11b8fe9bd505a331add0601ab1904a1b038df0ee24d1`.
It binds inventory schema 9, 23 sites, 5,398 source bytes, and inventory digest
`13807efba664c2abc49325a80d8bc67c15896e7250ea48416e0d58e0f029982f`.

The counter partition remains frozen: witness materialization and native
proving are included; guest execution, serialization, and native verification
are excluded; the Blake2s shell is included with zero field work. Changing the
partition requires a schema change.

## Scaling receipt

The V2 work profile is an exact receipt for the algorithm schedule that
actually completed. Worker and backend partitions may therefore have different
field-operation totals while preserving identical statement, transcript, and
proof bytes. R-006 bundle validation V3 requires every verified attempt to
carry a complete V2 receipt and requires byte-identical full disclosures only
within the same `(lane, workload, worker_count)` cell. The scaling reduction V2
recomputes signed counter deltas and zero-safe exact ratios against each
lane-local one-worker cell; CPU-versus-Metal deltas are explicitly
observational. M7's process-work, retired-instruction, GPU-command, and RSS
budgets remain the regression gates—cross-worker or cross-backend V2 counter
equality is not one of them.

The canonical blocker in
`../artifacts/p003-work-profile-closure-v1/scaling-blocker-v1.json` has been
regenerated against schema 9, all 23 sites, and the 16/16 matrix. Its only
remaining blocker is the retained inadmissible host preflight; no P-003 closure
blocker remains. It correctly contains a null R-006 scaling receipt and
`terminal_v4_seal_authorized=false`.

The retained Aug 20 V1 host preflight is AC-powered, has low-power mode disabled,
clear thermal state, minimum idle above 90%, and normalized one-minute load
below 0.20. It is still inadmissible because median idle was 93.81%, below the
95% threshold. It remains immutable historical blocker evidence. R-006 V4 now
admits a newly captured Battery Power cohort when that machine-observed source
stays stable, Low Power Mode is off, and every unchanged quiet/load/thermal
gate passes; this does not reinterpret either retained V1 observation.

Non-Zig closure evidence on the settled source:

- 37/37 independently aggregated P-003/R-006 Python closure tests pass;
- the matrix validator binds schema 9, 23 ordered sites, every authority path,
  and the full typed-site union; and
- blocker replay independently recomputes the matrix and inventory digests.

The terminal Metal gate is current: the Debug real-device proof plans and
completes OODS, relation, quotient preparation, quotient row execution, AIR
composition, and PCS shell exactly once, then independently verifies. The CPU
gate uses accepted receipts at the production proof boundary: each `N=1/2/4`
proof independently verifies, preserves identical statement, transcript, and
proof bytes, and publishes exactly one byte-for-byte identical receipt. Its
authority digest is
`df914f214597393737a7795fc988680df17ca0e5ba09d9d577930260cb703b14`;
its receipt digest is
`9e99ccedbe8302548ef7c95babd445b48f270b355a26090badcec64388350f68`.
The Blake2s shell receipt digest is
`864d550670c284c36dd79fc8521852504b2dd6221410d47cfffceeb56473b46f`.
The real-device Metal gate emitted no separate proof, transcript, work, or
shell identity. Its CPU-independent evidence is the green 3/3 gate, 118
authenticated AOT exports with AOT/JIT parity, exact-once producer completion,
independent verification, 305.58 seconds wall time, and 4,967,989,248-byte
maximum RSS; no CPU digest is reused or inferred for Metal.
The observer is test-only and compile-time erased from non-test builds.

The ordinary unprofiled path is not globally branch-free: it retains only
cold runtime-null/constant branches at the two OODS stage boundaries and per
commitment root. The component row loops, SIMD lanes, and Metal kernels select
their unobserved implementations at compile time and contain no profiling
branch or callback. No receipt arithmetic constructs a second canonic coset;
the coset tally is an integer formula, preserving observer neutrality.

## Reproduction gates

The terminal producer evidence passed these serialized gates with `-j1`:

```text
python3 scripts/typed_air_zig_lane.py --label p003-root-custody-shell -- zig build --build-file src/prover/build.zig test-pcs-shell-work -Doptimize=Debug --summary all
python3 scripts/typed_air_zig_lane.py --label p003-final-producers-real-cpu-debug -- /usr/bin/time -l zig build test-riscv-profile-partition -Doptimize=Debug -j1 --summary all
python3 scripts/typed_air_zig_lane.py --label p003-final-producers-real-metal-debug -- /usr/bin/time -l zig build test-riscv-metal -Doptimize=Debug -j1 --summary all
python3 scripts/typed_air_zig_lane.py --label p003-16-of-16-evidence -- zig build --build-file src/prover_api/build.zig test-work-profile-completion test-work-site-source-authority -Doptimize=Debug --summary all
```

The shell unit gate passed 5/5. The real CPU N=1/2/4 gate passed in 169.16 s
at 3,585,015,808 bytes maximum RSS. The real-device Metal gate passed in
305.58 s at 4,967,989,248 bytes maximum RSS, after accepting 118 exact AOT
kernel exports and AOT/JIT parity. The final P-003 evidence build passed 6/6
steps, including independent matrix and blocker replay. With all matrix
families closed, a fresh installed R-006 `1/2/4/max` scaling cohort may be
attempted as soon as the host preflight is admissible.
