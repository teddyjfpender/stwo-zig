# Recursive prover cost map

The state fold verifies one full S31 STARK proof inside a circuit. Its proof
size is roughly constant across steps, but proving that verifier circuit is
the main cost. This record uses the [affine-square source](../../src/frontends/s31/examples/affine_square4.s31)
and the [v2 local measurement](measurements/state-fold-general-v2-2026-10-07.json).
The [v3 counter record](measurements/state-fold-u32-v3-2026-10-07.json)
shows the same padded geometry after widening the step counter.

Run `s31.py inspect-state-fold PACKAGE` to rebuild the sealed AIR and get
`verifier_stages`: cumulative raw gate and variable counts after each verifier
phase. The final stage must equal the report's raw geometry. The profiler
observes the witness-free topology; it adds no gates and leaves the sealed
preprocessed root unchanged. The acceptance fixture checks those properties.

| Phase | New raw variables | Share of 11,823,692 |
| --- | ---: | ---: |
| Guess child proof witness | 800,582 | 6.8% |
| Merkle decommitments | 2,925,406 | 24.7% |
| FRI decommitments | 7,948,629 | 67.2% |
| State-fold digest | 664 | <0.01% |

Merkle and FRI decommitments together add 10,874,035 raw variables, or
91.97% of this circuit. `finalize` also adds 386,834 `m31_to_u32` rows to
range-constrain guessed values; that is 91.3% of the final 423,808 rows in
that component. Stage counts are **circuit size**, not measured wall time or
memory attribution. Padding puts this circuit at 19,642,180 variables and
a trace log size of 22. The local step-1 proof was 552,213 bytes and its
timed proving call took 2.678 seconds; one process also spends time building
the witness and preprocessed commitment. The earlier square/add sample saw
9.31 GB standard versus 7.00 GB low-memory peak RSS. These are isolated
local observations.

The native batch `state-fold-advance` path reuses the immutable preprocessed
circuit, commitment and padded witness-free topology across steps. It still
checks full gate equality against each step's value circuit, then natively verifies
each child and output proof. Before topology retention was added, a
three-step batch reusing only the commitment took 9.94 s wall versus 10.87 s
for three one-step commands, an 8.6% reduction; peak RSS was about 9.31 GB
in both. The later topology cache saves a further small amount of wall time
at roughly 150 MB higher peak RSS in the one-fold fixture. All compared
proofs were byte-identical. The old timing was one sample; topology caching
does not address the main verifier-circuit cost.

## Four FRI folds per commitment

The gate package now permits `--fri-fold-step 4` as an explicit build-time
choice. The PoW, blowup and query counts remain 26, 1 and 70. The FRI
configuration is mixed into the transcript and pinned by the package key;
cross-schedule leaf proofs are rejected even when the leaf AIR root and
circuit hash are identical. The wrapper and fold keys acquire distinct roots.
The [local pinned Stwo protocol revision](../../src/core/protocol_revision.zig)
also uses fold step 4 in its production configuration; this is still an
engineering comparison, not an independent soundness calculation.

| Affine-square recursive circuit | Fold step 1 | Fold step 4 | Change |
| --- | ---: | ---: | ---: |
| Raw variables | 11,823,705 | 5,589,622 | −52.7% |
| Padded variables | 19,642,180 | 9,811,780 | −50.0% |
| FRI decommitment variables | 7,948,629 | 2,288,070 | −71.2% |
| Padded Blake-G rows | 4,194,304 | 2,097,152 | −50.0% |
| Trace log size | 22 | 21 | −1 |

The main reduction is in FRI decommitment: fewer commitment layers mean far
fewer in-circuit Blake2s Merkle-path checks. The proof format and verifier
geometry change, while the source relation does not. Full state-fold and
cross-schedule acceptance tests pass. In [four alternating local runs per
schedule](measurements/fri-fold-step-v1-2026-10-07.json), the three-step batch
had a median wall time of 10.819 s at fold step 1 and 6.457 s at fold step 4
(40.3% lower). Median peak RSS was 9.46 GB versus 5.09 GB (46.2% lower),
and the top proof shrank from 554,591 to 372,317 bytes (32.9% lower). The
same source, assignment and visible PoW, blowup and query counts were used;
these are local measurements, not a universal speedup or a soundness proof.

The next efficiency sequence is:

1. Reduce remaining Merkle/FRI verifier work through exact common-path
   sharing or a dedicated recursive verifier AIR. Any shared opening must be
   constrained to the same index, leaf, tree root, and transcript challenge.
   Benchmark raw rows, padded rows, proof bytes, wall time, and peak RSS;
   smaller source code alone is not a useful result.
2. Replace the large `u16` guess finalization cost only with a range-check
   chip whose lookup or polynomial argument is independently validated.
   Simply omitting those rows would make proof words unconstrained.

Each optimization must keep the exact sealed child key, AIR root, PCS/FRI
configuration, raw-u32 public digest, BLAKE2s domain, proof-of-work check,
and the full native/in-circuit verification differential suite. It must also
preserve the source-derived transition and the well-founded decreasing
counter. The state-fold key v3 widens that counter to `u32` with just 13
more raw variables and unchanged padded AIR sizes. The
current circuit's soundness still depends on the STARK system, the in-circuit
verifier implementation, and BLAKE2s binding; this profiling is not a
cryptographic audit.
