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
circuit and commitment across steps. It still rebuilds a witness-free
topology and checks full gate equality at every step, then natively verifies
each child and output proof. In one three-step local comparison, the cached
batch took 9.94 s wall versus 10.87 s for three one-step commands, an 8.6%
reduction; peak RSS was about 9.31 GB in both. All three proofs were
byte-identical. This is one sample, not a stable benchmark or a solution to
the main verifier-circuit cost.

The next efficiency sequence is:

1. Reduce repeated Merkle/FRI verifier work through exact common-path
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
