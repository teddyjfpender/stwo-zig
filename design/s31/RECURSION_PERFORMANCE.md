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

Gate and sparse-wide-gate packages permit `--fri-fold-step 4` as an explicit
build-time choice. For gate packages it also selects the wrapper and fold
schedule; sparse-wide wrappers are always fourfold. The PoW, blowup and query
counts remain 26, 1 and 70. The FRI
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

## Sparse-wide leaf bridge

The [original sparse-wide acceptance record](measurements/sparse-wide-recursion-v1-2026-10-07.json)
uses `wide_order.s31` as a four-component `S31NAT5W` leaf. Its verifier circuit
has 6,972,423 raw variables. The first and second outer proofs use the
ordinary circuit AIR, so they can be checked by the existing native gate
verifier. The three proofs were 238,047, 507,885, and 554,779 bytes in that
run. End-to-end command wall times were 1.09 s to prove the leaf, 2.21 s to
wrap it, and 4.25 s to wrap the first wrapper; each command includes native
verification and setup. Building and sealing both wrapper keys took 61.26 s.
Those are single local samples and should not be extrapolated to larger
Bitcoin header sources.

The [onefold-child/fourfold-wrapper record](measurements/sparse-wide-recursion-v2-2026-10-07.json)
keeps the sparse-wide leaf at FRI fold step 1 and fixes the gate wrappers at
fold step 4. The wide recursive key v3 records this outer schedule, which the
second-level verifier must use; an altered schedule key is rejected. The
visible 26 proof-of-work bits, blowup factor 2, and 70 queries are unchanged.
Leaf, first-wrapper, and second-wrapper proofs are now 238,047, 372,615, and
372,181 bytes. The second wrap took 2.32 s wall time in this local run versus
4.25 s in the earlier step-1 wrapper run (about 45% lower). The second proof
is about 33% smaller. The leaf proof is byte-identical. Package build still
took about 61 s; the first verifier circuit remains 6,972,423 raw variables.
These are separate single runs, not a controlled performance study or an
independent calculation of cryptographic soundness.

The child proof can also use fourfold FRI with `--fri-fold-step 4`. In the
[wide-order record](measurements/sparse-wide-recursion-v3-2026-10-07.json),
leaf/first/second proof sizes were 182,891/345,589/373,568 bytes. The first
verifier circuit fell from 6,972,423 to 3,601,643 raw variables, about 48%.
First-wrap wall time fell from 2.25 s in the onefold-child record to 1.27 s;
second-wrap time was 2.32 s versus 2.36 s. This option changes the child key,
proof transcript, and the first verifier circuit. It is useful for reducing
the first recursion layer, but the top layer needs its own cost comparison.

The bridge adds a profile-specific transcript prefix and a four-component
statement; the rest of the in-circuit STARK verifier is shared. The child
source digest, root, circuit identity, component sizes, and PCS parameters
are fixed by the sealed key. Native proof capture occurs only after full
verification; the outer circuit independently checks the captured openings.
Ten post-authentication circuit mutations and seven second-level mutations
are rejected. Package and statement checks also reject changed proof bytes,
public words, roots, and key bytes. These checks exercise implementation
consistency; they are not a cryptographic soundness proof.
The [cross-key fixture](../../src/frontends/s31/acceptance_sparse_wide_key_binding.py)
also confirms that a same-AIR source rename changes the sparse-wide profile
identity, rejects leaf proof replay, and changes the outer AIR root. A
repaired clone statement still fails outer proof verification.
The same fixture's `--compare-fri-schedules` mode holds source, preprocessed
AIR root, and sparse-wide circuit identity fixed while changing only the
child FRI step. It rejects leaf proof replay in both directions and a
first-wrapper replay under a repaired public statement.

This bridge still uses the generic verifier circuit and its Blake2s path
checks. A [homogeneous fixed-key claim fold](../../src/frontends/s31/docs/recursion-wide-fold.md)
now starts at the second wrapper. A fold for **changing** Bitcoin header
state and an authenticated SHA AIR chip remain efficiency and functionality
targets.
The [original two-header Bitcoin acceptance record](measurements/bitcoin-sparse-wide-recursion-v1-2026-10-07.json)
confirms the same two-wrapper path for the byte-exact SHA256d and PoW
relation: 9,733,516 raw verifier variables, 372,904-byte leaf proof,
521,838-byte first wrapper, and 560,419-byte second wrapper. The measured
wrap command wall times were 2.51 s and 4.80 s in one local run.
With fourfold wrapper FRI, the [onefold-child Bitcoin record](measurements/bitcoin-sparse-wide-recursion-v2-2026-10-07.json)
has the same 372,904-byte leaf, a 370,088-byte first wrapper, and a
369,616-byte second wrapper. The wrap commands took 2.37 s and 2.45 s in
one local run. Relative to the step-1 wrapper record, the second proof is
about 34% smaller and the second command about 52% faster.

The [fourfold-child Bitcoin record](measurements/bitcoin-sparse-wide-recursion-v3-2026-10-07.json)
measured 4,697,100 first-verifier variables versus 9,733,516 with a onefold
child, a 51.7% reduction. Its leaf/first/second proof sizes were
266,285/352,610/373,854 bytes; wrap times were 1.33 s and 2.15 s. The
first wrap was about 44% faster than the onefold-child/fourfold-wrapper run;
the second was about 12% faster in these runs. The first proof became smaller but the second
grew 1.1%. All figures are single local runs; the same visible query and
proof-of-work counts do not establish equal concrete soundness for different
FRI schedules.

The local records can be compared directly by recursion depth. `1/4` means
onefold child FRI and fourfold wrapper FRI; sizes are bytes and times are
wall seconds for each proof command:

| Source | Child/wrapper fold steps | First verifier variables | Leaf | First wrap | Second wrap | Leaf time | First time | Second time |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `wide_order` | `1/1` | 6,972,423 | 238,047 | 507,885 | 554,779 | 1.09 | 2.21 | 4.25 |
| `wide_order` | `1/4` | 6,972,423 | 238,047 | 372,615 | 372,181 | 1.19 | 2.25 | 2.32 |
| `wide_order` | `4/4` | 3,601,643 | 182,891 | 345,589 | 373,568 | 0.65 | 1.27 | 2.36 |
| `bitcoin_header_pair` | `1/1` | 9,733,516 | 372,904 | 521,838 | 560,419 | 1.19 | 2.51 | 4.80 |
| `bitcoin_header_pair` | `1/4` | 9,733,516 | 372,904 | 370,088 | 369,616 | 1.13 | 2.37 | 2.45 |
| `bitcoin_header_pair` | `4/4` | 4,697,100 | 266,285 | 352,610 | 373,854 | 1.21 | 1.33 | 2.15 |

These runs were collected during development, with compiler changes and
other work on the same host. The table shows bottlenecks and proof geometry;
it is not a controlled benchmark or a basis for a security level.

## Same-key sparse-wide claim fold

The first wrapper's padded verifier layout cannot fit the fixed-fold
circuit. The second wrapper's layout does fit: `eq=32768`,
`qm31_ops=1048576`, `m31_to_u32=262144`, `triple_xor=131072`, and
`blake_g=2097152` rows. The fold reuses those padded sizes without another
power-of-two jump. `inspect-fold` rebuilds the topology to expose exact
headroom; for the fourfold `wide_order` leaf it has 5,589,558 raw variables
and 18,488 unused `triple_xor` rows. This is a **claim fold** over one leaf
execution, not a Bitcoin state-transition fold.

The [wide-integer record](measurements/sparse-wide-fold-v1-2026-10-07.json)
and [two-header Bitcoin record](measurements/bitcoin-sparse-wide-fold-v1-2026-10-07.json)
each prove three steps under one sealed `KF` and verify the top proof after
deleting all lower proof files. They reproduce `KF` from sealed keys and
challenge both base and recursive AIR witnesses plus repaired public
claims. With fourfold child and wrapper FRI, the proof sizes are:

| Leaf relation | Leaf | First wrapper | Second wrapper | Fold 0 | Fold 1 | Fold 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `wide_order` | 182,891 | 345,589 | 373,568 | 374,579 | 372,837 | 373,231 |
| `bitcoin_header_pair` | 266,285 | 352,610 | 373,854 | 372,076 | 370,893 | 375,737 |

The fold output is eight raw `u32` digest words; its public statement also
carries the original eight-word leaf claim and a constrained `u16` step.
Each fold proof is approximately the size of the second wrapper proof;
proof size does not grow linearly with the number of folds. The recorded
local fold commands took roughly 2–3 seconds each, and isolated top native
verification about 0.1–0.15 seconds. These measurements neither establish
a concrete security level nor imply a useful Bitcoin light client. The
counter is currently bounded to 65,535 steps, and no new header is
consumed by a fold step.

`inspect-fold` now records cumulative verifier phases for this same-key
fold. The [wide-order stage record](measurements/sparse-wide-fold-stages-v1-2026-10-07.json)
reproduces the original fold AIR root and all six proof sizes while rejecting
16 direct base and recursive mutations, including both proof-of-work nonces.
The [two-header Bitcoin stage record](measurements/bitcoin-sparse-wide-fold-stages-v1-2026-10-07.json)
also rejects all 16 mutations at both branches and keeps its original six
proof sizes.
Subtracting consecutive `raw_vars` counts gives:

| Fixed-fold phase | New raw variables | Share of 5,589,558 |
| --- | ---: | ---: |
| Guess child proof witness | 341,244 | 6.1% |
| Merkle decommitments | 2,824,606 | 50.5% |
| FRI decommitments | 2,288,070 | 40.9% |
| Fold output digest | 656 | 0.012% |

Merkle and FRI decommitments account for 5,112,676 raw variables, or
91.5% of the circuit. Finalization adds 155,858 of the 203,136 raw
`m31_to_u32` rows because witness range checks are deferred. Phase counts
measure circuit geometry, not wall-time attribution. The witness-free
instrumentation adds no gates; the sealed root remains
`c262acf359f951f417267296f61dc6ce3bafbc411e4c807d05c0d13f801b619b`.

`fold-advance` reuses the sealed preprocessed AIR, its commitment, and the
padded witness-free topology across several steps. It still verifies every
child proof, checks every value-bearing gate list, and verifies each newly
produced proof before writing it. The
[fourfold wide-order batch record](measurements/sparse-wide-fold-batch-v1-2026-10-07.json)
compares three separate low-memory fold commands (6.578 s summed wall time)
with one three-step batch command (5.786 s wall time), a 12.0% reduction in
this one local sample. Every proof and statement byte matches, including a
batch resumed from step 0. This comparison includes different numbers of
CLI/package checks; it does not isolate the cache's contribution or promise
the same improvement on another host.
In a [separate three-trial macOS run](measurements/sparse-wide-fold-batch-memory-v1-2026-10-07.json)
that alternated command order, median three-step wall time was 6.420 s for
separate commands and 5.573 s for one batch, 13.2% lower. Median peak
resident size was 3.736 GB for the largest separate command and 3.814 GB
for the batch, about 74 MiB higher. The batch retains a padded topology;
this is a measured memory-for-time tradeoff. Every compared proof and
statement was byte identical, and each top proof passed the native
verifier. The measurement includes process startup, package checks and
proof-of-work, so the cache alone cannot be credited with the full change.
The [Bitcoin two-header batch record](measurements/bitcoin-sparse-wide-fold-batch-v1-2026-10-07.json)
also matches every separate proof byte. Its three fold commands summed to
7.352 s; the batch took 6.650 s, 9.5% less in that local sample. The
Bitcoin source is still a fixed two-header leaf, and these fold steps do
not append headers.
The [onefold-child wide-order record](measurements/sparse-wide-fold-fri1-batch-v1-2026-10-07.json)
passes the same three-step batch and mutation checks. Its leaf and first
wrapper are larger (238,047 and 372,615 bytes), while the fixed fold still
fits the second wrapper's padded AIR layout and produces a 370,522-byte
step-2 proof. This confirms support for both sealed child FRI schedules;
the fold's own verifier schedule remains fourfold.
The [source-key](measurements/sparse-wide-fold-key-binding-source-v1-2026-10-07.json)
and [FRI-only](measurements/sparse-wide-fold-key-binding-fri-v1-2026-10-07.json)
replay fixtures rebuild a valid second package, repair the entire top
statement under its keys, and still reject the original fold proof at
native STARK verification. The source-key comparison holds the leaf's
preprocessed AIR root fixed; the FRI comparison also holds the leaf source
and circuit identity fixed.

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
