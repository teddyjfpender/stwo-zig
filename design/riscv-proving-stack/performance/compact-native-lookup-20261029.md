# Compact native lookup design

The measured architectural target is the six independent Cartesian lookup tables:
24,379,392 base fixed/main/interaction cells even when the source uses only a few
of their tuples. Removing that floor requires a different constrained encoding,
not merely caching the dense tables or choosing a smaller unverified subset.

## Problem matching and decision

The reusable pattern is a sparse histogram whose keys are proved members of an
exact finite language. Each signed histogram entry discharges the same original
native LogUp tuple and uses the same Universal relation challenges. No helper
lookup namespace or host-approved tuple list is introduced. Duplicate valid keys
are harmless: their signed multiplicities add in the original relation. Zero
multiplicity padding must still encode a valid tuple.

For range tables, Boolean columns encode the exact 20, 19, 20, 16 or 15 input
bits. For the M31 limb table, an inverse constraint excludes exactly (255,127),
including when a malicious witness gives it zero multiplicity. Bitwise rows use
16 input bits and four Boolean one-hot operation selectors; the output polynomial
matches AND, OR, XOR and the original fourth operation whose result is zero.
The bitwise tuple has degree three and its LogUp recurrence degree four; all
other sparse and dense recurrence components have degree two.

A single heterogeneous proof contains all six components with independent row
logs and an explicit dense/sparse mode for each. Sparse row count depends on
nonzero signed counters and is rounded once to the component's power-of-two
geometry. Dense mode preserves the full original language for high density.
Both modes retain six separate physical claimed sums, absorbed before the
interaction commitment. Epoch binding commits every fixed/main root before
relation challenges, and the entry identity separately binds the layout and
source-demand plan. The independent verifier regenerates fixed columns and
checks their roots; neither mode selection nor a checkpoint is a proof receipt.

## Cost selection and limitations

`block_v7_lookup_compact_layout_v1` reports base committed cells, LDE cells,
constraint-domain evaluations, OODS field count, query leaf fields and a
conservative Merkle-compression upper bound. Selection uses explicit weights
(64 operations per opened field, 512 per compression) in addition to polynomial
work and refuses sparse mode unless base cells also decrease. These weights
are a transparent initial policy, not benchmark-derived timing predictions.
The exact resulting recursive verifier rows and real timings must be measured
before making performance claims. Small sparse tables use wider rows and can
increase per-opening arithmetic; comparing only base cell count hides that cost.

The original dense provider is retained as a differential oracle. The new proof
is isolated: it is not accepted by the active whole-execution receiver until
explicit integration and recursive fixed-key qualification. No old receipt or
original proof identity is relabeled as the new layout.

## Qualified original proofs and independent geometry

The stripped ReleaseSafe compact proof gate passed **253 tests**. It exhaustively
compares all original dense tuple rows with the Boolean encoding, proves both
compact and original dense providers under the **same epoch**, and checks equal
six signed claims plus fresh verification after postcard roundtrip. A second
actual proof mixes dense M31 with five sparse components. A malicious prover
recommits a non-Boolean bit witness and is rejected by the original AIR, rather
than just the honest witness generator. Compensating claimed-sum mutations and
changed layout metadata are rejected as well. Original proof gates use q8/PoW0.

The heterogeneous proof requires one composition split. All six components use
an actual four-way quotient domain and matching reported bound/split, including
the degree-two range components; this extra work is included in the cost model.
The independently derived q70/PoW26 **geometry-only** gate passed 210 tests:

| Geometry | Original dense | All sparse, 16 rows each | Dense M31, other five sparse |
|---|---:|---:|---:|
| Raw fixed/main/interaction cells | 24,379,392 | 2,352 | 264,144 |
| PCS lifting log | 21 | 5 | 16 |
| Composition log / split | 21 / 1 | 6 / 2 | 17 / 2 |
| Columns, including composition | 58 | 163 | 149 |
| OODS secure fields | 82 | 187 | 173 |
| Trace query field upper bound | 4,060 | 11,410 | 10,430 |
| Trace path edge upper bound | 5,880 | 1,400 | 4,480 |
| FRI rounds | 20 | 4 | 15 |
| FRI opened secure-field upper bound | 2,800 | 560 | 2,100 |

Query bounds do not assume Merkle multiproof deduplication. This is the important
tradeoff: sparse encoding eliminates the large Cartesian domain but widens
opened rows. Even the smallest retained dense table keeps fifteen FRI rounds.
The table does **not** establish a net recursive arithmetic-row reduction or
end-to-end speedup. Exact symbolic composition, transcript/fixed-row parity and
standalone recursive parent qualification remain the next work.

## Standalone recursive parent milestone

The new family-specific recursive path passed **276 stripped ReleaseSafe tests**.
It replays the original 53-pair epoch transcript, compiles the exact same
Boolean/dense equations symbolically, and keeps all six physical claims as
public circuit operands. Cold setup derives every fixed row and public route
independently; the test compares all fixed rows, context, wires and verifier key
with the actual original-proof preparation. A standalone parent proof is encoded
and freshly verified after producer rows are released. Changed physical claims,
public root-coordinate maps and verifier keys are rejected.

For this diagnostic q8/PoW0 sparse fixture, the actual retained recursive witness
has 31,445,572 bytes, 48,160 BLAKE3 G rows, 13,760 XOR rows, 3,629 arithmetic rows,
52 inverse rows and 1,304 readonly rows. Its standalone parent encoding is
129,652 bytes. These are fixture counts, not a comparison with a matched dense
recursive parent, a canonical-security timing, or whole-block qualification.
The next integration is the actual source-complete v7 mixed root; the six open
lookup claims must close against the native/caller requests there.

The public statement circuit is `4_200_052`. The original compact proof uses
its B7C transcript domains; the separate parent and public bus use distinct B7L
domains. Claim values and roots never become fixed verifier equations. Mutable
derived profile aliases (configuration and all composition/lifting/mask scalars)
are explicitly checked against a freshly reconstructed profile.
