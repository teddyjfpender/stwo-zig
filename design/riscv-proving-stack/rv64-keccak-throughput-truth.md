# RV64 throughput-v1 Keccak-f truth

Status: implemented and qualified on fixtures (see "Tests"). v3 Keccak truth
proofs of log >= 13 now default to its quartet batching on a 27-row slot
(`throughput_r27_v1`, section "Quartet batching and the 27-row slot"; the
29-row quartet `throughput_quartet_v1` and this throughput-v1 stay selectable);
v2, fixtures and existing v3 bundles keep their profiles byte-for-byte.

Lever (a) of the Keccak/memory cost design (`rv64-keccak-and-memory-cost-reduction.md`
on `codex/rv64-keccak-memory-cost`, section 2(a) and 6).

## What changes

- MAIN witness, row filler, slot geometry (29 rows / 2 calls) and every direct
  constraint are the compact component's (`delegations/keccak/equations.zig`
  `emitDirectFor`). Only the lookup interpretation changes.
- `BatchPolicy.throughput_v1` (`batch_policy.zig`): per active round row 320
  five-output chi queries (one per `(y,z)` row of five lanes) and 107
  three-position xor5 queries, 427 total, cleared three per degree-4 batch:
  143 round batches (the last holds one query plus two dummy entries with
  denominator 1 and weight 0) + 9 unchanged IO11 batches = 152 batches,
  608 interaction columns (compact: 649 / 2596).
- Tuples: `keccakf_lookup_tuples.zig` `throughputChi` / `throughputXor5`, now
  the single authority also used by the RV32 throughput plan
  (`keccakf_throughput_interaction_plan_v1.zig` delegates to them).
- Tables: the RV32 `keccakf_throughput_tables_v1.zig` (2^21 chi, 2^16 xor5;
  7 fixed, 1 multiplicity, 4 interaction columns), selected by
  `tables.Trace.initPolicy`. Multiplicities: `throughput_counts.zig`.
- Identity: `Policy.mix` adds `0x4b545055` + table logs + query counts +
  batch count; the services truth transcript (`services/protocol.zig`
  `beginTruth`) mixes a distinct word vector plus `Policy.mix` for throughput
  and leaves the compact words untouched. The fixed root differs (different
  tables), so the manifest binds the profile too. Wire: the Keccak truth
  declaration's `logs[1]` is 0 (compact, unchanged bytes) or 21 (throughput);
  `wire.keccakPolicy` rejects anything else. The older `keccak/shared`
  protocol refuses non-compact setups.
- Planner (`ethereum/plan.zig`): under `ethereum_services_v3` a truth takes the
  throughput tables iff that commits fewer cells (`keccakTruthCells`), i.e. log
  >= 13. `admitProfile` rejects throughput truths under v2.

## Soundness argument

1. Range: every state cell of round r+1 is a chi-table output (`tuple[1..6]`
   of the `(y,z)` query covers x = 0..4, all 1600 cells); round-0 state is
   bound to boolean input planes by the unchanged direct equations; every
   parity cell is an xor5-table output (positions 0..319; positions 320,321 of
   the last query are the constant zero entry, equal to table row 0). Hence by
   induction every committed state/parity cell is in {0,1,8,9} (`a + 8b`).
2. Key injectivity: theta = state + two parities has digits a, b in [0,3], so
   each theta is in [0,27] and the packed chi key `sum theta_x 28^x + iota 28^5`
   (iota = one round selector, in {0,1}) is < 2 * 28^5 < p and determines the
   five thetas and the iota bit. xor5 tuples carry each sum (in [0,45]) and
   parity as separate coordinates; no packing.
3. Table identity: the receiver builds the fixed columns itself from the RV32
   authority (`TruthSetup.initPolicy` seals the key); a tampered table changes
   the fixed root and is rejected before any challenge.
4. LogUp mass: each table bus has mass = active round rows x {320, 107} <=
   slots x 24 x 320 < p (`layout.admitThroughputRoster`; implied by the
   stricter compact bound already enforced by `validateGeometry`). With mass
   < p, the rational identity forces each looked-up tuple's count to equal its
   table multiplicity modulo p and an absent tuple's count to be 0 mod p, hence
   0; multiplicities need no range check. Table traces also reject a count
   total >= p and any count on the padded xor5 suffix.
5. Degree: residuals are delta * d0 d1 d2 - c * (pairwise products), c =
   roundActive (degree 2), d linear: degree 4, as compact.

Not changed / not claimed: whole-protocol security accounting
(`rv64-whole-protocol-security-policy.md`) still has to include the new table
sizes; recursion circuits for the throughput truth are not built (no Keccak
truth recursion exists for compact either).

## Cost (committed MAIN + INTERACTION cells; fixed excluded)

| per Keccak-f call, frozen roster (32,835 calls, 2 x log18 truth) | compact | throughput |
|---|---:|---:|
| permutation (2 x 2^18 rows) | 72,156.5 | 40,413.6 |
| tables (2 per roster) | 2.8 | 658.4 |
| **total** (`calibration.json`) | **72,159.3** | **41,072.0** (-43.1%) |

The 2^21 chi table adds 7 x 2^21 fixed cells per truth proof (outside the
proxy) and makes the truth proof's largest component log 21. Small truths pay
10.8 M table cells, so the planner keeps compact below log 13.

## Tests

`test-riscv64-keccak-throughput` (AIR: geometry, transcript identity, mass
bounds, degree <= 4, SIMD lane parity, tuple/table agreement, wrong chi output
in each of five lanes and the b plane, wrong xor5 parity, coherent wrong
rho wiring, multiplicity forgery, table tamper, proof + fresh OODS receiver,
compact receiver rejects); `test-riscv64-word16-sponge-services` (services
fixture with a throughput truth: fresh keys and wire verify, compact receiver
rejects, tampered claim rejects, wrong permutation input fails IO11).

## Quartet batching and the 27-row slot (branch `codex/rv64-ge-keccak2`)

Where the throughput-v1 cells go, per Keccak-f call (exact layout):
14.5 rows x (1,923 MAIN + 608 INTERACTION) = 36,700 cells; MAIN is 1,600
packed state cells (two calls a + 8b), 320 packed parities and 3 header
cells per row; 427 round queries (320 chi rows + 107 xor5 triples) and 25 IO
lanes per row; 29 rows per pair = 25 states + 2 input + 2 output bit planes.
The 4-packet prefix of block 24,628,607 (22,385 truth IDs, two truths log18 +
log16) adds table cells (2 x 5 x (2^21 + 2^16)) and padding: 38,016 per ID.
MAIN per round (960 bits per call-round) is already at the floor of this
packing, so the two cuts are interaction width and slot rows.

### `throughput_quartet_v1` (`--keccak-pair29`)

Same MAIN, direct equations, tuples, tables, multiplicities and mass bounds
as throughput-v1; the 427 round queries and the 25 IO lanes are cleared four
per batch (`clearQuartetFor`): 107 round batches (the last holds three queries
and one dummy entry d = 1, c = 0) + 7 IO batches = 114 batches, 456
interaction columns. Degree: delta * d0 d1 d2 d3 is 1 + 4 and c * (triple
products) is 2 + 3 (c = roundActive or ioActive, degree 2), so 5, which still
fits the log + 2 quotient domain (as compact `quartet_v3`). Soundness is
throughput-v1's: the batch equations only regroup the same fractions.
Identity: `Policy.mix` (enum, width 4, 456 columns, degree 5, plus the
throughput table identity), wire `logs[1]` = 21 | 4 << 8 = 1045.

Measured (real 4-packet prefix of 24,628,607, fresh `verify-prefix`
accepted): Keccak-f truth cells 850,984,960 -> 801,177,600 (-152 x (2^18 +
2^16) exactly), 38,016 -> 35,791 per truth ID (-5.85%). CPU cells identical.

### `throughput_r27_v1` (v3 default)

27-row slot (`layout.Geometry.pair27`): complemented A input plane p, packed
states v0..v24, complemented A output plane p'. Call B's bits are not stored:
they are the b digits of v0 and v24, read through the affine expression
(v + s[-1] - 1) / 8 on the v0 row (s[-1] = p) and on the output-plane row
(v = p', s[-1] = v24). Direct equations: those of pair29 except the unpack,
which becomes, per cell, on the v0 and output-plane rows,
active * t * (t - 8) = 0 with t = v + s[-1] - 1 (degree 4).

Soundness. (1) Plane rows are boolean (active-gated). (2) With p boolean,
t in {0, 8} forces v0 = 1 - p + 8b, b in {0,1}: v0 is in {0,1,8,9} with call A
bit 1 - p and call B bit b. This is exactly the induction base of the
throughput-v1 argument (round-0 digits boolean); rounds, tables and mass
bounds are unchanged. On the output side the same equation ties p' and b'
to the digits of v24 (a chi output). (3) IO: group A (entries 0..24) tuples
(BASE_ID, fixed[27], lane, bytes of 1 - v) weighted active_A * (fixed[0] +
fixed[27]); group B (entries 25..49) tuples (BASE_ID + 1, fixed[27], lane,
bytes of (v + s[-1] - 1) / 8) weighted active_B * (fixed[2] + fixed[27]).
Every tuple element is affine in committed columns (denominators linear); IDs
and directions are pair29's. 50 IO entries in 13 quartets: 120 batches, 480
interaction columns. (4) Every equation that reads a neighbour row (unpack,
round lookups, IO) is gated by the slot's active flag and COMPLETE_SLOT
forces an incomplete tail inactive, so all phases are enabled (pair29 had to
disable phase 26 on incomplete slots); 27 never divides 2^k, so the last
domain row is always inactive and no active equation reads across the wrap.
(5) Fixed columns keep pair29's meaning (0 input plane, 2 + r round r, 26
final state, 27 output plane; 1 and 28 identically zero), so the round
selectors, iota tuples and table counts are reused unchanged. Identity:
`Policy.mix` adds (0x4b523237, 27 rows, 50 IO entries, 13 IO batches); the
fixed root differs from pair29; wire `logs[1]` = 1045 | 27 << 16.

Per call before padding/tables: 13.5 x (1,923 + 480) = 32,440.5 vs
34,495.5 (quartet), -6.0%. Power-of-two padding decides whether that shows:
with the old planner the prefix's remainder (2,967 IDs) still takes a log16
truth and r27 is worse (809,041,920 cells). The v3 planner therefore sizes
the remainder by the cheapest split into at most three truths, counting each
proof's tables (`keccakBestSplit`): for r27 the prefix becomes 19,418 (log18)
+ 606 (log13) + 2,361 (log15) = 760,799,232 cells, 33,987 per ID; the pair29
quartet plan of this prefix is unchanged by the search (801,177,600).

Measured (real 4-packet prefix of 24,628,607, `produce ... 4 --keccak-r27
--proof-jobs=1`, memguard --gb 15, 140.7 s wall, max RSS 19.84 GB; fresh
`verify-prefix` accepted, 4 CPU + 7 truth proofs): truths [18, 1770517],
[13, 1770517], [15, 1770517]; Keccak-f truth MAIN + INTERACTION cells
760,799,232 exactly as planned (throughput-v1 default before: 850,984,960;
29-row quartet: 801,177,600), i.e. 38,016 -> 33,987 per truth ID (-10.6%).
All truth proofs -90,185,728 cells; CPU cells identical (2,274,110,496).

| per truth ID, prefix of 24,628,607 (22,385 IDs) | cells | vs throughput-v1 |
|---|---:|---:|
| throughput-v1 (log18 + log16) | 38,015.9 | |
| throughput-quartet-v1 (log18 + log16) | 35,790.8 | -5.85% |
| throughput-r27-v1 (log18 + log13 + log15) | 33,987.0 | -10.6% |

Not done here: the sponge permutation row (~2,600 cells per permutation)
is unchanged; tables are still committed once per truth proof (10.8 M cells
each, ~1,450 per ID on this prefix with three truths); packing several table
entries per row or sharing one table set across the truths of a bundle
would remove most of that.

### Tests

`test-riscv64-keccak-throughput` (41 tests): `rv64_keccak_throughput_quartet_test.zig`
(geometry, identity vs all profiles, degree <= 5 with the fifth degree used,
SIMD parity, honest residuals zero on every row and one-limb interaction
tamper caught at its batch, same claim as throughput-v1, serial == pooled,
wrong round constant / skipped round / dropped final round / wrong theta
parity / wrong iota-lane chi rejected, forged IO rejected, proof + fresh
receiver, compact and throughput-v1 receivers reject) and
`rv64_keccak_r27_test.zig` (geometry and log sizes, degree, SIMD parity, slot
semantics against an independent Keccak-f through the AIR's own IO tuples,
honest residuals on every row with odd calls and an incomplete tail, same
claim as the pair29 quartet, forged plane bits and non-canonical packed cells
rejected by exactly the unpack/booleanity equation, forged permutations,
proof + fresh receiver with compact / throughput-v1 / pair29-quartet
receivers rejecting). `test-riscv64-word16-sponge-services`: both profiles
through the services lane with fresh keys and wire, cross-profile receivers
(throughput-v1 has the same fixed root as the quartet and still rejects),
tampered claim, wrong truth input, forged and stale message.
`test-riscv64-word16-ethereum-terminal`: planner (defaults, r27 split,
exhaustive contiguous admitted spans, v2 plan unchanged), options.
