# RV64 throughput-v1 Keccak-f truth

Status: implemented and qualified on fixtures (see "Tests"). v3 default for
Keccak truth proofs of log >= 13; v2, fixtures and existing v3 bundles keep the
compact truth byte-for-byte.

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
