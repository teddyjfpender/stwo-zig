# RV64 Word16 INIT/TEARDOWN: receiver-owned sortedness (boundary v3)

Status: implemented on `codex/rv64-perf2-air-boundary` (base `eac3b7c07`).
Protocol change: proof bytes change; `SCHEMA` 5 -> 6, boundary encoding
`scalable-boundary-v2` -> `scalable-boundary-v3`. Historical receipts are
untouched and are now rejected by the schema/transcript checks, as intended.

## What was removed

The `load_store_v2` public boundary chips (`.initial` = INIT, `.terminal` =
TEARDOWN) used to call the closed-RAM helper `boundaryLocalFor`
(`src/frontends/riscv/rv64/air/memory/closed_ram/equations.zig:101`, unchanged
and still used by the legacy closed-RAM chip) plus four U16 gap lookups
(`R.equations.rangesFor(..., &L.BOUND_U16, ...)`). The chip now emits
`emitBoundaryWithPublicFor`
(`src/frontends/riscv/rv64/air/memory/load_store_v2/equations.zig:41-55`).

| Check (old) | Columns | Constraints | What it proved |
|---|---|---|---|
| C1 carry chain `prev_addr_c + delta_c + carry_{c-1} = addr_c + 2^16 carry_c` on sorted rows | main 14..17 (delta), 18..21 (carry) | 4 | `addr_r = addr_{r-1} + delta` as 64-bit integers |
| C2 `carry_3 = 0` | - | 1 | no 64-bit wraparound |
| C3 `delta_sum * inv = 1` | main 22 | 1 | `delta != 0` |
| C4 carry booleans | - | 4 | carries are bits |
| C5 inactive/first rows zero the 9 sort witnesses | - | 9 | padding canonical |
| C6 four U16 gap lookups (two strict pairs + prefix) | inter 8..19 | 4 | `delta` limbs are u16 |
| previous-row masks on address limbs | main 1..4 prev | - | needed by C1 |

Kept: the 4 active-prefix/row-count constraints, the 13 inactive-row zero
constraints, booleans on `active`, `R`, `W`, the RAM14 inverse + signed prefix
(`scalar.single`, 3 constraints), and two constant residuals pinning the
chip's `range16` and `range8` claims to zero.

Shape: main 23 -> 14, interaction 20 -> 8, constraints 47 -> 25, previous-row
main masks {0,1,2,3,4} -> {0}, previous-row interaction masks
{4..7,16..19} -> {4..7}
(`src/frontends/riscv/rv64/air/memory/load_store_v2/layout.zig:16-17,47,55,60-72`).

C1-C6 jointly proved that the active rows' addresses are strictly increasing
64-bit integers, hence unique. They did NOT prove alignment, canonical address
or value limbs, or that the rows equal the public list: those were already
receiver-owned (the v2 encoding identity said "public-RAM14-canonical-tuples").

## Producers and consumers of the removed checks

Producers (prover):
- Main row: `boundaryRow` (`.../load_store_v2/native.zig:93`) now writes only
  the 14 RAM14 coordinates; `Source.init`
  (`.../load_store_v2/boundary_source.zig:63`) still refuses unsorted,
  duplicated or unaligned lists natively (`error.InvalidBoundaryOrder`).
- Interaction: `writeRows`/`generateSerial` in `boundary_source.zig` and the
  two-wave `boundary_interaction_parallel.zig` now write inverse (0..3) and the
  signed RAM prefix (4..7) only; no range histogram is produced.
- Range table multiplicities: `Prepared.fromRows`
  (`src/integrations/riscv_cpu/word16_execution/memory/prepared.zig:109`) no
  longer merges boundary `counts16`/`counts8` (the fields are gone).

Consumers (verifier/AIR/admission):
- AIR authority for native, packed and circuit lanes:
  `emitWithPublicFor` -> `emitBoundaryWithPublicFor`
  (`.../load_store_v2/equations.zig:21-55`), evaluated by
  `component.zig` (OODS + domain) and `packed_rows.zig` (packed domain).
- Range16 mass admission: `Geometry.range16Mass`
  (`src/integrations/riscv_cpu/word16_execution/geometry.zig:69-76`) no longer
  counts boundary queries.
- Claim shape: boundary `range16`/`range8` claims must be zero in
  `Claims.validate` (`word16_execution/protocol.zig:74`),
  `validateCanonicalClaims` (`word16_execution/sources.zig:427`) and
  `Components.init` (`word16_execution/components.zig:47`), in addition to the
  AIR constant residuals (`equations.zig:53-54`).
- Transcript: `boundary_encoding.mix` (`.../load_store_v2/boundary_encoding.zig`)
  and per-shape widths (`word16_execution/protocol.zig:122,126`), plus
  `SCHEMA` (`word16_execution/protocol.zig:14`, mixed at `:116`).
- Diagnostic two-PCS boundary proof
  (`word16_execution/memory/global_boundary_proof.zig`): layout constants only.

## Invariants relied on

For every receiver that accepts a Word16 CPU proof containing an INIT or
TEARDOWN component bound to a public cell list `L`:

- I1 (native list validation). `L` is aligned (`address & 7 == 0`), strictly
  ascending (hence unique), and TEARDOWN addresses equal INIT addresses
  position by position; all `Cell` fields are typed (`u64` address/value,
  `u16` epoch, `u24` tick, `u2` rights), and the wire decoder rejects
  `tick >= 2^24` or `rights > 3` (`word16_execution/cells_wire.zig:66`).
- I2 (Fiat-Shamir order). `L` is absorbed before the MAIN root
  (`request.memory.digest()`, `word16_execution/protocol.zig:130`), and RAM
  challenges are drawn only after MAIN is committed: per execution
  `P.draw` after the MAIN commit (`word16_execution/execution.zig:199`); in
  the global/services lanes from the sealed manifest over every spec and MAIN
  root (`word16_global_execution/protocol.zig:35,46,72`;
  `services/protocol.zig:124`).
- I3 (exact claim). `claims.<kind>.ram == expectedClaim(L, sign, ram)` exactly
  (`.../load_store_v2/boundary_source.zig:153`), recomputed natively.
- I4 (AIR binding). `scalar.single` (`equations.zig:52`) forces
  `inverse_r * d(t_r) = 1` on every row and the signed prefix of
  `±active_r * inverse_r` to equal `claims.ram` (first/last anchored).
- I5 (activity). `active` is boolean, exactly `row_count = |L|` rows are
  active and they form a prefix (`equations.zig:45-50`).
- I6 (mass). Total LogUp mass is below the M31 characteristic
  (`word16_global_execution/protocol.zig:138`; boundary logs <= 22).

Where each receiver establishes I1 and I3:

| Receiver | I1 | I3 |
|---|---|---|
| Per execution (`word16_execution/execution.zig` `verify`) | `admission.validate` (`:178`) -> `Statement.validate` (`memory/statement.zig:40-47`, line 44) | `validateBoundary` (`:65-66`, called at `:200`) |
| Global RAM prefix (`word16_global_execution/execution.zig` `verify`) | `P.validateRequests` (`:143`) -> `validateInventory` (`protocol.zig:103-143`, line 140; INIT only on shard 0 `:127`, TEARDOWN only on last `:129`) | `:177` |
| Services / Ethereum (`ethereum/receiver.zig:38` -> `services/execution.zig:56`) | `P.admit` (`:61`) -> `G.validateMaterials` (`services/protocol.zig:69`) -> `validateInventory`; wire: `services/wire.zig:95` (core_schema), `:223` (`Cells.read`) | `services/execution.zig:102` |
| Keccak global (`keccak/execution.zig`) | `validate` -> `P.validateMaterials` (`:89`) | `:247` |
| Keccak shared truth (`keccak/shared/execution.zig`) | `admitCpu` -> `validateMaterials` (`keccak/shared/protocol.zig:48`) | `:364` |
| secp (`secp/execution.zig`) | `admit` -> `G.validateMaterials` (`secp/protocol.zig:52`) | `:351` |
| Diagnostic boundary proof (`memory/global_boundary_proof.zig`) | `specs` (`:102-103`) | `:230` |
| Prover self-check (`memory/prepared.zig:180`) | `Source.init` (`boundary_source.zig:63`) | same line |

`src/integrations/riscv_cpu/rv64_work_packet_body.zig` is the older
authenticated-execution packet, not a Word16 boundary consumer; its own
`validate` (`:69-75`) already enforces sorted, aligned cells and is unaffected.

No receiver computes the boundary claim from prover-supplied data without
native validation: `L` is always the typed public request list, validated by
I1 before any proof bytes are decoded, and the claim is recomputed from it.

## Argument

Let `T = {t_r : active_r = 1}` be the multiset of committed RAM14 row tuples
and `S = {tau(c) : c in L}` the canonical tuples of the public list
(`tau` = `Metadata.tuple`, the same projection the prover uses). By I4/I5 the
chip's claim equals `sum_r ±active_r / (z - <alpha, t_r>)`; by I3 it equals
`sum_{c in L} ±1 / (z - <alpha, tau(c)>)`. Both sides are rational functions
of the RAM challenges `(z, alpha)`; `T` is fixed by the MAIN root and `S` by
the transcript before the challenges are drawn (I2). Unless the two rational
functions are identical, Schwartz-Zippel bounds the probability of equality by
(total degree) / |QM31|, with degree at most a small multiple of the row
count (<= 2^22) against |QM31| ~ 2^124. Identity of the rational functions with
multiplicities below the characteristic (I5, I6) means `T = S` as multisets of
F^14 tuples.

Therefore the active rows are exactly a permutation of the canonical public
tuples: every address is canonical, aligned and unique, because I1 makes it so
for `S`. C1-C6 are implied. The order of rows is not observable: the chip's
only output is its signed debt in the execution-wide RAM LogUp sum, which is
permutation invariant. Downstream LS rows rely on "canonical aligned INIT
coverage" (`layout.zig` comment) only through RAM14 tuples entering that sum,
which are exactly `S`.

The removed range lookups also removed the chip's `range16` claim; leaving it
free would let a prover shift range-table debt into an unconstrained claim, so
it is pinned to zero in the AIR and natively (see Consumers).

## Evidence

- Adversarial proofs
  (`src/integrations/riscv_cpu/word16_execution/memory/boundary_anchor_test.zig`):
  for a noncanonical address limb, a duplicated address and an out-of-range
  value limb, a full CPU proof whose RAM claims are repaired to the ghost rows
  VERIFIES under the bare AIR (the removed checks are really gone) and is
  REJECTED by `Execution.verify` with `UntrustedWord16MemoryBoundaryClaim`;
  rebinding the claims to `expectedClaim` fails the AIR prefix binding. An
  unsorted permutation of the exact public set verifies end to end: same
  multiset, same statement. Nonzero boundary range claims are rejected by
  `Claims.validate`, `validateCanonicalClaims` and as a single nonzero AIR
  residual.
- Unsorted, duplicated or unaligned PUBLIC lists are rejected natively by
  existing tests (`word16_global_execution/adversarial_test.zig:133-141`,
  `GlobalTouchedSetMismatch`).

## Recursion / circuit-lane impact (not updated here)

- `load_store_v2.component.ComponentFor(C)` for circuit lanes, kinds
  `.initial`/`.terminal`: widths 3/23/20 -> 3/14/8, 47 -> 25 constraints, mask
  shape as above, and two constant claim residuals. Exercised by
  `test-riscv64-ls-circuit-lanes`.
- Every Word16 CPU proof's shape list (mixed into the transcript) and
  `rv64-word16-recursion-shape` output change for INIT/TEARDOWN.
- An in-circuit verifier of Word16 CPU proofs must perform I1 and I3 (as every
  native receiver does) to inherit this argument; the AIR alone no longer
  proves address uniqueness. No such verifier exists at this base.

Review reminder: this argument is a protocol-soundness claim; it should get an
independent review before the change is promoted.
