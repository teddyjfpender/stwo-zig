# RV64 secp256k1 row truth (`row_v1`, v3)

Status: implemented; fixture-qualified (AIR + services lane, fresh wire
receiver). Real-prefix numbers: see "Measured". v2 and every existing bundle
keep the RCB product/linear/BYTE truth byte-for-byte.

## What changes

The Word16 secp bridge, its Wire35 tuples `(kind 1|2, call ID, wire ID, 32 LE
bytes)`, the RCB program authority (`ethereum_services/secp256k1.zig`, k256
0.13.4 homogeneous XYZ, b3 = 21) and the guest ABI are unchanged. Only the
truth that consumes the bridge's before-coordinates and produces its written
after-coordinates changes:

- RCB profile (unchanged, v2 and v3): one product row per multiplication and
  one linear row per add/sub/reduce, 284/128 BYTE limbs per row, internal
  wires closed by Wire35 inside the truth, a separate BYTE provider.
- Row profile (new, v3): one call per row on the generic curve/field truth
  authority (`air/delegations/curves`, keyed by `curves.spec.SecpKind`).
  `curves.spec.secpDef` writes the RCB formulas as exact carried integer
  relations over byte limbs:

  ADD `[X1 Y1 Z1 X2 Y2 Z2] -> [X3 Y3 Z3 X2 Y2 Z2]`, witnesses
  `xx = X1X2, yy = Y1Y2, zz = Z1Z2, xy = X1Y2 + Y1X2, yz = Y1Z2 + Z1Y2,
  xz = X1Z2 + Z1X2`, then `X3 = xy yy - 21 xy zz - 21 yz xz`,
  `Y3 = yy^2 - 441 zz^2 + 63 xx xz`, `Z3 = yz yy + 21 yz zz + 3 xx xy`.

  DOUBLE `[X Y Z] -> [X3 Y3 Z3]`, witnesses `yy = Y^2, zz = Z^2, xy = XY,
  yz = YZ, ym = yy - 63 zz`, then `X3 = 2 xy ym`,
  `Y3 = ym yy + 21 ym zz + 168 yy zz`, `Z3 = 8 yy yz`.

  These are the program's expressions expanded (e.g. `(yy + 21zz)(yy - 21zz)
  = yy^2 - 441 zz^2`), so every output equals the program's canonical value.
- Interaction: three fractions per degree-4 batch (curve ops keep two per
  degree-3 batch and are byte-identical), native 4n composition, as the RCB
  truth already was.

## Soundness argument

1. Exactness. Each relation `sum coef a b + sum coef v + K p - q p = 0` is
   checked as carried group equations; `spec.deriveRelation` certifies at
   comptime that with every limb in [0, 256) and every carry in its encoded
   range the group sums are below 2^31 - 1, so the group equations hold over
   the integers and telescope to the integer relation (same certificate as the
   curve ops; `geometry` test). Witness, quotient, carry (and shifted top-byte)
   and D limbs are local-BYTE ranged.
2. Residues. Each relation holds mod p, so witnesses are bound by residue only
   (a witness alias w + p is harmless); raw packet words (any 256-bit value)
   enter by residue, exactly the program's `reduce_once` since raw < 2^256 < 2p.
3. Canonical outputs. `x + D + 1 = p` over 16-bit chunks with Boolean borrows
   and no final borrow, D BYTE-ranged, proves each output < p. Without it the
   alias x + p (possible when x < 2^256 - p, e.g. X3 = 0) would be accepted.
4. Packet bytes. PACKET/OUT limbs are not locally ranged: they are the 32-byte
   payloads of Wire35 tuples whose only other participant is the Word16 bridge
   (U8 on all BEFORE and AFTER bytes). With admitted total Wire35 mass < p and
   unit weights, closure makes the truth's consumed and produced multisets equal
   the bridge's, so every PACKET/OUT limb is a ranged bridge byte (the premise
   of the RCB `canonical_inputs` policy and of the curve truths). Output wire
   IDs are the program's output wires (`bridge.outputWire`), all >= coords, so
   no truth fraction can cancel another.
5. LogUp. Denominators are drawn after the truth MAIN root (`drawTruth`,
   domain `0x53524231`); BYTE mass = queries x rows < p and Wire35 mass are
   admitted by `validateGeometry`/`protocol.admit`/`wire.validateDeclarations`.
6. Identity. Wire `logs = .{ log, 0 }` (`row_roster.PROFILE_WORD`); an RCB
   linear log is never 0, so a declaration names exactly one profile. The
   truth spec mixes `0x53524f57` + geometry words, distinct from the RCB words.
   `ethereum.main.admitProfile` rejects row declarations under v2. The fixed
   tree is the curve `(ROW, FIRST, LAST, BYTE)` columns of the declared log.

Not changed / not claimed: whole-protocol security accounting
(`rv64-whole-protocol-security-policy.md`); recursion leaves for secp truths
(missing for the RCB profile as well).

## Planner

`ethereum/plan.zig`: under `ethereum_services_v3` each family takes row spans
iff their total cells are below the RCB truths' for the same calls; a span is
split at the next smaller power of two when that saves at least 1/8 of its
cells (padding only; `secpRowSpan`).

## Tests

- `test-riscv64-curves-truth`: the generic curve tests run on both secp keys
  (geometry, wrong outputs, single-cell perturbation, interaction claim and
  residuals, packed = scalar and degree = Layout.DEGREE, carry forgery);
  `secp_tests.zig`: RCB-program agreement on raw coordinates (>= p included),
  group law (ADD(P,P) = DOUBLE(P), P + -P has Z3 = 0, identity, curve walk),
  zero outputs forged as p, wrong output/witness limbs, Wire35 identity equal
  to the bridge's.
- `test-riscv64-word16-v3-services` (`secp_row_test.zig`): combined fixture
  (Keccak-f then ADD and DOUBLE of its raw output words) proves and verifies;
  durable wire with fresh keys; an RCB receiver, swapped kinds, a larger key
  and a nonzero unused claim slot are rejected; a false DOUBLE output word
  leaves Wire35 unclosed.
