# RV64 v3 curve and field services (BN254, BLS12-381, arith384_mont)

Status: truth AIR, Word16 bridge kinds and services-lane families implemented;
see the curves handover (`autoresearch/guest_efficiency/handover/prover-curves.md`)
for what is verified and by which command.

## 1. Operations and ABI

Seven admitted `ethereum_services_v3` operations, one services family, Wire35
program kind and Word16 bridge kind each (ordinal = `curves.Op`):

| Kind | Op | Tag | Packet (inline, 32-byte aligned) | Written |
|---:|---|---|---|---|
| 5 | `bn254_g1_add` | `0x30100` | `[x1 y1 x2 y2]` (32 B each, plain) | `x3 y3` over `x1 y1` |
| 6 | `bn254_g1_double` | `0x30101` | `[x y]` | `x3 y3` |
| 7 | `bn254_fp2_mul` | `0x30102` | `[a0 a1 b0 b1]` | `c0 c1` over `a0 a1` |
| 8 | `bls12_381_fp2_mul` | `0x30112` | `[a0 a1 b0 b1]` (48 B each) | `c = a b 2^-384` per coefficient |
| 9 | `arith384_mont` | `0x30121` | `[a b m pad16]` (48 B each) | `r = a b 2^-384 mod m` over `a` |
| 10 | `bls12_381_g1_add` | `0x30110` | `[x1 y1 x2 y2]` (48 B, Montgomery) | `x3 y3` |
| 11 | `bls12_381_g1_double` | `0x30111` | `[x y]` (48 B, Montgomery) | `x3 y3` |

Change from the execution-only candidates (`notes/candidate-curves-abi.md`):
packets are **inline** and 32-byte aligned instead of pointer packets, because
the Word16 bridge binds contiguous 32-byte coordinates at `a0`; pointer
indirection would need a new bridge. The guest glue copies operands into an
aligned packet. Preconditions (trap `CurveDomain`, the AIR is then
unsatisfiable): curve coordinates `< p`; `x1 != x2` (add); `y != 0` (double);
`m` odd (`arith384_mont`). There is no point at infinity: the guest handles
`O`, `P = Q` and `P = -Q` before calling; `(0,0)` is an ordinary formula input.

Geometry authority: `ethereum_services/curves.zig` (execution) and
`air/delegations/curves/spec.zig` (`def`, comptime-checked against each other).

## 2. Truth AIR (`air/delegations/curves/`)

One generic, comptime-specialised AIR: one call per row, degree 3, own PCS,
local BYTE table (fixed column `row mod 256` plus a MULT column). Every op is a
fixed list of exact integer relations over little-endian byte limbs

    sum_t coef_t a_t b_t + sum_s coef_s (v_s << 8 shift_s) + K p - q M = 0

with `M` the constant field modulus or the packet operand `m`. Affine add:
`l (x2 - x1) = y2 - y1`, `l^2 = x1 + x2 + x3`, `l (x1 - x3) = y1 + y3`; double:
`2 l y = 3 x^2`, `l^2 = 2x + x3`, `l (x - x3) = y + y3`. Montgomery ops shift
every linear term by 48 bytes (`* 2^384`) and use the Montgomery residue of the
slope, so `R` cancels in the quadratic sides. `K p` (comptime) keeps `q >= 0`.

### 2.1 Exactness certificate (per relation, comptime)

`spec.deriveRelation` bounds, for each coefficient index `k`, the positive part
`P_k` and negative part `N_k` of the coefficient using `255` for every byte
(inputs/outputs/witnesses/quotients) and `255 * 255 * #pairs` per product, and
groups 2 (else 1) coefficients into one carried equation of radix `R = 256^g`:

    G_j + c_{j-1} - R c_j = 0   (mod 2^31 - 1),   c_{-1} = c_last = 0.

Carries are encoded as `carry_bytes` BYTE-queried bytes of
`c + 2^(bits-1)` (the top byte additionally shifted so it is `< 2^top_bits`),
so `|c_j| <= 2^(bits-1)`. The certificate (checked at comptime and by the
`geometry` test) is

    max_j max(|P_j|, |N_j|) + 2^(bits-1) (R + 1) < 2^31 - 1,

so each group equation holds over the integers, and telescoping gives the
integer relation exactly; `bits` is the smallest width covering the honest
carry bound. Any limb outside `[0,256)` breaks the bound, so every byte that
enters a product is ranged: witnesses, quotients, carries and `D` bytes by the
local BYTE table; packet inputs and outputs by the Word16 bridge (32 U8 queries
on BEFORE and on AFTER, bound to the truth through Wire35).

### 2.2 Canonical outputs and inputs

`x + D + 1 = M` over 16-bit chunks with Boolean borrows and no final borrow,
`D` BYTE-ranged: proves `x < M`. Applied to every output and, for G1 ops, to
every input coordinate. Without it `x + M` (same residue) would be accepted.

### 2.3 Nonzero proof and odd modulus

`x2 - x1 != 0` (add) / `y != 0` (double): one-hot chunk selector (Boolean,
sum = active) and an inverse column, `sel . chunk(delta) * INV = active`. Both
operands are canonical, so a nonzero chunk difference means the residues
differ. `arith384_mont`: `m_0 = 2 HALF + 1`, `HALF < 128` (two BYTE queries
HALF, HALF+128), and `r < m` by 2.2 with the variable modulus.

### 2.4 Why a zero `y`, equal `x` or even `m` is unsatisfiable

Equal x: every chunk difference is zero, so no selector choice can satisfy the
inverse equation. y = 0: same. Even m: low byte of m is even, contradicting
`m_0 = 2 HALF + 1` with `HALF` an integer `< 128`. Tested exhaustively over
selector choices / HALF values.

## 3. Bridge and services lane

Bridge kinds 5..11 reuse the Word16 Wire35 bridge unchanged
(`secp256k1/word16_bridge`): `coordinates(kind) = curves.coords(op)`, the
leading `curves.writtenCoords(op)` are written, after-values publish as Wire35
IDs `coords + c`. The truth consumes the before tuples (IDs `0..coords-1`) and
produces the written after tuples. Services families 5..11 follow
`arith256_mod` in `services/types.zig`; each mixes only when present, so v2 and
curve-free v3 transcripts, claims and wire bytes are unchanged. Truth keys
depend only on (op, log) (`curves/roster.zig`, `ethereum/keys.zig`).

## 4. Joint REG/RAM write induction: case C7 (curve writers)

[rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md) needs every
RAM producer to be independently anchored or to depend only on strictly earlier
tokens, and every producer tick to be `4r'+4` (P1).

- **Ticks.** Curve after-tokens are bridge RAM tokens with the OWNER-bound ECALL
  tick (`TICK = LOW + 65536 HIGH`, continuation equality across the coordinate
  rows of one call) exactly as for secp ADD/DOUBLE. P1 holds.
- **Written words (independent anchor).** Each after-limb is
  `AFTER[2c] + 256 AFTER[2c+1]` (`word16_bridge/equations.zig` `ramRow`), and
  all 32 AFTER bytes of every bridge row are in the bridge's U8 list
  (`word16_bridge/layout.zig`, `U8` covers `BEFORE..AFTER+32`). So every
  written limb is in `[0, 2^16)` independent of the IH — the same anchor as
  the secp and SHA-256/arith256 bridges. The truth's own canonicity
  (`x < p` / `r < m`, 2.2) is a field-level fact on top of this; RAM limb
  canonicity does not depend on it.
- **Unwritten coordinates and read-only words.** `after = before` with the
  before token consumed from RAM (`tau(before) < tau(after)`, P2): IH.
- **OWNER/REG.** Curve bridges supply ECALL C = 0 (owner tuple limbs 13..16 are
  zero) and no REG token, so P4 is unaffected.
- Tested by `joint_write_invariants_test.zig` ("LS32 curve/field producers
  (kinds 5..11) ...": tick perturbation produces a new residual, every AFTER
  byte is U8, owner C limbs are zero) for every curve kind.

So the lemma extends with no new edge (the curve writer is anchored). Giving the
curve bridge unranged after columns, or letting the truth write RAM directly,
must re-open the lemma.

## 5. Tests (`zig build test-riscv64-curves-truth -Doptimize=ReleaseSafe`)

Independent std.math.big oracle and candidate-executor agreement for all 7 ops;
group law (`[r-1]G = -G`, points on curve); wrong outputs, non-canonical outputs
(`x + M`), wrong slopes; equal x / y = 0 / non-canonical inputs; even modulus,
`r >= m`, non-canonical quotient limbs (carries re-derived by the forger: only
the q BYTE range rejects); carry forgery (field-solved carries for a wrong
output); `P = Q`, `P = -Q` and `(0,0)` inputs; tag injectivity and wrong-kind
Wire35 sums; every single-cell perturbation; activity prefix; interaction claim
and residuals; packed = scalar and degree <= 3.

## 6. Costs (measured layout, cells per call)

| Op | MAIN | INTERACTION | Truth cells | Bridge coords x 378 | Total |
|---|---:|---:|---:|---:|---:|
| bn254_g1_add | 812 | 1,224 | 2,036 | 4 x 378 | 3,548 |
| bn254_g1_double | 720 | 1,164 | 1,884 | 2 x 378 | 2,640 |
| bn254_fp2_mul | 478 | 648 | 1,126 | 4 x 378 | 2,638 |
| bls12_381_fp2_mul | 912 | 1,176 | 2,088 | 6 x 378 | 4,356 |
| arith384_mont | 520 | 736 | 1,256 | 5 x 378 | 3,146 |
| bls12_381_g1_add | 1,416 | 2,044 | 3,460 | 6 x 378 | 5,728 |
| bls12_381_g1_double | 1,274 | 2,228 | 3,502 | 3 x 378 | 4,636 |

## 7. Not done

Recursion (same gap as SHA-256/arith256); the program-identity binding of the
v3 profile (receiver policy today).
