# M7 profile notes §8: fused Blake2s compression component `fused_blake2s_v1`

*Stream blake-gadget, M5 (an M7 lever pulled forward), 2026-11-04. Extends `rv64-m7-profiles.md` (§1–§7, owned by stream profiles) with the soundness argument for the fused Blake2s AIR. It is a separate file so that the profiles stream stays the only writer of `rv64-m7-profiles.md`; profiles should link it as §8 at its next edit.*

Labels: **[M]** measured (a receipt exists), **[D]** arithmetic on measured numbers, **[E]** estimate.

## 8.0 What changes, and what does not

- **Not a hash change.** Blake2s-256 with 10 rounds, the RFC 7693 IV, σ schedule and parameter block. Every outer profile keeps its security label, because the Merkle and channel hash is unchanged.
- **AIR change.** In a circuit (outer) proof, one compression is today 80 `blake_g_gate` rows and 8 `triple_xor` rows. Every intermediate state word travels through the Gate wire relation (6 uses and 4 yields per G). Under `fused_blake2s_v1` a compression is **one row** of the `fused_blake2s` component:
  - 3,328 main columns;
  - 2,752 interaction columns (1,376 lookups, paired);
  - 45 preprocessed columns;
  - 640 constraints of degree ≤ 3.
- **What is new in the relation set:**
  - two 2^16-row tables, `VerifyBitwiseXor_8_Split4` (id 734258691) and `VerifyBitwiseXor_8_Split7` (id 1830449294). Each id is `blake2s(name)[0..4] LE & 0x7fffffff`; a test checks the derivation and that neither collides with an existing id;
  - plain XOR reuses the circuit's `VerifyBitwiseXor_8` (id 112558620, 2^16 rows).
- **Profile/VK.** A proof that commits `fused_blake2s` rows is a new circuit shape. It must carry a new outer profile/VK field (`outer_blake = fused_v1`, see `M5-INTERFACES.md` §blake-gadget). Receivers must refuse a fused proof under any profile that does not name it, and vice versa. Old proofs (`outer_blake = g_gate`) stay valid under their own profile.

## 8.1 Statement proved by one row

Let the row's cells be **c** and its preprocessed values be:
- `addr_h[8]`, `addr_m[16]`, `addr_out[8]`, `mult_out[8]`;
- `v12` bytes (= IV[4] ⊕ t0);
- `last ∈ {0,1}`.

**Claim (local soundness).** If every constraint of the row holds over M31, and every XOR lookup tuple of the row lies in its table, then the 8 output words read from the row equal `Blake2s_compress(h, m, t0, last)`. Here `h` and `m` are the integers whose 16-bit limbs appear in the row's Gate-relation use tuples.

**Proof sketch** (the row program is `fused_blake2s_v1.zig`; each step is a separate check):

1. **Bytes.** Every byte cell is an argument of a byte XOR table whose rows contain only bytes, so the cell is in [0, 256). That holds for every add result, XOR output, `h` byte and output byte. Split cells are bounded by their tables: `lo < 2^s` and `hi < 2^(8−s)`.
2. **Limbs.** Each 16-bit limb is `b0 + 256·b1` with bytes `b0`, `b1`, so it is in [0, 2^16). Message limbs are committed directly as u16 cells, and their range comes from the Gate relation. A use tuple matches only a yield of a u32 wire `(lo, hi, 0, 0)`, and every u32 wire's yield is range-checked where it is produced (`m31_to_u32` or a prior compression's output bytes). This is the same trust today's G gate places on `f0`/`f1`.
3. **Additions without carry cells.**
   - For `r = Σ op mod 2^32` with n ∈ {2, 3} operands, the low half's carry is `e_lo = (Σ op_lo − r_lo)·2^-16` and the high half's is `e_hi = (Σ op_hi + e_lo − r_hi)·2^-16`.
   - The constraints `∏_{k=0}^{n−1}(e − k) = 0` force `e ∈ {0..n−1}` in M31.
   - All limbs are < 2^16, so `Σ op_lo − r_lo` lies in (−2^16, 3·2^16) as an integer, far below p = 2^31 − 1. So `e_lo·2^16 = Σ op_lo − r_lo` holds over the integers. The same holds for the high half with `e_lo ≤ 2` added.
   - Hence `r_lo + 2^16·r_hi ≡ Σ op (mod 2^32)`, and the carries add no prover freedom because they are not cells.
4. **XOR and rotations.**
   - The `VerifyBitwiseXor_8` table fixes `z = x ⊕ y` byte-wise.
   - `rotr16` and `rotr8` are byte permutations of the XOR output.
   - `rotr12` and `rotr7` recompose the split halves, `hi_{j+1} + 16·lo_{j+2}` and `hi_j + 2·lo_{j+1}`, which are exactly the rotated bytes when the split tables hold. Each recomposed byte is < 256, and it feeds a later table lookup that re-checks it as a byte.
5. **Counter and flag.** `v12` is 4 preprocessed bytes, and `v14` is `iv + last·(255 − 2·iv)` byte-wise, which is linear in the 0/1 preprocessed flag. Both are setup-fixed, as today's interned constants are.
6. **Composition.** Steps 3–5 applied to the 80 G steps and the 8 final double-XORs in program order compute the RFC 7693 compression. The completeness tests check this.

**Soundness smoke tests [M]** (`fused_blake2s_v1.zig`):
- All 13,312 single-cell perturbations of an honest row are rejected (3,328 cells × deltas {+1, −1, +256, +2^16}). Each is rejected by a local constraint, a table lookup, or a changed Gate tuple. At most 128 escape the local checks; those are message-limb changes, which the Gate relation binds.
- These negative rows are rejected: a wrong digest with a valid byte encoding; a byte smuggled as 256 + (limb borrow); a flipped `last`; a different `t0`.
- On the GPU, 27 of 27 single-cell corruptions are caught by the device checker.

## 8.2 Wiring (global soundness)

- **Inputs and outputs.**
  - `h` and `m` enter only as Gate-relation **uses** `(addr, lo, hi, 0, 0)`.
  - The 8 output words leave as **yields** with preprocessed multiplicities `mult_out`, at addresses `addr_out`.
  - This is exactly the interface of today's G-gate chain, seen from outside the compression.
- **No intermediate wires.** No intermediate wire exists, so no new address, multiplicity or permutation obligation is introduced. The Gate relation loses 76 % of its traffic: per compression, 32 tuples instead of 80·10 + 8·4 = 832.
- **Padding rows.**
  - A padding row is an honest fill of the zero compression (h = 0, m = 0, t0 = 0, last = 0).
  - It uses address 0, the zero wire, 24 times, and yields with multiplicity 0.
  - The zero wire's multiplicity must count those uses. This is the same convention as today's padded G rows, and circuit construction (canon-vk) owns it.
- **Instances.** A node's compressions are split over at most 3 power-of-two instances of the same AIR (`planInstances`).
  - Each instance is a separate component with its own log size.
  - Log sizes are **circuit constants per (family, rung)**, which is plan §4.2. They are never guessed.
  - The instance split therefore changes no binding argument, only the component list of the class.
- **XOR table multiplicities** are prover-committed columns. They are checked only by the LogUp sum, as today.

## 8.3 Error terms

- **LogUp `M/|F|` term.** Lookups per compression fall from 80·26 + 8·12 = 2,176 to 1,376. The circuit's LogUp soundness term `≈ (total lookups)/|F_ext|` per relation therefore shrinks by about 37 % on Blake traffic. Table sizes are unchanged (2^16), plus two new 2^16 tables.
- **Composition degree.** The fused main constraints have degree ≤ 3. The circuit's paired LogUp interaction constraints already reach degree 3: the cumulative difference times two linear denominators. So the composition degree bound, and with it the profile's blowup argument, should be unchanged. canon-vk must confirm this against the circuit's composition bound when it wires the component; it is listed as obligation 2a below.
- **FRI/PCS.** No change; the profile's query and blowup terms apply as stated in §1.
- **Width.** Parents open 6,080 more columns per child query than today's 311.
  - That is a cost, not a soundness term. The diet census put it at +174 M cells per verified child at q51 and +369 M at q108 [D].
  - This is why the combined fused + outer-GKR configuration (GKR removes the 2,752 interaction columns) is the target. Without GKR, a k = 2 layout is the fallback (×0.61 tree at q51 [D]).

## 8.4 Obligations before a proof-format merge (M7)

1. canon-vk adds the circuit-construction record, the component and the two tables to the component list and the circuit hash, and a new profile field. Receivers refuse a mismatch.
2a. canon-vk confirms that the circuit's max constraint degree bound admits degree 3 for a main-only constraint.
2. The in-circuit verifier gains the fused AIR's constraint evaluation at the OODS point. It must be generated from `fused_blake2s_v1.zig`'s `Eval`, and a differential test must check it against `Eval` on random rows.
3. The negative corpus (`scripts/rv64_m5_negative_corpus.py`) gains:
   - a fused row with a wrong output word;
   - a padding row with a non-zero `mult_out`;
   - a proof whose profile says `g_gate` but whose VK has `fused_blake2s`.
4. A fresh-receiver acceptance on both dev blocks, under the named profile.
5. **Until 1–4 are done, the only production path is the shadow flag** (`STWO_RV64_FUSED_BLAKE=shadow|check`). It does not change proof bytes; see the receipts under `vectors/reports/rv64-m5-20261104/blake-gadget/`.
