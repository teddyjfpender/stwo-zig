# RV64 admitted arith256_mod service (`ethereum_services_v3`)

Status: implemented in the Word16 services lane: truth AIR, bridge kind,
execution, tape, services lane, Ethereum driver planning and receiver policy.
It is qualified by unit, adversarial, bridge-closure and services-fixture
tests with a fresh receiver. Not yet run: a block-scale prefix proof with a
guest that uses the tag (see "Remaining gaps").

## ABI

- Tag `0x0003_0021` under `ethereum_services_v3` (v2 + SHA-256 + this tag).
  v1/v2 sessions keep trapping the tag (`UnsupportedService`).
- `a0` points to a **32-byte aligned** packet of 20 little-endian u64 words:
  `a[4] b[4] c[4] m[4] r[4]`, each value four LE limbs (limb 0 least
  significant). The candidate ABI allowed 8-byte alignment; the admitted bridge
  binds five aligned 32-byte coordinates.
- Effect: `r = (a*b + c) mod m`, and `r = 0` when `m = 0`. Words 0..15 are
  unchanged; words 16..19 receive r. One ECALL is one retired instruction and
  all registers are preserved.
- All 160 bytes need read permission and words 16..19 also need write
  permission. Every check precedes the write, so a trapping call changes
  nothing (tested for misaligned and read-only packets).
- ISA decode and ECALL effects are unchanged, so the Word16 CPU AIR and ROM are
  unchanged (v3 tapes run under the v2-decoded ROM, `tapeMatches`).

## Components

| Part | Where | Shape |
|---|---|---|
| Native execution | `rv64/ethereum_services/{session,arith256}.zig` | `Event.arith256_mod`, v3-only dispatch before secp |
| Tape and wire | `rv64/compact_tape{,_wire}.zig` | `arith256_mod_calls`; v3-only extension (u32 count + u32 reserved) between the secp and SHA-256 records; 352-byte records |
| Truth AIR | `rv64/air/delegations/arith256/` | one call per row, degree 3, own PCS, local BYTE table |
| Bridge | `rv64/air/delegations/secp256k1/word16_bridge/`, kind `.arith256_mod = 4` | shared Word16 Wire35 bridge: 5 rows per call, only coordinate 4 (r) written |
| Services lane | `word16_global_execution/services/*`, `word16_global_execution/arith256/roster.zig` | family 4, appended after SHA-256 |
| Native jobs / packets | `rv64_ethereum_batch.zig`, `rv64_ethereum_native_prepare.zig`, `rv64_work_packet_admission.zig`, `word16_execution/{packet,prepared}.zig` | separate arith counters and contiguous IDs |
| Ethereum driver | `word16_global_execution/ethereum/{plan,keys,main,role_cost,telemetry}.zig` | bridge logs, log16 truth spans, keys, `admitProfile` gate, cost rows |

## Truth AIR (one call per row)

Every 256-bit value is 32 little-endian byte columns. The row proves the exact
integer identity

    (1 - z) * (a*b + c) = q*m + r,     q < 2^512 (64 bytes)

and, when `z = 0`, `r < m`. `z` is the `m = 0` indicator.

| Group | MAIN columns | Range authority |
|---|---:|---|
| ACTIVE | 1 | Boolean, activity prefix |
| a, b, c, m | 128 | U8 via Wire35 from the bridge's BEFORE bytes |
| r_before (old r slot) | 32 | U8 via Wire35 (bridge BEFORE bytes of coordinate 4) |
| r | 32 | U8 via Wire35 (bridge AFTER bytes of coordinate 4) |
| q | 64 | local BYTE lookups |
| z, inv | 2 | z Boolean; inv a field element |
| carries lo, hi | 94 | local BYTE lookups on lo, hi and hi + 128 |
| d (= m - r - 1) | 32 | local BYTE lookups |
| borrows | 15 | Boolean |
| MULT | 1 | BYTE table multiplicity |
| **total** | **401** | |

FIXED (4, depend only on the log size): ROW, FIRST, LAST, BYTE = row mod 256.
INTERACTION: 122 cumulative QM31 columns (488 M31), two fractions each.

Constraints (209, every one of degree <= 3; composition native 2n):

- 17 Booleanity: ACTIVE, z, 15 borrows.
- m = 0 indicator: `z * Σm = 0` and `Σm * inv = active - z`. `Σm` is a sum of
  32 inherited bytes (< 2^13), nonzero in the field iff m != 0. A non-Boolean z
  is also excluded by these two alone.
- 48 identity groups. With `P_k = (1-z)(Σ a_i b_{k-i} + c_k) - Σ q_i m_{k-i} - r_k`
  (k = 0..94) and `G_j = P_{2j} + 256 P_{2j+1}`:
  `G_j + carry_{j-1} - 65536 carry_j = 0`, `carry_{-1} = carry_47 = 0`,
  `carry_j = lo_j + 256 hi_j - 16384 * active`. The `(1-z)` factor makes these
  degree 3.
- 16 r < m chunks (16-bit): `M_i - R_i - s_i - b_{i-1} + 65536 b_i - D_i = 0`
  with `s_0 = active - z`, `b_{-1} = 0` and no final borrow column, so
  `m - r - (active - z) = d >= 0`.
- 4 activity constraints (same as SHA-256): exactly rows `0..calls-1` active.
- 119 BYTE-chain batches and 3 Wire35-chain batches:
  `(C_b - C_{b-1}) d0 d1 - n0 d1 - n1 d0 = 0`. The BYTE chain wraps around the
  trace with **no claim** (it must close to zero); the Wire chain carries the
  public claim at FIRST.

Padding rows are all zero (the carry offset is multiplied by `active`), so no
identity equation needs an activity factor.

## Soundness argument

1. **Byte canonicality.** a, b, c, m and both r values appear only in Wire35
   tuples matched against the bridge's U8-range-checked BEFORE/AFTER bytes
   (same inheritance as SHA-256 OUT and secp `canonical_inputs`). q, d and the
   carry bytes are looked up in the local BYTE table. The BYTE challenge is
   drawn after the truth's MAIN root is committed (`drawTruth`), the chain is
   forced to close to zero, and the lookup mass `237 n < p` for `n <= 2^22`
   (checked in `validateGeometry`), so every queried value is in [0, 255].
   `hi + 128` in [0, 255] bounds `hi < 128`.
2. **Exact identity.** `|P_k| <= 32 * 255^2 + 255 = 2,081,055`, so
   `|G_j| <= 257 * 2,081,055 = 534,831,135`. Carries lie in
   `[-16384, 16383]`, so each group's field residual has integer magnitude at
   most `534,831,135 + 16,384 + 65,536 * 16,384 = 1,608,589,343 < p`. Each
   group therefore holds over Z, and telescoping gives `Σ P_k 256^k = 0`, i.e.
   `(1-z)(a*b+c) = q*m + r` over the integers. Honest carries satisfy
   `|carry| <= 8,161`, inside the range.
3. **Remainder.** For z = 0: each chunk equation is an integer equation
   (|terms| < 2^18); summing gives `m - r - 1 = d` with `d` a canonical
   256-bit value, so `r < m`. With `q, r >= 0`, `r < m` and the identity,
   `r = (a*b + c) mod m` (unique). For z = 1: m = 0, so the identity reads
   `0 = r`, hence r = 0 (q is free but byte-bounded).
4. **Binding to RAM.** The bridge (unchanged equations, kind 4) binds the real
   ECALL with `a7 = 0x30021`, the full 64-bit `a0`, 32-byte alignment, five
   non-wrapping coordinate addresses, authenticated RAM14 predecessors,
   readability of all 20 words, writability of words 16..19, and
   after = before with preserved rights for words 0..15. Wire35 tuples are
   `(kind 4, call ID, wire ID, 32 bytes)`: wires 0..4 are the five BEFORE
   coordinates (truth consumes them), wire 5 is the new r (truth produces it,
   bridge consumes the AFTER bytes of coordinate 4). Call IDs are
   `first_id + ROW` (truth) and `first_id + row/5` (bridge). The kind prevents
   substitution with secp/SHA-256 tuples under the shared challenge.
5. **Statement.** Family 4 is appended after SHA-256. `beginCpu` mixes an
   arith block (`0x57534134`, claim count 5, tag, calls, first ID, kind, log,
   widths) only when the bridge is present; `CpuClaims.count`/`mix` append
   five claims per present v3 bridge in `T.V3` order. `beginTruth` mixes the
   truth geometry (log, widths, constraint count, arity, kind, BYTE queries).
   Truth claims are `[wire claim, 0, 0]`; the zero slots are receiver- and
   wire-checked. Admission adds 40 RAM terms and 6 + 6 Wire35 terms per call.

## Measured cost (exact layout cells)

| Part | Per call | Notes |
|---|---:|---|
| Truth MAIN + INTERACTION | 889 | 401 + 488 per row (+4 FIXED, key material) |
| Bridge MAIN + INTERACTION | 1,890 | 5 rows x (134 + 244) (+5 x 8 FIXED) |
| **Total, unpadded** | **2,779** | = 18.0 instructions at 154.8 cells/instruction |
| Estimate it replaces | 6,500 | `proposals/candidate-service-costs.json` |

The RAM transitions are inside the bridge rows (RAM28 per lane), so there is no
separate 96-cell closed_ram term per word as in the estimate; boundary
INIT/TERM cells are per touched word, not per call. The bridge's 26 U16 and
73 U8 range queries per row go into the CPU's existing shared range tables.

Padding: the truth pads to a power of two of at least 256 rows (the BYTE
table), the bridge to a power of two of `5 * calls + 1` rows. At 319 calls
(the Rust-guest count on block 24,628,607) this is 512 truth rows (455,168
cells) plus 2,048 bridge rows (774,144 cells): **3,853 cells per call padded**.
The cost entry should use 2,779 cells per call (the proxy convention for
Keccak/secp is the unpadded per-call share) with 3,853 as the padded upper
reference at this call count.

## Evidence

- `zig build test-riscv64-arith256-truth`: known answers on >1,000 edge and
  random inputs (0, 1, 2, 255, 2^64, 2^128-1, 2^255, 2^256-2, 2^256-1, P-256,
  secp256k1 n, BN254 p, m-1 squares) against two independent big-integer
  references; adversarial rows: wrong r, r >= m (only rejected through the
  out-of-range d byte; with canonical d the top chunk fails), wrong q with
  mod-2^256 wraparound, m = 0 forgeries (nonzero r, z = 0, non-Boolean z,
  z = 1 with m != 0), non-canonical q and d limbs and carry forgery
  (out-of-range BYTE queries), every single-cell perturbation, the activity
  prefix, full-trace residuals and Wire claim equality, a forged BYTE
  multiplicity, packed 16-lane vs scalar equality and an exact degree-3 bound.
- `zig build test-riscv64-word16-arith256-bridge`: bridge residuals vanish for
  random packets (one with m = 0); bridge + truth Wire35 claims sum to exactly
  zero; a forged r, a changed r_before or an offset call-ID span do not close;
  read-only writes, unwritable r and misalignment are rejected.
- `zig build test-riscv64-word16-arith256-services -Doptimize=ReleaseSafe`:
  two v3 shards (SD, arith, arith | SD, arith) on one cross-page packet; the
  second call re-reads the r the first wrote and the last call has m = 0.
  Real CPU, bridge and truth proofs verify; the bundle round-trips the durable
  wire and verifies with freshly constructed keys; a receiver without the
  bridge, with a SHA-256 bridge instead, or with a truth key of another size
  rejects it; nonzero unused truth claims are rejected; split truth spans
  verify and swapped spans do not; a false r and a nonzero r for m = 0 fail
  global Wire35, a forged input word fails global RAM, a wrong pointer fails
  CPU OWNER closure.
- `zig build test-riscv64-execution`: session (v2 trap, v3 result, m = 0,
  atomic traps), packet semantics vs the candidate executor, tape-wire round
  trips with arith records and pre-v3 rejection.
- v2 identity: see "v2 byte-identity" below.

## v2 byte-identity

V2_IDENTITY_PLACEHOLDER

## Remaining gaps

- No block-scale prefix proof with a guest that issues the admitted tag. The
  guest routing (32-byte aligned packets under `ethereum_services_v3`) and a
  basket run on the admitted profile are not done here.
- Debug builds of the services tests overflow the 1 MiB worker stack inside
  the existing division-product evaluator (`division/word16_product`); the
  same suites pass in ReleaseSafe. This affects the combined suite too and is
  not specific to this family.
- Recursion circuits do not support the family (like SHA-256 and bulk memory).
- Merge points with bulk memory: `T.Family` ordinal 4, Wire35 kind 4 and the
  tape-wire v3 extension's reserved word must be reconciled if that branch
  also claims them.
- The per-call cost is exact layout arithmetic, not a whole-block measured
  `cost.json` from the driver.
