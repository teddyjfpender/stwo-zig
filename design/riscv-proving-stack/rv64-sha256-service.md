# RV64 admitted SHA-256 compression service (`ethereum_services_v3`)

Status: implemented in the Word16 services lane. It is qualified by unit,
adversarial and services-fixture tests with a fresh receiver. See "Evidence"
and "Remaining gaps" below for what is and is not established.

## ABI

- Profile `ethereum_services_v3` = `ethereum_services_v2` (Keccak-f `0x0001_0001`,
  LE-word secp ADD/DOUBLE `0x0002_0011/12`) plus `sha256_compress`, tag
  `0x0003_0010`.
- `a0` points to a **32-byte aligned** packet of 12 little-endian u64 words.
  The candidate ABI only required 8-byte alignment; the admitted bridge binds
  three aligned 32-byte coordinates.
  - Words 0..3 hold H0..H7 as little-endian u32 pairs, with H0 in the low half
    of word 0.
  - Words 4..11 hold the 64-byte block in stream order.
- One ECALL is one retired instruction. Registers are preserved. Words 0..3
  receive the new state and words 4..11 are unchanged.
- All 96 bytes need read permission, and words 0..3 also need write permission.
  A trapping call changes nothing.
- ISA decode and ECALL effects are identical to v2, so the Word16 CPU AIR and
  ROM are unchanged.

## Components

| Part | Where | Shape |
|---|---|---|
| Native execution | `rv64/ethereum_services/{session,sha256}.zig` | `Event.sha256`, v3-only dispatch before secp |
| Tape and wire | `rv64/compact_tape{,_wire}.zig` | `sha256_calls`; count in the formerly reserved header word, v3 only; 224-byte records |
| Truth AIR | `rv64/air/delegations/sha256/` | one compression per row, own PCS |
| Bridge | `rv64/air/delegations/secp256k1/word16_bridge/` with kind `.sha256` | the shared Word16 Wire35 bridge: 3 rows per call, only coordinate 0 written |
| Services lane | `word16_global_execution/services/*`, `word16_global_execution/sha256/roster.zig` | family 3, appended after the v2 roster |
| Ethereum driver | `word16_global_execution/ethereum/*` | plan, keys, `admitProfile` receiver gate |

## Truth AIR layout (one compression per row)

FIPS 180-4 is unrolled with two shift registers: `A_j` and `E_j` for
`j = -4..63`, with `A_{-1..-4} = H0..H3` and `E_{-1..-4} = H4..H7`. For each
round `t`:

- `E_t = A_{t-4} + E_{t-4} + Σ1(E_{t-1}) + Ch(E_{t-1},E_{t-2},E_{t-3}) + K_t + W_t`
- `A_t = E_{t-4} + Σ1 + Ch + K_t + W_t + Σ0(A_{t-1}) + Maj(A_{t-1},A_{t-2},A_{t-3})`
- The output is `H_i + (A_63, A_62, A_61, A_60, E_63, E_62, E_61, E_60)[i]`.

MAIN columns, 7,409 in total:

| Group | Columns | Notes |
|---|---:|---|
| ACTIVE | 1 | Boolean activity prefix |
| W_0..63 bits | 2,048 | the message schedule |
| A_{-4..63} bits | 2,176 | |
| E_{-4..63} bits | 2,176 | |
| Schedule carries | 192 | t = 16..63: low/high, 2 bits each (carry ≤ 3) |
| Round carries | 768 | E and A, low/high, 3 bits each (carry ≤ 6) |
| Feed-forward carries | 16 | Boolean low/high per word |
| OUT bytes | 32 | new state, little-endian |

- FIXED has 3 columns: ROW, FIRST, LAST. They depend only on the log size.
- INTERACTION has 8 columns: two cumulative QM31 sums.
- K_t are constants inside the constraints, so they need no columns.
- Padding rows hold an honest compression of the zero state and zero block,
  so no SHA equation needs an activity factor.

Constraints: 7,751 in total, all of degree ≤ 3. The composition is native 2n
(`compositionLogSplit = 1`) in the truth's own PCS.

- 7,377 Booleanity constraints (degree 2).
- 96 schedule equations. Each 16-bit half of `W_t + 2^16·c` equals the half of
  `σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}` (+ the low carry). σ bits
  are XOR3/XOR2 polynomials, degree ≤ 3.
- 256 round equations. Σ bits are XOR3 (degree 3). `Ch = z + x(y − z)` has
  degree 2. `Maj = xy + z·(x ⊕ y)` has degree 3.
- 16 feed-forward equations with Boolean carries.
- 4 activity equations. They use the previous row of ACTIVE only:
  - `FIRST·(1−a)`
  - `(1−FIRST)·a·(1−a_prev)`
  - `a_prev·(1−a)·(ROW − calls)`
  - `LAST·a`

  Together they force exactly rows `0..calls−1` active, with `calls < n`.
- 2 LogUp batch equations of degree 3:
  - `(C0 − C1_prev + claim·FIRST)·d0·d1 + a·(d0 + d1) = 0`
  - `(C1 − C0)·d2·d3 + a·(d3 − d2) = 0`

Exactness: every half-sum is below `8·2^16 < p`, so each field equation is an
integer equation. Given Boolean bits (so each half is canonical in `[0,2^16)`)
and a carry of at most 7, the half is the sum mod 2^16 and the carry is its
floor. The high carry is discarded (mod 2^32).

## Wire35 binding

Tuple: `(program kind = 3, call ID, wire ID, 32 bytes)`.

| Wire | Bytes | Truth side (linear in MAIN) | Bridge side |
|---|---|---|---|
| 0 | state H0..H7, little-endian | bytes of the `A_{-1..-4}`, `E_{-1..-4}` bits | coordinate 0 BEFORE bytes |
| 1 | block bytes 0..31 | big-endian bytes of the `W_0..7` bits | coordinate 1 BEFORE bytes |
| 2 | block bytes 32..63 | big-endian bytes of the `W_8..15` bits | coordinate 2 BEFORE bytes |
| 3 | new state | OUT | coordinate 0 AFTER bytes |

- The truth consumes wires 0..2 (−active) and produces wire 3 (+active). The
  bridge produces its BEFORE tuples (+1) and consumes coordinate 0's AFTER
  tuple (−1).
- The call ID is `first_id + ROW` on the truth side and
  `first_id + row/3` on the bridge side.
- The receiver requires the sum of all bridge and truth Wire35 claims to be
  zero. The ADD, DOUBLE and SHA-256 kinds share one challenge but cannot
  substitute for each other, because the kind is the first tuple element.

What each lookup proves:

- **Inputs.** The truth's state and message bits are exactly the bytes that
  the bridge read from RAM. The bridge's bytes are U8-range-checked, and each
  truth byte is a Boolean-weighted sum below 256, so the tuples match
  element-wise. The byte-swap from stream bytes to big-endian `W_j` is part of
  the linear form.
- **Output.** The truth's OUT bytes equal the bridge's U8-checked AFTER bytes
  of coordinate 0. OUT has no local range check: a non-canonical OUT byte
  could satisfy the feed-forward equation, but it would then match no
  bridge-consumed tuple and the global Wire35 sum would not close. The same
  inherited-canonicality argument is used for secp (`canonical_inputs`).

## Packet-to-RAM binding (bridge)

The bridge is the existing secp Word16 Wire35 bridge with
`Kind.sha256 = 3`. It has 3 coordinates, and only coordinate 0 is written
(fixed column 6 is `coord < 1`, and the output wire ID is 3).

- OWNER19 binds the real ECALL, the full 64-bit `a0`, `a7 = 0x30010`, the
  public epoch and the CPU slot-4 tick. The CPU supplies the positive term.
  A SHA tag therefore closes OWNER only in a shard whose roster contains a
  SHA bridge.
- A 32-byte alignment decomposition and four 16-bit additions with Boolean
  carries and final carry 0 give canonical, non-wrapping word addresses.
- Each of the 12 words has an authenticated RAM14 predecessor (epoch/tick
  strictly earlier, ranged gaps) and is readable. Words 0..3 must be writable;
  words 4..11 are read-only, so their after-value equals the before-value with
  rights preserved (`WRITE = active·f6`).
- RAM mass is 24 terms per call. The bridge has 26 U16 and 73 U8 range
  queries per row.

## Statement, transcript and v2 identity

- `Family.sha256 = 3` is appended after the v2 roster.
- `beginCpu` mixes a SHA block only when the shard has a SHA bridge: marker
  `0x57534833`, the v3 claim count, the tag, calls, first ID, kind 3, log and
  widths. The CPU claim vector grows by five claims only in that case
  (`CpuClaims.count`).
- `beginTruth` mixes the SHA geometry: log, widths, constraint count, Wire35
  arity and kind. `drawTruth` uses only the shared Wire35 challenge.
- Truth claims are `[claim, 0, 0]`. The two unused slots are checked to be
  zero by both the wire and the receiver.
- Wire JSON omits every v3 field when it is absent (`Logs.sha256`,
  `sha256_calls`, `WireClaims.sha256`).
- Result: the services fixture bundle (2 CPU and 3 truth proofs, `bundle.json`,
  `cells.bin`) is byte-identical to the pre-change build, and the old bundle
  verifies with the new receiver.
- Receiver policy: the Ethereum driver's request `execution_profile` defaults
  to v2. `admitProfile` rejects any SHA-256 declaration unless the request is
  v3. A receiver expecting no SHA bridge in a shard rejects SHA-bearing proofs
  (`InvalidCombinedBridgePresence`).

## Measured cost

MEASURED_COST_PLACEHOLDER

## Evidence

EVIDENCE_PLACEHOLDER

## Remaining gaps

GAPS_PLACEHOLDER
