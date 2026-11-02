# RV64 admitted SHA-256 compression service (`ethereum_services_v3`)

Status: implemented in the Word16 services lane and qualified by unit,
adversarial and services-fixture tests with a fresh receiver, plus a
freshly verified 4-shard Ethereum prefix (block 24,628,607). See "Evidence"
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

Committed MAIN+INTERACTION cells per compression (fixed columns are key
material and are not counted):

| Item | Nominal | Measured, block 24,628,607 prefix |
|---|---:|---:|
| Truth row | 7,417 | 30,380,032 cells / 2,771 calls = 10,964 (log12, 4,096 rows) |
| Bridge (3 rows × (134 + 244)) | 1,134 | (3,096,576 + 193,536) / 2,771 = 1,187 (shard logs 13 and 9) |
| **Total** | **8,551** | **12,151** |

- The measurement is a 4-shard prefix that contains 2,771 of the block's 2,772
  compressions. It is recorded in `calibration.json`
  `coefficients.sha256_cells_per_call` together with its derivation.
- The sibling estimate was 18,000 (range 12k-26k). Software SHA-256 costs
  about 3,980 instructions, which is about 616k cells, per compression.
- The SHA-256 truth proof for 2,771 compressions took 0.69 s of worker
  stages: composition 0.22 s and MAIN commit 0.09 s, with 8 lane threads
  (M-series CPU, same-process run).
- The whole 4-shard prefix proved in 29.5 s with peak RSS 22.8 GB. A fresh
  `verify-prefix` took 3.2 s with RSS 2.9 GB.
- Guest-efficiency harness, all 15 blocks, admitted v3 ELF against a same-tree
  v2-lean reference ELF. Outputs are exact on every block.

  | Set | instr/gas (v2 ref → v3) | committed bits/gas (v2 ref → v3) |
  |---|---|---|
  | scored | 13.181 → 11.541 (−12.4%) | 151,702 → 135,602 (−10.6%) |
  | holdout | 11.164 → 9.699 (−13.1%) | 128,554 → 114,175 (−11.2%) |
  | all | 12.783 → 11.177 (−12.6%) | 147,133 → 131,372 (−10.7%) |

  The basket made 196,254 compressions. Block 24,628,607 dropped from
  98.82M to 88.72M instructions.

## Evidence

- `zig build test-riscv64-sha256-truth`:
  - FIPS 180-4 known answers: "abc", the empty message, the two-block 448-bit
    message and the 896-bit message.
  - 48 random and extreme blocks (all-ones state and block, zero, IV) checked
    against an independent compression (`candidate_services.sha256Compress`),
    with every MAIN residual zero and the wire byte forms equal to the native
    bytes.
  - Adversarial rows are rejected: a wrong output byte, a flipped message bit,
    a non-canonical bit (2·2^(i−1) substituted for 2^i), a forged round carry,
    and a forged feed-forward carry.
  - A +1 perturbation of every one of the 7,409 MAIN cells is caught.
  - Activity-prefix rules hold.
  - The interaction claim equals the native Wire35 sum, and both batch
    residuals vanish on every row.
- `test-riscv64-execution`:
  - The v3 session executes SHA-256 and v2 traps on the tag.
  - Misaligned and read-only packets trap without publishing anything.
  - Tape wire round-trips for every profile, including the v3 SHA-256
    section. A mutated read-only word, a SHA count in a v2 header and a
    misaligned record are each rejected.
- `test-riscv64-word16-combined-services`:
  - The existing suites pass, plus `services/sha256_test.zig`.
  - A two-shard v3 fixture (SD, SHA, SHA | SD, SHA on one cross-page packet)
    proves 2 CPU proofs and 1 SHA truth. It verifies with independently built
    keys after a durable wire round-trip.
  - The same calls split over two truth spans also verify. Swapping the spans
    is rejected.
  - A receiver expecting no SHA bridge rejects the bundle
    (`InvalidCombinedBridgePresence`), and a nonzero unused truth-claim slot
    is rejected.
  - Locally valid but false proofs are rejected by global closure:
    - a false new state → `UnclosedCombinedSecpWire`;
    - a forged block word consistent between truth and bridge →
      `UnclosedCombinedRam`;
    - a wrong pointer → `UnclosedCombinedCpuRelations`.
- v2 identity: the `rv64-word16-combined-services-fixture produce` bundle
  (bundle.json, cells.bin, 2 CPU and 3 truth proofs) is byte-identical before
  and after the change, and the pre-change bundle verifies with the new
  binary.
- Other suites still pass: word16-global-execution, word16-ethereum-terminal,
  word16-keccak-shared, word16-keccak-bridge, word16-secp-bridge,
  services-gkr-local, word16-execution-prepared and secp.
- Ethereum: block 24,628,607 with the admitted v3 guest:
  - native jobs: 22 batches, completed, 88,717,886 instructions;
  - 4-shard `produce` (2,771 SHA-256 calls) followed by a fresh
    `verify-prefix`: `accepted: true`;
  - the same bundle under a v2 request fails with `UnadmittedSha256Service`.

## Remaining gaps

- **Recursion.** The RV64 recursion circuits (om31 and circuit lanes) have no
  SHA-256 truth or bridge role, so a v3 bundle cannot yet be wrapped or folded.
  This is the largest remaining piece of prover work.
- **Complete block.** Only a 4-shard prefix was proved. A complete-block v3
  proof with a fresh `verify` has not been run.
- **Profile in the statement.** v3 is a receiver policy (`admitProfile`),
  enforced together with bridge presence in the per-shard spec. It is not part
  of the program identity: native jobs keep the v2-decoded ROM authority,
  because decode is identical. A downstream consumer must run the v3 receiver.
- **Security accounting.** Whole-protocol security bits are not established,
  exactly as for the other services. That includes LogUp rational degree, the
  per-proof Wire35 mass (4 terms per call on each side) and union bounds.
- **No local OUT range check.** OUT canonicality comes from the bridge's U8
  checks through Wire35 (an argument, tested via `wrong_output`). An auditor
  may prefer a local byte range check; it would add 32 queries per row.
- **Width.** The truth is wide (7,417 columns) and log13 caps a span at 8,191
  calls. The largest basket blocks (about 29k compressions) need 4 spans.
- **Not reviewed or optimised.**
  - The guest crate's admitted `stwo-sha256-service` feature needs
    dependency and cryptographic review.
  - Carry bits could be narrowed and the bits for `A_63`, `E_63`, `W_62` and
    `W_63` folded away, which would save about 2%.
  - GPU/Metal paths and same-AIR Rust verification are not done.
  - The legacy wide route (`rv64-ethereum-proof prove`) rejects v3 by design.

## Integration into the shared v3 profile (2026-11-01)

Merged with arith256_mod and bulk memory on
`codex/rv64-guest-prover-v3-integration`
([rv64-services-v3-integration.md](rv64-services-v3-integration.md)). SHA-256 keeps
family 3, Wire35 kind 3, its tape section and its transcript block. The
SHA-only v3 fixture (`rv64-word16-combined-services-fixture produce-v3 sha256`)
is byte-identical to this branch's output and verifies both ways; the header
word 28..32 now carries the SHA-256 count in its low 31 bits (bit 31 flags the
arith256_mod extension). The evmone client sends every compression to the
service with a 32-byte aligned packet (`build.py --profile v3`), and the
complete block was proved with that guest, which closes the "Complete block"
gap for SHA-256 (see the integration note for cells and timing).
