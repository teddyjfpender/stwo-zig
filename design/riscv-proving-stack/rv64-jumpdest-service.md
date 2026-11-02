# RV64 admitted JUMPDEST analysis service (`jumpdest_bitmap`, 0x0003_0040)

Status: AIR, executor, collector and services lane implemented on
`codex/rv64-ge-jumpdest`; AIR tests and a two-shard services fixture with a
fresh receiver pass (section 6). Profile `ethereum_services_v3`. Source-level
soundness argument, conditional on the physical STARKs and the randomized
LogUp arguments, like [rv64-bulk-memory-service.md](rv64-bulk-memory-service.md),
whose components, clock blocks and argument this service reuses.
Proposal and measurements: `autoresearch/guest_efficiency/proposals/jumpdest-bitmap.md`.

Paths: `bm/` = `src/frontends/riscv/rv64/air/delegations/bulk_memory/`,
`svc/` = `src/integrations/riscv_cpu/word16_global_execution/services/`.

## 1. ABI (admitted form)

`a0` = 8-aligned packet `code, len, bitmap` (LE u64), `a7 = 0x0003_0040`; all
registers preserved; one retired instruction. Admitted exactly when:

- `code` 64-aligned, `bitmap` 8-aligned, `len` a nonzero multiple of 8,
  `len <= 2^20`, no address wrap;
- packet words and code words readable; the `ceil(len/64)` bitmap words
  readable and writable;
- packet, code words and bitmap words pairwise disjoint (every access shares
  the ECALL's RAM clock, so an alias is unprovable).

Effect: bitmap word `r`, bit `i` (= byte `64r + i`) is 1 iff that code byte is
`0x5b` and not PUSH1..PUSH32 immediate data (an opcode `0x60 + k` at `j` makes
`j+1 .. j+1+k` data; data past `len` is cut off). Executor:
`ethereum_services/bulk_memory.zig` (`Kind.jumpdest`); every check precedes
the write.

## 2. Components (inside the CPU proof, bulk-memory family)

| Kind | Rows | MAIN | INTER | Fixed | Constraints | Fractions/row |
|---|---|---:|---:|---:|---:|---|
| `jdesc` | 1 per call | 45 | 60 | 3 | 88 | 6 RAM14, 2 OWNER19, 15 U16 |
| `jscan` | 1 per 64 code bytes | 287 | 232 | 3 | 497 | 18 RAM14, 65 OWNER19, 27 U16 |
| `jtab` | 2^14 (8,448 entries) | 1 | 16 | 7 | 7 | 1 OWNER19 |

`jdesc` consumes the CPU ECALL tuple (`a7` limbs `0x40, 3`), reads the three
packet words (code limb 0 = `64 q` with `q`, `64 q` both U16: `q < 1024`;
len = `[8 q0, l1, 0, 0]`), and emits the token
`[TOKEN_JD, E, TL, TH, code, bitmap, W]` (`W = q0 + 8192 l1` code words).

`jscan` row `r` of a call: `remaining` = code words left (`W - 8r`), base
address `code + 64r` (carry chain, +64 per row), bitmap address `bitmap + 8r`
(+8 per row), 7 valid bits for words 1..7 (word 0 is valid on every active
row), per byte `k` of the row the byte `b_k`, the pending PUSH-data counter
`c_k` (bytes still to skip before byte `k`) for `k = 0..64` and the JUMPDEST
bit `j_k`. Fractions: a RAM14 read of each valid code word at
`[limb0 + 8w, limb1, limb2, limb3]` with value limbs `b_{2i} + 256 b_{2i+1}`
(weight `valid_w`); a RAM14 write of the bitmap word with limbs
`sum_{i<16} j_{16l+i} 2^i` (rights 1, 1); the token consumed with weight
`-start`; and per byte one OWNER19 lookup `[TOKEN_JD_TABLE, c_k, b_k, c_{k+1}, j_k]`
with weight `-valid_{k/8}`.

`jtab` is the fixed transition table (fixed columns `c, b, c', j`, entry
`c * 256 + b` for `c <= 32`; rows past 8,448 repeat entry 0): `c > 0` gives
`(c - 1, 0)`; `c = 0` and `0x60 <= b <= 0x7f` gives `(b - 0x5f, 0)`;
otherwise `(0, [b = 0x5b])`. Its single fraction emits the entry with the
multiplicity column as weight.

## 3. Constraints (degree <= 3; finite-difference test in `bm/tests.zig`)

`jscan` chain (as bulk `copy` plus): `last` Boolean; a continuation row
follows only a non-last active row and every non-last active row is followed
by one (`c * pm.last = 0`, `pm.active (1 - pm.last)(1 - c) = 0`); epoch and
tick copied; `remaining = pm.remaining - 8`; code +64 and bitmap +8 carry
chains (carries Boolean, zero on start rows); `c_0 = pm.c_64` on
continuations and `c_0 = 0` on start rows. Valid prefix: Booleans,
`valid_w (1 - valid_{w-1}) = 0`, and
`sum(valid) + active - 8 active - last (remaining - 8) = 0`, i.e. 8 valid words
on non-last rows and `remaining` on the last row. Invalid words carry no
JUMPDEST bit: `j_{8w+i} (1 - valid_w) = 0`. Clock blocks of the 8 reads (gated
by their valid bit) and of the write, W bits Boolean. Inactive rows are zero.
`jtab` has only its fraction and prefix constraints.

## 4. Soundness argument

Context as bulk section 4 (canonical services receiver; OWNER19, U16, REG
closed per CPU proof; RAM14 global with INIT/TERM anchored).

**J1 Call authenticity, packet, token.** As bulk B1/B2: one `jdesc` row per
`0x30040` ECALL (OWNER tuple binds `a0`, `a7`, epoch, tick `4r+4`), packet read
at that clock, one token per call (slot 0 `TOKEN_JD` outside the opcode range),
consumed by exactly one `jscan` start row. Code alignment: limb 0 = `64 q`,
`q < 1024`; only canonical addresses meet RAM (bulk B4).

**J2 Run length.** `remaining` starts at `W` and drops by 8 per row; the run
ends exactly at the row flagged `last` (continuation rules; the padded last
physical row is inactive, so every run ends). On the last row
`sum(valid) = remaining in [1, 8]` because `valid_0 = 1` and 7 Booleans; on
other rows all 8 words are valid. Hence `W - 8(R - 1) = v` with `v in [1, 8]`;
both sides are integers below p (`W < 2^17`, `R <= 2^24`), so `R = ceil(W/8)`:
exactly `W` code words are read (weights 1 on valid words, 0 otherwise) and
exactly `R = ceil(len/64)` bitmap words are written.

**J3 Every byte classified.** Each valid byte contributes one OWNER19 lookup
with weight `-1`; the table rows contribute `+m_t` for fixed entries `t`.
OWNER19 closes per CPU proof; the per-tuple coefficient of a looked-up tuple
not in the table is minus its lookup count, at most `64 R < 2^31 - 1`,
nonzero mod p, so (w.h.p. over the challenges) every looked-up tuple is a
table entry. Multiplicities are prover chosen and need no range: a forged
`m_t` only fails closure. The lookup also proves `b_k < 256`, so the read
value limbs are canonical byte pairs of the RAM word.

**J4 The bitmap is the canonical one.** By induction on the byte index `n`
of the call (row `n / 64`, byte `n % 64`): `c` at byte 0 is 0 (start row);
`c` at byte `n + 1` is the table's `c'` for `(c_n, b_n)`, also across rows
(`c_0 = pm.c_64`). evmone's walk keeps exactly this counter (bytes of PUSH
data left), so `c_n` is evmone's state before byte `n`, and the table's
`j_n = [c_n = 0 and b_n = 0x5b]` is the canonical bit. Forged JUMPDEST inside
PUSH data needs `c_n > 0, j_n = 1`; a missing JUMPDEST needs
`c_n = 0, b_n = 0x5b, j_n = 0`; neither is a table entry. Resetting the counter
at a row boundary breaks `c_0 = pm.c_64`; at a call start, `c_0 = 0` forbids
carrying another call's counter. A truncated PUSH at the end leaves `c_64` of
the last row unconstrained, which nothing reads (evmone's cut-off). Bits of
invalid words are zero, so the last bitmap word has no bit at or past `len`.
The written limbs are `sum j 2^i` with Boolean `j`, so they are canonical.

**J5 RAM order and freshness.** As bulk B5: every read is a RAM14 transition
at the call's clock with `after = before`, so the code bytes analyzed are the
latest values written to those words (by LS, memcpy, an earlier JUMPDEST call
...), and later accesses see the written bitmap. Writes carry rights (1, 1).

**J6 Write induction (the RAM-writer case).** The joint REG/RAM canonical-limb
induction ([rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md),
bulk B7) gains one writer: the `jscan` bitmap write. Its tick is the
OWNER-bound `4r+4` copied through the token (P1). Its value is independently
anchored: every limb is `sum_{i<16} j_i 2^i` with each `j_i` a table output in
{0, 1} (valid bytes) or forced 0 (invalid words), so `0 <= limb < 2^16`
without reference to any earlier token. The code reads keep value and rights
(`after = before`). No new dependency edge is added, so the lemma's ordering
is unchanged.

## 5. Mass bounds (per CPU proof, `svc/protocol.zig::admitBulk`, `svc/wire.zig`)

- RAM14: `6 * jump_calls + 18 * jump_rows` added to the global bound.
- U16: `15 * 2^log_jdesc + 27 * 2^log_jscan` added to the range16 mass.
- OWNER19: per call 2 (ECALL, token), per row 1 + 64 lookups matched by the
  table: below `2^31 - 1` since rows `<= 2^24`; `jump_calls` count towards
  `service calls <= steps`.
- `jump_rows <= jump_calls * 2^14`; `jdesc` and `jscan` present together
  (`jump_calls = 0` iff `jump_rows = 0`); `jtab` has `TABLE_ENTRIES` rows and
  log `>= 14`.

## 6. Tests and qualification

1. AIR (`zig build test-riscv64-word16-bulk-memory -Doptimize=ReleaseSafe`,
   13 JUMPDEST tests among 43): honest scenario (PUSH32 data across rows,
   truncated PUSH32 at the end, read-only code, analysis of an earlier service
   write) closes RAM14/OWNER19/U16; 17 random codes covering every last-row
   remainder match the executor's reference walk; degrees <= 3. Adversarial,
   each with the check that rejects it: forged JUMPDEST in PUSH data and
   missing JUMPDEST with RAM made to agree (OWNER19 table); counter reset
   across rows, bits past the length, run ended early, extra valid word,
   counter carried into the next call (local constraints); forged packet length
   (RAM14 + OWNER19); relabelled remaining (OWNER19 or RAM14); stale code read
   and forged code byte (RAM14); misaligned code (U16); read-only bitmap
   predecessor and forged tick (RAM14 / OWNER19); misaligned code or bitmap,
   partial-word length, read-only bitmap and aliasing refused natively
   (`validateCall`). Executor: canonical bitmap vs the candidate reference for
   8/64/72/200 bytes, recorded before-values, ten trap cases leave memory
   unchanged.
2. Services lane (`zig build test-riscv64-word16-jumpdest-services
   -Doptimize=ReleaseSafe`, 3/3): two real CPU STARKs (epoch 1: a 72-byte call,
   LD of its bitmap word; epoch 2: a call analyzing epoch 1's bitmap words, LD
   of its bitmap word), verified in process and by a fresh receiver over the
   wire with rebuilt keys; wrong code word, stale code read and wrong length
   rejected as `UnclosedCombinedRam`; a nonzero absent memory-block claim, keys
   without the JUMPDEST bridges, a table at the wrong log and a changed scan
   row count rejected.
3. Byte identity: the memory block (desc/copy/set) keeps its transcript words,
   claim vector and JSON; the JUMPDEST block is committed, mixed (after the
   sponge) and serialized only when present. Checked results are in the
   branch's commit messages.

## 7. Cost

Layout-exact cells (MAIN + INTER, fixed excluded): 519 per 64 code bytes
(8.11 per byte; 11.70 with the 1/ln 2 padding expectation), 105 per call
(151.5 padded), plus the table, 278,528 cells in each CPU proof that issues a
call. `calibration.json` `admitted_services.jumpdest_bitmap` = 11.70 per byte
and 29,950 per call (table amortized over the basket's CPU proofs, an upper
bound). Status: not yet from a complete-block `cost.json`.

## 8. Gaps

- Complete-block / prefix proof of 24,628,607 with the jumpdest guest not run
  (coordinator-scheduled); cells there replace the layout tier.
- Recursion circuits and `services/gkr_local` do not know the JUMPDEST kinds
  (as for the bulk components).
- The table is per CPU proof; a shared table (one per bundle) would drop the
  per-call term to ~150 cells.
