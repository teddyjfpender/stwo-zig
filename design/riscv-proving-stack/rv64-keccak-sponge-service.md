# RV64 admitted Keccak-256 sponge service (`ethereum_services_v3`)

Status: implemented on `codex/rv64-guest-prover-keccak-sponge` (on top of the
finished v3 integration). The bridge AIR is qualified by AIR-level known-answer,
alignment and adversarial tests; the services lane by a two-shard fixture with
real STARKs and a fresh receiver (section 8). This is a source-level soundness
argument, not a machine-checked proof.

Paths: `ks/` = `src/frontends/riscv/rv64/air/delegations/keccak_sponge/`,
`svc/` = `src/integrations/riscv_cpu/word16_global_execution/services/`,
`exec` = `src/frontends/riscv/rv64/ethereum_services/keccak_sponge.zig`.

## 1. ABI (admitted form)

Tag `0x0003_0130` (same tag as the execution-only candidate), profile
`ethereum_services_v3`. `a0` points to an 8-aligned packet of four LE u64
words `{state, in, len, flags}`; one ECALL is one retired instruction and all
registers are preserved.

- `flags` bit 0 = **finalize**, bit 1 = **fresh** (start from the zero state).
  Other bits trap.
- Absorbs `len` bytes at `in` (**any alignment**) with Keccak rate 136 into
  the 25 LE lanes at `state`; one permutation per full block, plus one for the
  padded tail when finalizing. The whole state is written back; the digest is
  lanes 0..3.
- **Padding responsibility (guest-controlled, as in the candidate):** the
  service pads (Keccak `0x01 .. 0x80`, `0x81` when they share a byte) only
  when finalize is set; without finalize `len` must be a **nonzero** multiple
  of 136. A guest hashing in pieces absorbs whole blocks without finalize and
  passes the tail with finalize.

Admitted restrictions relative to the candidate (each needed by the bridge;
`exec` enforces all of them before any write, so a trapping call changes
nothing and execution and provability coincide):

| Rule | Candidate | Admitted | Why |
|---|---|---|---|
| `len` | ≤ 256 MiB | **< 2^20** | `len` limb 1 < 16 is range-checked; one call's permutation run fits one shard component |
| `len = 0` without finalize | allowed (no-op) | **traps** | every call has at least one permutation row |
| state rights | write (+ read unless fresh) | **read and write always** | one atomic RAM14 transition per state word (before = old, after = new) |
| state alignment | 8 | 8 | |
| disjointness | none | packet, state and message **words** pairwise disjoint | every access of a call shares the ECALL clock; an alias is unprovable |
| message permission | `[in, in+len)` readable | the covering words readable | RAM rights are per word (pages are 4 KiB, so equivalent in practice) |

## 2. Components and layout

Two bridge components live inside the issuing CPU proof (like bulk memory);
the permutations are proven by the **unchanged Keccak-f truth AIR**.

| Kind | Rows | MAIN | INTER | Fixed | Constraints | Fractions/row |
|---|---|---:|---:|---:|---:|---|
| `call` | 1 per ECALL | 694 | 380 | 3 | 325 | OWNER 2, RAM 58, IO 50, U16 33, U8 34 |
| `perm` | 1 per permutation | 973 | 688 | 3 | 1,025 | OWNER 1, IO 50, AND 136, RAM 36, U16 18, U8 90 |

Column maps: `ks/layout.zig`. Interaction: one QM31 inverse per pair of
consecutive fractions (`inv·d1·d2 = 1`) and one centered prefix per relation
(RAM14, OWNER19, IO11, AND, U16, U8). All constraints have degree ≤ 3 (native
2n composition, split 1).

**call row.** Consumes the CPU OWNER19 ECALL tuple `[ECALL, a0, 0^4, (0x130, 3,
0, 0), 0^4, E, T]` (weight `−active`). Reads the four packet words at `a0+8k`
(carry chains) as RAM14 read transitions; their values are column expressions:
`state` limbs; `in = (s + 8 q0, in1, in2, in3)` with a one-hot shift `σ`;
`len = (len0, len1, 0, 0)`; `flags = (fin + 2 fresh, 0, 0, 0)`. Decomposes
`len = 136 q + r` (r < 136, q < 2^16), `(1 − fin) r = 0`, the empty flag
`z = [len = 0]` (inverse witness) and the word count
`8 W = (1 − z)(s + len + 7 − e)` with `e < 8`. Reads and writes the 25 state
words (old → new, rights R = W = 1 constants in both tuples). Emits the IO11
**link** `(id, 2, l, old_l)` with weight `active − fresh` and consumes the last
permutation's output `(id + q + fin − 1, 1, l, new_l)`. Emits one OWNER19
token `[0x4B530001, E, TL, TH, B (aligned base), len, W, fin, fresh, s, id]`.

**perm row** (row `k` of a call's contiguous run; its IO11 ID is
`first_id + row index`, from the fixed row index and the public `first_id`):

- Run structure: `first`, `last`, continuation `c = active − first`; a
  continuation follows an active row, an active non-last row is followed by a
  continuation, a last row by a first or padding row. The clock, `fin` and `σ`
  are copied along the run; the base address advances by 136 (carry chain);
  `rb` (bytes left) drops by 136 per row, `wr` (words left) by the previous
  row's read count. The first row consumes the token (weight `−first`), which
  binds base, `len`, `W`, flags, shift and the first ID.
- Message words: an 18-slot window of the words `17k .. 17k+17`. Slots 1..17
  are RAM14 read transitions at `base + 8j` (weight = read flag `r_j`); slot 0
  is read on the first row only and equals the previous row's slot 17
  otherwise. Read flags are a thermometer that continues across rows, and the
  last row reads exactly `wr` words, so the reads are precisely the words
  `0 .. W−1`, each once.
- Absorbed block: `msg_t = mask_t · Σ_s σ_s · window[t + s] + pad_t`, with a
  thermometer `mask` (all ones except on the finalizing last row, where
  `Σ mask = rb`) and `pad_t = (mask_{t−1} − mask_t) + [t = 135] · 0x80 ·
  lastfin` (`mask_{−1} = active`).
- XOR: `in = pre + msg − 2 (pre AND msg)` per rate byte, with the AND byte
  looked up in the CPU proof's canonical byte-AND table (`(pre, msg, and)`;
  this also range-checks `pre` and `msg`). Capacity lanes pass `pre` through.
- IO11: consumes `(id, 0, l, in_l)` for all 25 lanes (weight `−active`) and
  `(id − 1 + first, 1 + first, l, pre_l)`, i.e. the previous permutation's
  output, or on the first row the call's link (weight `−(active − freshfirst)`;
  a fresh call's first `pre` is constrained to zero).
- U8 checks on the odd byte of every window limb (see S5), U16/U8 clock gaps.

## 3. Statement, IDs and v2 identity

- The sponge is a separate roster block after bulk (`Logs.sponge = {call,
  perm}`), not a `Family`: it uses the Keccak IO11 bus and the Keccak-f truth.
- Sponge permutations take **Keccak IO11 IDs after every Keccak-f call** of
  the bundle, in shard order. Each shard's request carries `sponge = {calls,
  perms, first_id}`; `protocol.admit` checks every `first_id` against the
  Keccak-f total and earlier shards and requires the Keccak truth spans to
  cover `1 .. K + S` exactly. The existing Keccak truth needs no change: its
  span inputs are the Keccak-f inputs followed by the sponge permutation inputs.
- `beginCpu` mixes a sponge block (marker `0x4b53504e`, tag, token, link
  direction, length cap, calls, perms, first ID, geometries) only when present;
  CPU claims mix twelve sponge claims after the bulk block only when present.
  The receiver adds the sponge IO11 claims to the global IO sum; OWNER, AND
  and range claims close locally (`CpuClaims.local`), RAM globally.
- The AND requests join the core AND table: the sponge's AND counts are added
  to the table multiplicities (`roster.mergeAnd`, mass < p) before interaction.
- Wire JSON omits every sponge field when absent; v2, SHA-only, arith-only
  and bulk bundles are unchanged (section 8).
- Receiver policy: `ethereum/main.zig admitProfile` rejects sponge bridges
  unless the request is v3.

## 4. Soundness argument

Context: `svc/execution.verify` verifies every STARK, closes OWNER/AND/ranges
per CPU proof, RAM14 and IO11 globally with INIT/TERM anchored.

S1 Call authenticity: as bulk B1. The call row consumes the CPU ECALL tuple
(tag `0x30130`, `a0`, epoch, tick); OWNER19 closes per CPU with unit weights,
so each sponge ECALL has exactly one call row and vice versa.

S2 Token and run: tokens are OWNER19 tuples with slot 0 `0x4B530001` (outside
the opcode range and distinct from bulk tokens), unique per call (clock). Each
is emitted once and consumed by exactly one first row, so each call has
exactly one run, which starts at its token's base, `len`, `W`, flags, shift and
ID. Every active row belongs to a run (row 0's wrapped predecessor is padding).

S3 Run length: `rb` starts at `len`, drops by 136 per row; non-final rows and
the last row of a non-finalizing call have a full mask; the finalizing last
row has `mask_135 = 0` and `Σ mask = rb ≤ 135`. All quantities are below
2^24, so `len = 136 (P − 1) + rb_last` over the integers: `P = q + fin`, and a
non-finalizing call has `r = 0`. The call row consumes the output of ID
`id + q + fin − 1`, which is the run's last row.

S4 Message words: reads are a thermometer within each row (`r_{j+1} ≤ r_j`),
continue across rows (`r_1 ≤ first·r_0 + c·r_17(prev)`, `r_0` only on the
first row), and the run reads exactly `W` words (the `wr` counter). Slot
`j` of row `k` addresses `B + 136k + 8j` = word `17k + j`. Hence exactly the
words `0..W−1` are read, once each, at the ECALL clock (RAM14 chronology as in
bulk B5, permissions from the transition rules: R = 1 constant). `W` is the
covering word count of `[in, in+len)`: `8W = s + len + 7 − e` with `e < 8`
forces the ceiling; a wrong `e` makes `W` a non-integer field element, which
the `wr` counter (≤ 18 per row) cannot reach.

S5 Bytes: every in-mask byte `t` of row `k` lies in a word `< W` (its stream
position is `< s + len ≤ 8W`), i.e. a read word (this row's slots or the
previous row's slot 17). Window bytes recompose the RAM limbs as `b0 + 256 b1`.
The odd byte of every limb is U8-checked; the even byte of an in-mask position
is AND-checked through `msg`. So every limb that contributes an in-mask byte
decomposes canonically (both bytes < 256, integer equation), and the absorbed
data byte is the true memory byte. Out-of-mask bytes are multiplied by
`mask = 0`. `pre` bytes are AND-checked (rate lanes) or equal truth output
bytes (canonical bit sums, capacity lanes); call-row old/new bytes inherit
canonicality through the link/IO tuples they meet.

S6 Permutation chain: the truth produces `(id, 0, l, x)` and
`(id, 1, l, f(x))` once per ID with canonical bytes. Row `k` consumes the input
tuple of its ID with `in = pre XOR msg` and the output tuple of ID − 1 as `pre`
(same run, previous row); the first row consumes the call's link (direction 2,
never produced by the truth) instead, carrying the RAM old state (or zero when
fresh). The call row consumes the last ID's output as the written state. With
IO11 closed globally and IDs unique, the written state is
`f(... f(f(old ⊕ m_0) ⊕ m_1) ...)`, i.e. Keccak-256 absorption of the masked,
padded message.

S7 Canonical RAM writes (joint write induction): sponge writes are the 25 state
words with `after` = bytes matched to truth output bytes (independently
anchored by the truth's bit columns); reads keep their values. Clock ticks are
the OWNER-bound `4r + 4`. No new circular edge.

S8 Masses: RAM 58/call + 36/perm, IO 50/call + 50/perm (plus 50/perm truth
production), OWNER ≤ 3/call, U16/U8/AND unconditional per physical row; all
admitted below p (`protocol.admitSponge`, wire read); the AND table's
consumer mass `8 · BINARY rows + 136 · 2^perm_log` is admitted below p.

## 5. Tests

`zig build test-riscv64-keccak-sponge` (`ks/tests.zig`): honest five-call
scenario (unaligned fresh+finalize, non-fresh absorb, empty finalize,
136-byte finalize with a padding-only block, 135-byte tail with `0x81`,
reading another call's output) closes every relation against an honest
memory environment and an honest Keccak-f truth; 23 lengths × 8 alignments
match `std` Keccak-256 and close; degree ≤ 3 by fourth finite differences.

| Forgery | Rejected by |
|---|---|
| wrong XOR (AND result) | AND table |
| wrong absorbed byte | local msg equation; with a forged window byte, RAM14 |
| skipped block | local counters / IO11 |
| reordered blocks | local / IO11 |
| forged final state (RAM-consistent) | IO11 |
| length mismatch (rb, or consistent packet len) | local; RAM14 packet read |
| missing `0x80`, nonzero fresh state | local |
| non-canonical tail byte split | U8 range |

`exec` tests (`test-riscv64-execution`): Keccak-256 for lengths 0..559 at
all 8 alignments, split absorb + finalize, empty message, and traps (domain,
length, overlap, misalignment, unmapped) leave memory unchanged; the v3
session dispatches the tag and v2 traps on it.

Services (`zig build test-riscv64-word16-sponge-services
-Doptimize=ReleaseSafe`): section 8.

## 6. Cost

See section 8 for measured numbers.

## 7. Integration

Frontend: `KECCAK_SPONGE_TAG`, `isPayloadFreeTag`, session arm, payload-free
tape record (`Tape.appendSponge`; no tape wire section — the ECALL step is the
call, like bulk), boundary capture and census arms, execution report counters.
Services: `types` (`Logs.sponge`, `SpongeCounts`), `roster` (fixed columns,
sources, AND merge, Keccak truth inputs), `protocol` (`admitSponge`, ID
checks, transcript block), `statement`, `air_components`, `worker`,
`pipeline`, `execution` (IO sum), `wire`, `collector` +
`sponge_collector.zig` (ledger replay). Driver: plan logs and Keccak truth
totals, `admitProfile`, native batch and work-packet admission.
