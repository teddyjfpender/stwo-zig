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

S7 Canonical RAM writes (joint write induction): see section 4.1.

S8 Masses: RAM 58/call + 36/perm, IO 50/call + 50/perm (plus 50/perm truth
production), OWNER ≤ 3/call, U16/U8/AND unconditional per physical row; all
admitted below p (`protocol.admitSponge`, wire read); the AND table's
consumer mass `8 · BINARY rows + 136 · 2^perm_log` is admitted below p.

### 4.1 Sponge writer case of the joint REG/RAM write induction

The joint induction ([rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md),
sections 2-4) requires every RAM producer to have canonical produced clocks
`4r'+4` (P1), atomic Boolean-weighted transitions coupled to its OWNER weight
(P4), and written limbs that are either independently anchored or depend only
on tokens with strictly smaller `(epoch, clock)`. The sponge is a RAM producer
in two places: the call row (4 packet words and 25 state words) and the perm
row (18 message slots). Line numbers refer to `ks/equations.zig` unless
another file is named.

*Clocks (P1).* Every sponge after token carries the call's after clock
`(E, TL, TH)`. The call row binds it through its OWNER19 ECALL tuple (slot 17
`E`, slot 18 `TL + 65536 TH`, line 80, consumed with weight `−active`, line
170) to the CPU ECALL row `r`, whose tick is `4r+4`; `TL` is U16-ranged and
`TH` U8-ranged (lines 193, 205), so the split is the canonical one. The perm
rows of the call's run take the same clock from the token (line 223, first row)
and copy it along the run (line 351). Hence every sponge-produced tick is
`4r+4` of an ECALL row in that CPU proof's epoch.

*Atomic transitions and weights (P2, P4).* Every sponge RAM access is one
`ramPair`: the before token with weight `w` and the after token with weight
`−w`, same address and rights. Call-row pairs use `w = active` (lines 173-182),
the same Boolean that weights its OWNER ECALL consumption, so each sponge ECALL
of the CPU contributes exactly one call row and its 29 transitions. Perm-row
slot pairs use the Boolean read flag `r_j` (line 244); these are reads
(`after = before`), so a wrongly set flag can only add a consistent
read transition (or leave a debt), never a new value. Each pair carries the
strict-predecessor clock gap with ranged gaps (`clockConstraints`), so the
before token is `<lex (E, 4r+4)` exactly as for LS (P2).

*Rights.* State words: `R = W = 1` constants in both tuples, so a state word
must be readable and writable from its INIT rights onward. Packet words:
`R = 1`, `W` a Boolean witness copied into both tuples. Message words: `R = 1`,
`W` copied likewise. Rights are preserved by every transition.

*Ordering.* All 29 + `W` accesses of one call share the clock `(E, 4r+4)`.
The executor requires packet, state and message words to be pairwise disjoint;
an aliasing proof would need two transitions of one word at the same clock,
and the second one's before token (the first one's after token) would not be
strictly earlier, so the gap equation has no solution with ranged gaps. Within
a call, each state word is one atomic old → new transition; no word is both
read as message and written. Across calls, the ticks differ (distinct ECALL
rows), so a later call reads the earlier call's written state through ordinary
chronology (scenario E in `ks/tests.zig`; sponge C in the services fixture).

*Written values (the induction case).* Only the 25 state words change value.

- **Packet and message reads**: `after = before` (lines 173-178, 242-246);
  new edge "sponge read (e,4r+4) → its before token `<lex (e,4r+4)`", strictly
  decreasing as LS edge E3. IH gives canonical limbs.
- **State write** (`after` limbs `= new_{2i} + 256 new_{2i+1}`, line 180): the
  same 8 `new` bytes of lane `l` form the IO11 tuple `(id + q + fin − 1, 1, l,
  new)` consumed with weight `−active` (lines 188-191). IO11 closes globally
  with mass `< p` (S8). The only producers of direction-1 tuples are Keccak-f
  truth rows, with Boolean weight `ioActive`, and their tuple bytes are
  `Σ_bit 2^bit · v` (`air/delegations/keccak/equations.zig:68-77`) over state
  bits `v` that are Boolean on every IO row
  (`air/delegations/keccak/equations.zig:183`; inactive rows are zero, `:191`).
  The call link (direction 2) and perm consumers cannot supply a direction-1
  tuple. So every consumed output tuple equals a truth tuple field-element-wise:
  each `new` byte is an integer in `[0, 256)` and each written limb is in
  `[0, 2^16)`. **Independent anchor**: the bound depends on truth booleanity
  and IO11 closure only, not on any RAM or REG token, so the case adds no
  dependency edge and needs no extra range query.
- `old` bytes need no range: they appear in RAM only as the before value
  (which P2 equates with a produced, hence canonical, token). For a non-fresh
  call they also form the link consumed as `pre` on the first perm row, where
  rate bytes are AND-checked and capacity bytes become truth input bits, so
  the link carries the canonical split of the true old state (S6).
- C value: the OWNER ECALL tuple has `C = 0` (slots 5-8 zero), as for the
  other bridges; the ECALL writes no register.

So the lemma extends with one strictly decreasing read edge (same shape as
bulk's B7 read edge) and one independently anchored writer. Load-bearing
facts a future change must keep: the `new` bytes used for the RAM after limbs
are the same columns as the IO11 output tuple (do not give the write its own
unranged columns), the truth IO-row booleanity, and the Boolean `active`
weight shared by OWNER and the call-row RAM pairs.

Adversarial coverage: `keccak sponge adversarial: digest-write forgery is
rejected` (`ks/tests.zig`): (a) written limbs `limb0 + 65536, limb1 − 1` (same
integer word) with a RAM environment forged to match, so RAM14, OWNER, AND,
ranges and every local residual pass, rejected only by IO11; (b) same limbs,
non-canonical byte split, rejected by IO11; (c) state pointer redirected,
rejected by RAM14 (packet read).

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
| digest-write forgery (non-canonical written limbs, RAM-consistent; byte split; redirected state) | IO11; IO11; RAM14 |

`exec` tests (`test-riscv64-execution`): Keccak-256 for lengths 0..559 at
all 8 alignments, split absorb + finalize, empty message, and traps (domain,
length, overlap, misalignment, unmapped) leave memory unchanged; the v3
session dispatches the tag and v2 traps on it.

Services (`zig build test-riscv64-word16-sponge-services
-Doptimize=ReleaseSafe`): section 8.

## 6. Cost

Measured geometry (2026-11-02), complete block 26,235,156 with the evmone v3
guest routing Keccak-256 inputs > 64 bytes to the sponge (`build.py --profile
v3 --v3-set sha,arith,mem,keccak`; `rv64-ethereum-proof nativeprepare`, 5
packets; `rv64-word16-ethereum plan`): 4,731 calls, 19,562 permutations.
Exact padded MAIN+INTERACTION cells (widths × 2^log, as cost.json computes):

| Component | Rows (logs over 4 shards) | Cells | Per unit | Nominal |
|---|---|---:|---:|---:|
| call | 12/5/5/11 → 6,208 | 6,667,392 | 1,409.3 / call | 1,074 |
| perm | 14/5/7/13 → 24,736 | 41,086,496 | 2,100.3 / permutation | 1,661 |
| Keccak-f truth (shared) | log18 + log16 over 20,994 IDs | 1,480,785,920 | 70,533.8 / ID | |

`calibration.json` `admitted_services.keccak_sponge`: 1,409.3 per call and
2,100.3 + 72,159.3 (frozen Keccak truth coefficient) per permutation.
Basket (15 blocks, all guards, exact outputs): provable v3 scored 4.778 →
4.426 instr/gas, 67,192 → 64,114 bits/gas; Keccak glue 0.465 → 0.108
instr/gas (`notes/keccak-sponge-admitted-results-20261102.json`).

Confirmed by a produced proof: a 1-packet prefix of the same block
(`rv64-word16-ethereum produce request.json native/jobs OUT 1`, 1 CPU + 4
truth proofs, 26.4 s, 15.2 GB max RSS) accepted by a fresh `verify-prefix`
(a v2 request rejects it). Its roster.json: `sponge_call` log 12, 2,943
active rows, 4,399,104 cells (1,494.7 / call); `sponge_perm` log 14, 13,685
active rows, 27,213,824 cells (1,988.6 / permutation).

## 7. Integration

Frontend: `KECCAK_SPONGE_TAG`, `isPayloadFreeTag`, session arm, payload-free
tape record (`Tape.appendSponge`; no tape wire section — the ECALL step is the
call, like bulk), boundary capture and census arms, execution report counters.
Services: `types` (`Logs.sponge`, `SpongeCounts`), `roster` (fixed columns,
sources, AND merge, Keccak truth inputs), `protocol` (`admitSponge`, ID
checks, transcript block), `statement`, `air_components`, `worker`,
`pipeline`, `execution` (IO sum), `wire`, `collector` +
`sponge_collector.zig` (ledger replay). Driver: plan logs and Keccak truth
totals, `admitProfile`, native batch and work-packet admission (sponge is a
payload-free tag: no tape payload, RAM effects in the capture, touched-word
bound `BULK_MAX_TOUCHED_WORDS` covers 29 + W ≤ 131,102 words), cost/roster
telemetry rows `sponge_call`/`sponge_perm`. Exercised end to end by the
prefix proof in section 6.
