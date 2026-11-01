# RV64 admitted bulk-memory services (aligned memcpy / memset)

Status: implemented on `codex/rv64-guest-prover-bulk-memory`; AIR, services
lane and services fixture qualified (section 8). Profile `ethereum_services_v3`.
This is a source-level soundness argument, not a machine-checked proof. It is
conditional on the soundness of the physical STARKs and the randomized typed
LogUp arguments, like
[rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md).

Paths: `bm/` = `src/frontends/riscv/rv64/air/delegations/bulk_memory/`,
`svc/` = `src/integrations/riscv_cpu/word16_global_execution/services/`,
`ram/` = `src/frontends/riscv/rv64/air/memory/closed_ram/`.

## 1. ABI (admitted form)

| Tag | Packet at `a0` (8-aligned, LE u64) | Effect |
|---|---|---|
| `0x0003_0001` memcpy | `dst, src, len` | `dst[0..len) := src[0..len)` |
| `0x0003_0002` memset | `dst, byte, len` | `dst[0..len) := byte & 0xff` |

The prover admits, and the v3 executor
(`src/frontends/riscv/rv64/ethereum_services/bulk_memory.zig`) enforces,
exactly:

- `len` is a nonzero multiple of 8 and at most 1 MiB (2^17 words);
- `dst`, `src` are 8-aligned and `dst + len`, `src + len` do not wrap;
- packet words readable, source words readable, destination words readable
  **and** writable (rights = 3);
- the packet words, source words and destination words are **pairwise
  disjoint**. This is the overlap rule: no memmove semantics, no forward
  overlap. Adjacent ranges (`dst == src + len`) are fine;
- all registers are preserved; one retired instruction.

Every check precedes any change; a trapping call changes nothing. The guest
wrapper (`autoresearch/benchmarks/guest_runtime/ethereum/rv64/mem`, feature
`admitted-bulk`; services crate feature `admitted-mem`) copies the unaligned
head and tail inline, splits bodies into 1 MiB chunks and keeps overlapping
moves, mismatched alignment and calls below a threshold in software, so a
wrapper call never traps.

Why disjointness instead of a direction bit: every RAM access of one call
uses the ECALL step's single RAM clock `(E, 4r+4)` (section 4). Two accesses
of one address at one clock cannot both be in a closed RAM history (strict
predecessor order), so any alias is *unprovable*, not unsound. The executor
refuses aliasing calls so that execution and provability coincide.

## 2. Components and layout

Three bridge components live inside the issuing CPU proof (like the Keccak and
secp word16 bridges); there is no separate truth proof.

| Kind | Rows | MAIN | INTER | Fixed | Constraints | Fractions/row |
|---|---|---:|---:|---:|---:|---|
| `desc` | 1 per call | 48 | 64 | 3 | 94 | 6 RAM14, 3 OWNER19, 17 U16 |
| `copy` | 1 per copied word | 41 | 36 | 3 | 93 | 4 RAM14, 1 OWNER19, 6 U16 |
| `set` | 1 per filled word | 24 | 24 | 3 | 59 | 2 RAM14, 1 OWNER19, 3 U16 |

Column maps: `bm/layout.zig`. Fixed columns: logical row index, first-row and
last-row selectors. Interaction: one 4-column QM31 inverse per *pair* of
consecutive fractions (`inv * d1 * d2 = 1`, contributions `w1*d2*inv`,
`w2*d1*inv`), then one centered prefix per relation (RAM14, OWNER19, U16).
Pairs may mix relations; each relation still has its own prefix and claim.

**desc row.** Consumes the CPU OWNER19 ECALL tuple
`[ECALL, a0 limbs, 0^4, (1+set, 3, 0, 0), 0^4, E, TL + 2^16 TH]` with weight
`-active`. Reads the three packet words at `P, P+8, P+16` (address limbs from
`P` with two 3-bit carry chains, no carry out of the top limb) as RAM14 read
transitions. Decomposes `len = [8*q0, l1, 0, 0]` and `word1.limb0 = lo + 256*hi`.
Emits one OWNER19 *token*, either
`[TOKEN_COPY, E, TL, TH, dst, src, N]` (weight `active - set`) or
`[TOKEN_SET, E, TL, TH, dst, (lo,0,0,0), N]` (weight `set`), with
`N = q0 + 8192*l1`. Token tags `0x424D0001/2` cannot equal a CPU opcode (< 256).

**copy / set body rows.** A call is a maximal run of rows: a start row
(`start = 1`) consumes the token (weight `-start`) with `remaining = N`; every
continuation row (`c = active - start`) has `addr = addr' + 8` (carry chain),
`remaining = remaining' - 1`, and copies `E, TL, TH` and the payload from the
previous row; `active' * (remaining' - 1) * (1 - c) = 0` forces a run to end
exactly at `remaining = 1`. A copy row is one src read and one dst write that
share the value columns (`dst.after = src.before = v`); a set row is one dst
write with `after = 257 * fill` per limb.

**Every RAM access** embeds a 6-column clock block
`be, bl, bh, same, g16, g8` with after clock `(E, TL, TH)`:

- same epoch: `bl + 2^16 bh + g16 + 2^16 g8 + 1 = TL + 2^16 TH`;
- cross epoch: `be + g16 + 1 = E`;
- `g16 < 2^16` and `g8 < 2^8` by U16 lookups (`g8` as `g8` and `256*g8`).

U8 facts are expressed as two U16 lookups (`x < 2^16 ∧ 256x < 2^16 ⇒ x < 256`)
so the bridges need no U8 prefix.

**Activity.** Active rows are exactly the public prefix `[0, rows)` and the last
row is padding (`ram/equations.zig` pattern); padding rows are all-zero. `rows`
is `calls`, `copy_words` or `set_words` from the transcript-bound request.

## 3. Degrees

All constraints have degree ≤ 3: tuples and denominators are affine in MAIN
columns (packet addresses `P+8`, `P+16` are affine in carries; `257*fill`,
`8*q0`, `q0 + 8192*l1` are affine), fraction weights are affine (`±active`,
`active - set`, `set`, `-start`, 1), so `inv*d1*d2`, `w*d*inv` and the gated
clock/chain/count equations are cubic. `bm/tests.zig` checks every constraint
of every kind by a vanishing fourth finite difference along a random line. The
components use the CPU proof's native 2n composition (split 1), like the
existing bridges.

## 4. Soundness argument

Accepting context: the canonical services receiver `svc/execution.verify`
(and the wire receiver built on it), which verifies each CPU STARK, closes
OWNER19/U16/REG per CPU proof (`CpuClaims.local`, now including the bulk
claims) and RAM14 globally with INIT/TERM anchored by `expectedClaim`.

**B1 Call authenticity.** OWNER19 is closed per CPU proof with Boolean unit
weights. The desc row consumes the CPU ECALL tuple with weight `-active`; the
tuple binds `a0`, `a7 ∈ {0x30001, 0x30002}` (selecting `set`), epoch and the
ECALL's after tick `4r+4`. The CPU emits one OWNER tuple per ECALL row and the
bridge set is fixed by the key (bulk fixed columns are in the fixed root; the
bulk block is in `beginCpu`), so every bulk ECALL is matched by exactly one desc
row and vice versa (tuples are distinct by tick). `(TL, TH)` are U16/U8 ranged,
so the after clock is the canonical split of `4r+4`.

**B2 Token chain.** Tokens are OWNER19 tuples with slot 0 outside the opcode
range, so they only meet other tokens. Each call emits exactly one token
(the two weights sum to `active`, Boolean). Tokens are distinct per call
(distinct ticks). Body start rows consume them with Boolean weight `start`.
Mass < p (section 6) makes the per-tuple multiplicity sum exact, so every token
is consumed by exactly one start row and every start row consumes an emitted
token: each call has exactly one body run with that run's `dst`, `src`/`fill`,
`N` and after clock.

**B3 Run length.** A run is a start row followed by continuation rows; row 0's
wrapped predecessor is padding (last row inactive) so every active run begins
with a start row. `remaining` starts at `N` and decreases by one per row; the
end constraint forces the last row to have `remaining = 1`. Hence
`N ≡ run length (mod p)`. Both are < p (`N < 2^29` from `q0 < 2^16`,
`l1 < 2^16`; run length ≤ 2^24 rows), so `N` is the integer run length. No word
is skipped and none is added. `len` limbs 2, 3 are the constants 0 in the packet
read tuple, so a packet with `len ≥ 2^32` cannot be read; `8*q0 = len.limb0` with
`q0 < 2^16` forces `len ≡ 0 (mod 8)`.

**B4 Addresses, alignment, wrap.** Body row `j` of a run addresses
`dst + 8j` and `src + 8j` (carry chain, Boolean carries, no carry out of limb
3). Every RAM tuple must equal a produced token, all of whose address limbs are
canonical (INIT addresses are canonical, aligned, sorted and unique —
`protocol.zig` admission — and transitions preserve addresses). With canonical
limbs the carry equations are exact integer addition, and a wrapping address
would need limb 3 = 2^16, which no token has. Alignment of `P`, `dst`, `src`
follows likewise: only 8-aligned addresses exist in the RAM history. No explicit
alignment bits are needed.

**B5 RAM order and freshness.** Each access is a RAM14 transition from a
consumed before-token to an after-token at `(E, 4r+4)`, weight `active`.
Before clocks equal produced clocks, hence are canonical (P1/P2 of the joint
induction note); the gap equations with ranged gaps then hold over the integers
and give a strict lexicographic increase. The global RAM DAG argument
(`rv64-ls-canonical-range-induction.md`, step 4) applies unchanged: every address
history is a single chain from INIT through strictly increasing clocks to TERM.
Consequences: (i) a read observes the latest earlier write to its address,
including writes by earlier bulk calls, LS stores, Keccak and secp (adversarial
"stale read" tests); (ii) two accesses of one address at the same clock are
impossible, so an aliasing call is unprovable (test "overlap": snapshot form
leaves the RAM sum unbalanced, chained form needs gap −1); (iii) every later
access observes the call's writes. Reads keep value and rights
(`after = before` by construction: the same columns); writes keep rights
(R = W = 1 are constants in both tuples, so only rights-3 words can be written).

**B6 Values.** memcpy: the dst after value *is* the src before value (shared
columns); a wrong copied word is a wrong src read, which matches no produced
token. memset: `after = 257*fill` per limb with `fill = lo`, where
`word1.limb0 = lo + 256*hi`, `lo, hi < 256` (U16-pairs), i.e. `lo = word1 & 0xff`.

**B7 Canonical limbs (joint REG/RAM write induction).** The induction in
[rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md) requires
every RAM producer to be independently anchored or to depend only on tokens with
strictly smaller `(epoch, clock)`, and every producer tick to be `4r'+4`.

- *Ticks*: all bulk after-tokens carry the desc row's OWNER-bound tick `4r+4`
  (B1) copied through the token and continuation equalities. P1 holds.
- *Packet and src reads*: `after = before` with tau(before) < tau(after) (B5);
  new edge "bulk read → its before token", strictly decreasing.
- *memcpy write*: `after.value = src.before.value`, a consumed token with
  strictly smaller tau (B5). New edge E5 "bulk copy write (e,4r+4) → src before
  token <lex (e,4r+4)", strictly decreasing; IH gives canonical limbs.
- *memset write*: independently anchored: `257*fill ≤ 65535` since
  `fill < 256` is ranged in the desc row.
- *Addresses/rights*: preserved by transitions (unchanged argument).
- OWNER weight coupling: bulk RAM weights are the Boolean `active` of the row;
  bulk does not supply OWNER C values to the CPU (ECALL C = 0 as for the other
  bridges), so P4 is unaffected. Tokens are disjoint OWNER tuples.

So the lemma extends with one new strictly decreasing edge; no circularity.
Removing the shared value columns (e.g. giving the dst write its own unranged
value columns) would break this — such a change must re-open the lemma.

## 5. Adversarial and known-answer tests

`bm/tests.zig` (`zig build test-riscv64-word16-bulk-memory`): a scenario of five
calls over two epochs (memset; memcpy reading the memset output; adjacent
cross-epoch copy; memset with a read-only packet; copy from a read-only source)
is checked for zero residuals and closure of RAM14 (against INIT/TERM of every
touched word), OWNER19 (against the CPU ECALL tuples) and in-table U16 values.
Known answers check copied/filled words. Each forgery names the check that
rejects it:

| Forgery | Rejected by |
|---|---|
| wrong copied word | RAM14 (src read token) |
| wrong memset fill on body rows | OWNER19 token + RAM14 |
| skipped word (a) chain shortened | local chain-end constraint |
| skipped word (b) remaining relabelled | OWNER19 (token N) + RAM14 |
| extra write (a) fifth continuation row | local chain-end constraint |
| extra write (b) standalone run + claimed count | OWNER19 (no token) + RAM14 |
| stale read before a prior write | RAM14 |
| predecessor at the call's own tick | U16 (gap −1) + RAM14 |
| accesses moved to a later CPU tick | OWNER19 + RAM14 |
| `len` not a multiple of 8 | U16 (`q0` out of range) |
| non-canonical copied limbs (`+2^16`, `−1`) | RAM14 |
| memset byte ≥ 256 | U16 |
| memcpy executed as memset (tag) | OWNER19 (ECALL `a7`) |
| forged packet `dst` | RAM14 (packet read) |
| overlapping memcpy | native admission; AIR: RAM14 or U16 (gap −1) |
| degree > 3 | finite-difference check |

Executor (`ethereum_services/bulk_memory.zig`): length 0, 12, 2^20+8,
misaligned dst/src, both overlap directions, packet aliasing dst or src,
unmapped, read-only destination, wrapping address; every trap leaves memory
unchanged.

Services lane (`svc/bulk_test.zig`, `zig build
test-riscv64-word16-bulk-services`): section 8.

## 6. Mass bounds (M31 characteristic)

Per CPU proof (`svc/protocol.zig::admitBulk`, repeated in `svc/wire.zig`):

- RAM14 (global sum, with every other producer): `6*calls + 4*copy_words +
  2*set_words` added to the existing global bound `ram < p`;
- U16: `17*2^log_desc + 6*2^log_copy + 3*2^log_set` added to the CPU's range16
  mass, `< p` (every physical row, padding included, looks up);
- OWNER19 (local): ECALL consume 1 + token emit 1 per call, start consume 1 per
  call: `≤ 3*calls`; bulk ECALLs are CPU steps, so
  `keccak + add + double + bulk.calls + ls ≤ steps < 2^22` is checked;
- body rows `copy_words + set_words ≤ calls * 2^17` (per-call cap);
- geometry: each present kind has `rows < 2^log`, `5 ≤ log ≤ 24`; a kind is
  present iff its row count is nonzero, and `copy`/`set` require `desc`.

`N < 2^29`, run lengths `< 2^24` and clocks `< 2^25` keep all integer
equations below p (section 4).

## 7. Integration

- `svc/types.zig`: `Logs.bulk` (desc/copy/set logs), `BulkCounts`,
  `BulkClaims`; JSON omits `bulk` when empty.
- `svc/roster.zig`: bulk fixed columns and sources after the three families.
- `svc/protocol.zig`: `Request.bulk`, `admitBulk`, a transcript block mixed
  only when bulk is present.
- `svc/statement.zig`: `CpuClaims.bulk` (RAM, OWNER, U16 per kind), mixed after
  the v2 claims only when present; included in `local()` and `ram()`.
- `svc/air_components.zig`, `worker.zig`, `pipeline.zig`, `execution.zig`,
  `wire.zig`, `collector.zig` (ledger replay of each bulk call; values come
  only from the chronological RAM ledger).
- Frontend (on top of the shared v3 plumbing from `codex/rv64-guest-prover-sha256`):
  `MEMCPY_TAG`/`MEMSET_TAG`, session dispatch arm and `ethereum_services/bulk_memory.zig`
  executor, `Tape.appendBulk` (no payload section: the ECALL step's `lhs`/`rhs`
  are the pointer and tag, so the tape wire is unchanged), boundary capture and
  access census arms, the v3 capture whitelist, and the Ethereum plan's bulk logs.
- Collector: bulk calls are counted from the CPU's own ECALL service records
  (not from a tape list) and replayed on the chronological ledger; every value
  the bridges use comes from that ledger, never from execution advice.

**v2 byte identity.** With no bulk roster nothing new is mixed, serialized or
committed: `beginCpu`, claim mixing, CPU proof columns, `bundle.json`
(`Logs`, `CompactRequest`, `CpuClaims` use custom JSON writers that omit empty
bulk fields) are unchanged. Checked by the existing combined-services suite and
by section 8.

## 8. Measured cost and qualification

See section 9 for numbers measured on this branch.

## 9. Gaps

See the end of this file (kept current with the branch).
