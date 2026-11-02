# LS joint REG/RAM write induction (LS48 -> LS32 gate)

Status: recovered implementation; qualification of the current MAIN70/schema7
port is tracked in [rv64-ls32-qualification.md](rv64-ls32-qualification.md).
Sections 1–10 preserve the earlier LS32 reasoning and historical measurements.
This is the design gate for removing the eight LS v2 U16 queries on the RAM
after-value limbs (logical columns 18-21) and the load result C (40-43). Base
commit eac3b7c07. This is a source-level argument, not a machine-checked proof.
It is conditional on the soundness of the physical STARKs and the randomized typed
LogUp arguments, exactly like
[rv64-ls-canonical-range-induction.md](rv64-ls-canonical-range-induction.md),
whose final bullet deferred this "further joint write lemma". Verdict at the end.

Paths are abbreviated: `air/` = `src/frontends/riscv/rv64/air/`, `ls1/` =
`air/memory/load_store_v1/`, `ls2/` = `air/memory/load_store_v2/`, `ram/` =
`air/memory/closed_ram/`, `x/` = `air/word16_execution/`, `int/` =
`src/integrations/riscv_cpu/`. Line numbers refer to eac3b7c07.

## 1. Checks removed and who relied on them

| Removed query (unit weight, every physical row) | Old role | Consumers that need the fact |
|---|---|---|
| U16 on after-value limbs, logical 18-21 (`ls2/layout.zig:16`) | independent anchor for every LS-produced RAM token | every later RAM consumer of that token: LS loads/stores, Keccak/secp bridges (they re-range their own before bytes anyway), TERM (public) |
| U16 on load result C, logical 40-43 (`ls2/layout.zig:16`) | independent anchor for LS register writes | CPU REG slot-2 after token (`x/tuples.zig:27-35`), hence every later register read: ALU/BINARY/SHIFT/MUL/DIV/JALR inputs, LS A/B, ECALL a0/a7 |

Nothing else reads these coordinates as bounded integers inside LS: the address,
selection and store equations use before limbs 14-17, B, b_low and the selection
facts (`ls1/equations.zig:71-123`). The removal therefore only loses the two
canonicality facts above; the lemma below re-derives both.

Retained (unchanged): U16 {12 after-low, 24 epoch gap, 25 low gap, 68 address
quotient}, U8 {13 after-high, 26 high gap, 73 b_low, 74 b_high}, OWNER19, the
selection lookup, the separate RAM14 inverse/prefix.

## 2. Value-independent prerequisites (already established, unchanged)

These facts are proved without any value-canonicality premise, so they can be
used inside the value induction without circularity.

* **P1 Canonical produced clocks.** Every produced RAM token has a canonical
  `(epoch, tick)` with tick `= 4r'+4` for a CPU row `r'` of that epoch, or is
  INIT at `(0,0)`.
  - LS: OWNER19 slot 18 is logical m[3] `= after_low + 65536*after_high`
    (`ls2/projection.zig:51`, `ls2/equations.zig:15-16`); the CPU side is
    `tick(row,3) = 4*row+4` and the public epoch (`x/tuples.zig:6-8,59-60`,
    `x/equations.zig:29`). after_low U16 and after_high U8 are retained, so the
    split is the unique canonical one.
  - Keccak bridge: first lane binds m[3] and m[9] through OWNER, continuation
    lanes copy them (`air/delegations/keccak/word16_bridge/equations.zig:14-15,31,49,53`;
    lane-start selector `row%25==0` in `.../word16_bridge/source.zig:22`).
  - secp bridge: same pattern on TICK/EPOCH/LOW/HIGH
    (`air/delegations/secp256k1/word16_bridge/equations.zig:41-42,72,83,86`).
  - INIT: receiver requires epoch 0, tick 0 (`int/word16_global_execution/protocol.zig:141`,
    `int/word16_execution/memory/global_boundary_proof.zig:95`); CPU epochs are
    `ordinal+1 >= 1` (`int/word16_global_execution/protocol.zig:117`).
* **P2 Strict RAM predecessor.** Every active RAM before token equals (as a
  full RAM14 tuple) some produced token (INIT or an after token), and
  `(e_before, t_before) <lex (e_after, t_after)` as integers. Unit Boolean
  weights (`ram/equations.zig:128,154`), global RAM mass `< p`
  (`int/word16_global_execution/services/protocol.zig:71`), gap equations with
  retained gap ranges (`ram/equations.zig:136-141`), and canonical before clocks
  inherited from P1 through tuple equality. This is step 4 of the predecessor note.
* **P3 Strict REG predecessor, per shard.** In each CPU proof every enabled REG
  before token equals a produced REG token of the same proof with smaller clock:
  after clocks are fixed `4r+s+1`, s in {0,1,2} (`x/tuples.zig:6-13,27-35`),
  gap16/gap8 ranges retained, REG closes locally. This per-CPU scope is
  load-bearing because REG6 contains no epoch. The production services receiver
  calls `services/statement.zig::CpuClaims.local` inside each CPU verification
  loop; `services/protocol.zig::drawCpu` binds ordinal/manifest before drawing
  local REG/OWNER challenges. Only RAM and service truth debts may leave that
  proof. Named ledger shares are not individually authenticated certificates;
  closure uses the combined typed rational identity and independent challenges.
* **P4 OWNER bijection with coupled RAM weight.** CPU OWNER weight is
  `active-function`, Boolean (`x/equations.zig:19,84-85`); CPU tuples are pairwise
  distinct by tick. LS OWNER weight is LS `active` (`ls2/local_lookup.zig:25`),
  the SAME Boolean column that weights the LS RAM transition (`ram/equations.zig:128,154`).
  Bridges use `active*lane0` (`keccak .../equations.zig:53`, `secp .../equations.zig:86`).
  OWNER closes inside each CPU proof with mass `< p`. Hence each CPU LS row `r`
  is matched by exactly one active LS row (head or tail instance), whose RAM
  transition is in the global RAM multiset with weight exactly 1, and whose
  C equals the CPU C of row `r` (`ls2/equations.zig:11-17`, `x/tuples.zig:52-61`).
  Opcode whitelists separate LS and ECALL providers.
* **P5 FUNCTION writers.** Every consumed FUNCTION fact matches provider
  truth under the closed typed relation. The current source audit is complete
  for all52 architectural writers, explicitly including LUI/AUIPC, in
  [rv64-ls32-qualification.md](rv64-ls32-qualification.md#every-register-writer-and-its-source-authority).
  ALU sum/difference anchors are `word16_v1/alu.zig:143`; BINARY byte tuple
  anchors `word16_v1/binary.zig:97`; SHIFT tuple/sign anchors
  `word16_v1/shift_word.zig:80,84,109`; MUL RESULT BYTE coverage
  `delegations/multiplication/provider.zig:53`; DIV C queries
  `delegations/division/word16_product/equations.zig:43`. LUI and AUIPC route
  through ALU ADD at `word16_execution/features.zig:48,53`. JAL also uses ALU
  ADD at `:59`; only JALR's architectural link is ROM-bound at
  `word16_execution/tuples.zig:43`. These output anchors do not presuppose LS
  canonicality. Reusable FUNCTION fact weights must not be confused with
  stateful OWNER/RAM activity: the latter remains Boolean/unit.
* **P6 Selection truth.** The selection table is the immutable set
  `(x, p, byte_p(x), bit7(byte_p(x)), bit15(x))` for `x < 2^16`, `p in {0,1}`
  (`ls1/selection.zig:5-11,26-29`), fixed root rebuilt by the receiver; every LS row
  queries it with unit weight (`ls2/local_lookup.zig:18,25`).

## 3. Time domain

For a produced token X define tau(X):

* RAM token: `(epoch, tick)`. By P1, tick = 0 (INIT, epoch 0) or `4r'+4`.
* REG token of CPU proof with epoch e: `(e, clock)`, clock 0 for public initial
  tokens, `4r+s+1` for slot s of row r.

Order: lexicographic on pairs of naturals over the finite produced multiset, so
it is well founded. REG clocks reset per proof but are always paired with that
proof's distinct epoch, so `(e, c)` never collides across proofs.

## 4. Invariant and lemma

**I(X):** every value limb of token X is an integer in `[0, 2^16)`.

**Lemma.** In any accepting context of section 7, I(X) holds for every produced
RAM and REG token X. Consequently every consumed token (equal to some produced
token by P2/P3) is canonical, every LS load C is canonical and every LS after
value is canonical - exactly the facts the removed queries supplied.

**Proof.** Strong induction on tau. Each case either uses an independent anchor or
uses only tokens with strictly smaller tau.

* **INIT (RAM, (0,0)).** Values are receiver u64 image words
  (`int/word16_global_execution/protocol.zig:141`); the per-boundary claim is
  recomputed from u64 limbs (`ls2/boundary_source.zig:168-184`) and compared
  (`int/word16_execution/memory/global_boundary_proof.zig:223`). Base case.
* **REG public initial token (e, 0).** `P.word(u64)` limbs
  (`air/word16_cpu/public.zig:23-29`, `air/word16_cpu/boundary.zig:18-35`).
  Base case; no dependency on the previous shard (adjacency compares public u64).
* **REG slot 0/1 after token (e, 4r+s+1).** Value equals A resp. B, i.e. the
  value of the consumed predecessor, which by P3 is a produced token with clock
  `<= 4r+s`. IH. Disabled slots emit no token and force zero (`x/equations.zig:68-81`).
* **REG slot 2 after token (e, 4r+3).** Value is the CPU C. Every active CPU row
  is FUNCTION or OWNER (weights sum to `active`, `x/equations.zig:19`).
  - FUNCTION: P5 (independent anchor; inputs are tokens at `(e,4r+1)`, `(e,4r+2)`
    or ROM/PC constants, so even the weak form only needs IH).
  - ECALL: bridge OWNER tuples carry C = 0 (`keccak .../equations.zig:9`,
    `secp .../equations.zig:36`). Canonical.
  - Store: LS forces C = 0 (`ls1/equations.zig:107`). Canonical.
  - **Load (the removed C anchor).** By P4, C is the C of the unique LS row L
    with tick `4r+4`. By `ls1/equations.zig:92-106` (one load flag, one aligned
    offset: `:52-70,79-91`) each C limb is one of:
    (a) a before limb `m[14+j]` of L's consumed RAM token Z;
    (b) `selected_byte + sign*65280` (LB/LBU), with `selected_byte < 256` and
        `sign in {0,1}` by P6 (sign is the constant 0 for LBU), so `<= 65535`;
    (c) `sign*65535`, `sign in {0,1}` by P6 or constant 0 for unsigned loads.
    For (a), P2 gives `tau(Z) <lex (e, 4r+4)`; by P1 either Z is INIT
    (epoch 0 < e) or `tau(Z) = (e', 4r'+4)`; if `e' = e` then `r' < r`, so
    `tau(Z) <= (e, 4r) <lex (e, 4r+3)`. IH gives I(Z).
* **LS RAM after token (e, 4r+4)** from LS row L (the removed after anchor).
  Exactly one of eleven flags is set on active rows (`ls1/equations.zig:52-59`).
  - Load (LB..LWU, LD): `after = before` (`ram/equations.zig:144`); before is Z
    with `tau(Z) <lex (e,4r+4)` by P2. IH.
  - SD / SW / SH at aligned offset o: limbs inside the written window equal B
    limbs, all others equal before limbs (`ls1/equations.zig:109-123`). B is
    OWNER-bound to CPU row r's architectural B (`x/tuples.zig:57`), i.e. the
    slot-1 token at `(e, 4r+2)` or 0 if rs2 = x0. Before limbs: Z as above. IH.
  - SB at offset o, limb c = o/2, k = 1 or 256 by parity: other limbs are before
    limbs (IH); the target limb is `L_c + k*(b_low - selected_byte)` where
    `selected_limb = L_c` (`ls1/equations.zig:86-90`) and P6 makes
    `L_c < 2^16` and `selected_byte = byte_parity(L_c)` exactly. With retained
    `b_low` U8 (col 73) the result is `L_c` with one byte replaced, in
    `[0, 2^16)`. Independent of IH.
  Inactive (padding) rows emit no RAM/OWNER mass and have all MAIN zero
  (`ram/equations.zig:129`, `ls1/equations.zig:47`).
* **Keccak bridge after token.** after limbs equal two U8-ranged bytes
  (`keccak .../equations.zig:46`, `.../layout.zig:15-16`; 18-21 are also in its
  U16 list). Independent anchor; unchanged.
* **secp bridge after token.** after limbs are recomposed from U8-ranged bytes
  (`secp .../equations.zig:25`, `.../layout.zig:32-45`). Independent anchor.
* **Keccak-sponge after tokens (v3).** State-word after limbs are recomposed
  from the bytes of the IO11 output tuple the call row consumes; those equal
  Keccak-f truth bit sums over Boolean bits, so they are independently
  anchored. Packet and message accesses are reads (`after = before`, edge as
  E3). Ticks are the ECALL's `4r+4` through OWNER and the run token. Full
  case: [rv64-keccak-sponge-service.md](rv64-keccak-sponge-service.md) section 4.1.

Every dependency edge strictly decreases tau:

| Edge | From | To | Why strict |
|---|---|---|---|
| E1 | REG read (e,4r+s+1) | REG (e, <=4r+s) | P3 gap equation |
| E2 | REG load write (e,4r+3) | RAM (e,<=4r) or earlier epoch | P2 + P1 tick `= 0 mod 4` |
| E3 | RAM LS after (e,4r+4) | RAM before `<lex (e,4r+4)` | P2 |
| E4 | RAM store after (e,4r+4) | REG B (e,4r+2) | slot clock 4r+2 < 4r+4 |

No other producer has an incoming edge. A minimal counterexample (smallest tau
with I false) would contradict the corresponding case. QED.

## 5. Special cases the task asked to check

* **Partial stores.** SB handled by P6 + b_low; SH/SW by B substitution and
  unchanged before limbs; misaligned offsets are forced zero
  (`ls1/equations.zig:83-84`). Upper B limbs unused by SB are still OWNER-bound but
  never reach RAM.
* **Sign-extended loads.** Extension limbs are `0` or `65535`; LB's low limb is
  at most `255+65280 = 65535`. Signs come from table truth, not from limb ranges.
* **Padding rows.** All-zero, zero OWNER/RAM weight; their (now removed) unit
  range queries carried no obligation. Selection still queries (0,0,0,0,0),
  which is a table fact.
* **Two LS instances.** Head and tail share OWNER/RAM and the same equations;
  P4 is per CPU row, not per instance.
* **Cross-shard global RAM.** Z may come from any earlier epoch (P2 cross-epoch
  equation with ranged epoch gap). REG never crosses shards except through public
  u64 boundaries, which are base cases.
* **x0.** No REG event; reads forced zero; a load into x0 writes nothing.
* **OWNER19 Boolean weights are load-bearing.** If the LS OWNER multiplicity were
  decoupled from the RAM weight (or signed/non-Boolean), an LS row could supply
  an OWNER C while its before token is not consumed by RAM closure; C would then
  be an unconstrained before limb such as 65536 and nothing else would reject it.
  Previously the C range blocked this; now only the coupling does. Any future
  change to LS/CPU OWNER weights must re-open this lemma.
* **SB parity coupling is load-bearing.** Selection parity is the sum of the
  odd one-hot offset flags (`ls1/equations.zig:21`); byte replacement uses1 or256
  from those same flags (`:116`). Decoupling these would invalidate the byte
  replacement bound.
* **Per-proof REG/OWNER closure is load-bearing.** The production verifier must
  not sum CPU-local debts across shards; REG tuples have no epoch. Public u64
  register adjacency does not authorize a global unclosed REG argument.
* **Tick residue is load-bearing for unanchored LS writers.** If any RAM producer could emit a tick
  `4r+1..4r+3` in the CPU's epoch, E2 would not be strictly decreasing in this
  measure (a load's RAM predecessor could be "later" than its REG write). All
  current producers are OWNER-bound to `4r'+4` (P1).
* **Future writers.** Any new RAM or REG writer must either range its written
  limbs or be added as a case with a strictly decreasing edge. A future LS-like
  writer without an anchor and without OWNER-coupled RAM weight breaks the lemma.

## 6. Counterexamples showing what remains necessary

* Without the RAM closure, a load with before limbs `(v0+65536, v1-1, ..)`
  satisfies every local LS equation and writes a noncanonical register; only
  the unmatched RAM14 before token rejects it.
* Without REG closure, a store with OWNER B limb `65536` writes a noncanonical
  RAM limb; only the unmatched REG predecessor rejects it.
* Without selection truth, SB with `selected_byte` not equal to the real byte gives
  after limb `L + k*(b_low - s)` outside `[0,2^16)`.
* Without b_low U8, SB writes `b_low = 300` into one byte position.
* A bare LS proof (open RAM/OWNER debts) no longer guarantees canonical C or
  after values even "locally". It never was an accepting verifier.

## 7. Accepting contexts (caller obligations)

The lemma is valid exactly where P1-P6 and the base cases are enforced: closed
`int/word16_execution/execution.verify`, global execution, Keccak, shared-Keccak,
secp and combined services receivers, and the Ethereum receiver (prefix and
completed), plus CSP/Sail through the closed receiver. All of them close REG,
OWNER, FUNCTION and selection locally per CPU proof and RAM globally, and anchor
INIT/TERM against expected u64 cells. No new open verifier is introduced.

## 8. Planned encoding change (STEP 2, not implemented here)

* `ls2/layout.zig`: `LOGICAL_U16 = {12, 24, 25, 68}`, `LOGICAL_U8` unchanged;
  fractions 18 -> 10, strict pairs 9 -> 5 (pair 0 stays OWNER+U16[12]);
  INTER `8 + 4*5 + 4 = 32`; residuals 261 -> 257; MAIN71 unchanged.
* `RELATION_U16`/native caches keep all coordinates (OWNER/RAM reconstruction).
* Bump `ls2/encoding.zig` identity (inter32, joint write induction) and any core
  schema/claim-mass constant the protocol derives from LS query counts; historical
  receipts and `load_store_v1` untouched.
* Shapes changed: Word16 LS head/tail component INTER width and residual count,
  LS circuit-lane adapter (`int/tests/rv64_word16_execution_circuit_test.zig`)
  and the diagnostic `int/word16_recursion/shape.zig`. `int/rv64_recursion` does
  not reference Word16 LS. Recursion code is not updated.
* Negative tests (actual committed false MAIN, real physical proof accepted by
  bare verification, closed receiver rejects): aliased before limbs read by LD
  (RAM debt), aliased register B stored by SD (REG debt), wrong SB selected byte
  (selection debt), and the existing range-induction cases rerun on the new shape.

## 9. Verdict

The joint induction holds for the current tree: every REG and RAM producer is
either independently anchored (INIT, public registers, FUNCTION providers, SB
target limb, ECALL/store C = 0, Keccak/secp bridges) or depends only on tokens
with strictly smaller `(epoch, clock)`. Two properties not previously stated as
LS obligations are now load-bearing and must be guarded in STEP 2 and in future
changes: OWNER weight equals the Boolean RAM weight on LS rows, and every RAM
producer's tick is `4r'+4` (or INIT 0). P5 was inherited in the original design gate; the current source audit and
file-and-line writer inventory are now in rv64-ls32-qualification.md. MUL/DIV
result anchors are retained; DIV input-range trims are separately versioned.

## 10. Implementation (STEP 2) and deviations from section 8

Implemented as planned in section 8, with the following concrete facts and the
deviations marked.

* **Encoding.** `ls2/layout.zig:19` `LOGICAL_U16 = {12, 24, 25, 68}`,
  `LOGICAL_U8` unchanged; a comptime guard pins 10 fractions, 5 strict pairs and
  `INTERACTION = 32`. `.ls` residuals 261 -> 257 (`ls2/layout.zig:51`). MAIN71,
  `RELATION_U16/U8` metadata caches, OWNER/RAM reconstruction, boundary
  components (BOUND_U16 on INIT/TERM limbs 14-17) are unchanged. Native fill,
  histogram mass (`int/word16_execution/geometry.zig:72,79`) and the narrow
  interaction (`ls2/interaction.zig:155-169`) are already parameterized by the
  query list and needed no edit.
* **Identity.** LS encoding identity string bumped to `encoding-v5 ... inter32 ...
  10-affine-local-fractions/5-strict-pairs ... joint-REG-RAM-write-induction`
  and its mix tag version 4 -> 5 (`ls2/encoding.zig:7,16`). **Deviation:** the
  core execution `SCHEMA` is also bumped 5 -> 6
  (`int/word16_execution/protocol.zig:16`), so a stale schema-5 bundle is now
  rejected explicitly at the services wire roster
  (`int/word16_global_execution/services/wire.zig:95`, observed
  `InvalidServicesWireRoster` on the eac3b7c07 prefix4 outputs) instead of
  failing later inside transcript verification. The LS96 -> LS48 change did not
  bump SCHEMA; this one does because it changes the receiver's soundness premise.
* **Historical material untouched.** `load_store_v1`, the LS48 qualification
  JSON and the `vectors/reports` receipts are unchanged.
  `rv64-ls-canonical-range-induction.md` only gains a superseded pointer.

### Negative tests (gate 2)

Local algebra (`int/word16_execution/memory/range_induction_test.zig`): every
case satisfies all LS local residuals and every retained LS32 range query, then
names the closure that excludes it.

| Test | Forged coordinates | Excluded only by |
|---|---|---|
| noncanonical load alias (LD) | before/after/C limb0 `+65536`, limb1 `-1` | RAM before token (value limb) and OWNER C |
| noncanonical store write (SD) | B and after limb2 `+65536`, limb3 `-1` | OWNER B (REG predecessor via CPU) |
| false LB selected byte | selected_byte and C limb0 `+65536` | selection table truth (byte `< 256`) |
| SB false selected byte / wide b_low | after limb outside u16; b_low `+256` | selection truth; retained U8 col 73 |

Physical proofs (`int/word16_execution/memory/range_induction_proof_test.zig`):
committed false MAIN, real PCS proof accepted by the bare physical verifier,
fresh closed receiver `Execution.verify` returns `UnclosedExecutionRelations`.
For the three new LS32 cases the test also recomputes the honest and forged LS
ledger shares under the same challenges and asserts that range16 and range8
shares are **identical** (the removed queries are blind) while exactly the
listed debts move:

| Test (fixture row) | Forgery | Moved shares |
|---|---|---|
| `load_c_alias` (LW, row 1) | before/after/C limb0 `+65536` | RAM, OWNER |
| `store_after_alias` (SD, row 0) | B limb1 and after limb1 `+65536` | RAM, OWNER |
| `lb_false_byte` (LB, row 2) | selected_byte and C limb0 `+65536` | OWNER, selection |

The pre-existing `read_write_value` case was renamed: it is now rejected by
RAM/OWNER/selection closure rather than by write ranges. The planned "wrong SB
selected byte" physical case is local-only because the shared fixture has no SB
row; the physical LB case exercises the same selection debt.

### Shapes changed (recursion not updated)

* Word16 LS head and tail components: INTER 48 -> 32, residuals 261 -> 257,
  same MAIN71 and mask offsets. Every Word16 CPU proof loses 32 interaction
  columns (16 per LS instance).
* LS CircuitLane adapter qualification
  (`int/tests/rv64_ls_circuit_lanes_test.zig`,
  `int/tests/rv64_word16_execution_circuit_test.zig`) now sized from
  `L.constraints(.ls)`; both pass. The diagnostic `int/word16_recursion/shape.zig`
  reads shapes dynamically. `int/rv64_recursion` does not reference Word16 LS.
  Any recursive Word16 verifier or pinned circuit/layout digest built against
  LS48 must be regenerated.

### Measured effect (Ethereum prefix4, 4 CPU + 3 truth proofs)

Native cells (`cost.json`, interaction tree only changes): CPU interaction columns
640/612/580/1296 -> 608/580/548/1264; interaction cells 1,267,334,272 ->
1,215,429,760 (-51,904,512, -4.1%); all native cells 3,057,402,784 ->
3,005,498,272 (-1.7%). Truth proofs unchanged. Fresh `verify-prefix` accepted.

Interleaved runs on the shared machine (2 baseline, 3 LS32), summed over the
seven proofs: `inter_ls + inter_ls_tail` 0.232 -> 0.159 s; interaction commit
4.31 -> 4.20 s; composition 8.16 -> 8.07 s (within noise); peak footprint
unchanged (16.31 GB). Wall 23.89/24.09 -> 23.41/23.69/23.32 s and user
170 -> 157-160 s, but most of that difference is `proof_of_work` (1.67 -> 0.56 s
summed), which depends on the transcript and is grinding luck, not an effect of
this change. The structural gain is the 4.1% interaction-cell cut.

## 11. RAM writers beyond LS: the services roster (2026-11-02)

Sections 1-10 cover LS, the Keccak permutation bridge and the secp bridge. The
services roster (`int/word16_global_execution/services/roster.zig::Sources`)
now also carries SHA-256, arith256_mod, seven curve/field kinds, six bulk-memory
kinds, the three JUMPDEST kinds (in the bulk array) and the two Keccak-sponge components, all of which produce RAM14 tokens
inside the CPU proof. This section re-establishes the lemma of section 4 for
every one of them. It is written per writer so that a new writer appends one
case; the regression guard
`int/word16_execution/memory/joint_write_invariants_test.zig` ("services RAM
writer inventory") pins the roster fields, the bridge kinds, the bulk kinds and
the sponge kinds and must be updated together with this section.

### 11.1 Obligations of a RAM writer (generic)

A component that produces RAM14 tokens keeps the lemma iff it meets W1-W5.
Each is a source-level fact about its equations; the "Why" column of 11.2 cites
where each writer meets it.

* **W1 Written limbs.** Every value limb of every produced (after) token is
  either (a) independently anchored: an integer combination of range-checked
  columns with a bound `<= 65535` over the integers (e.g. `b0 + 256 b1` with
  both bytes U8, or `257 * fill` with `fill < 256`, or affine in Boolean
  columns), or (b) equal to a value limb of a token the same row (or the same
  call) *consumes* with strictly smaller `tau` (a strictly decreasing edge),
  or (c) a combination of (a) and (b) whose bound needs only I() of tokens
  with strictly smaller `tau`.
* **W2 Tick.** The after clock `(E, TL, TH)` of every produced token is the
  issuing ECALL's OWNER19-bound clock: consumed once per call with the CPU's
  `(epoch, 4r+4)`, `TL` U16 and `TH` U8 so the split is canonical, and copied
  unchanged by every continuation row of the call (a continuation row's
  predecessor is active). This is P1 for the writer.
* **W3 Strict predecessor.** Every consumed before token is a full RAM14 tuple
  with its own clock block and a ranged gap equation giving
  `(e_b, t_b) <lex (E, T)` over the integers (P2); before clocks are canonical
  because they equal produced clocks (P1, INIT).
* **W4 Rights and addresses.** A transition keeps address and rights: the same
  columns (or the same constants) appear in the before and after tuple; a
  written word has `R = W = 1` in both tuples; a read has `R = 1`. Addresses
  are affine in canonical limbs plus Boolean carries with no carry out of the
  top limb.
* **W5 Weights.** The RAM weight of each transition is a Boolean column (row
  `active`, a lane/slot selector or a product of Boolean columns), unit per
  access, and is the same activity that consumes the call's OWNER token, so a
  row cannot supply RAM writes without being tied to an ECALL (P4 analogue).
  ECALL OWNER tuples carry `C = 0`, so no service writes a register (REG side
  unchanged).

Under W1-W5 a writer adds only edges "after (e,4r+4) -> before `<lex`
(e,4r+4)" (strictly decreasing by W3) or none, so the strong induction of
section 4 goes through unchanged.

### 11.2 Writer cases (roster order)

| Roster field | Component / equations | W1 written limbs | W2 tick | W4/W5 |
|---|---|---|---|---|
| `keccak` | Keccak word16 bridge (`air/delegations/keccak/word16_bridge/equations.zig`) | (a) `after = AFTER_BYTES[2c] + 256 AFTER_BYTES[2c+1]`, bytes U8 (`layout.zig` U8 list); limbs also U16 | lane-0 OWNER binds m[3]/m[9]; lanes copy (section 2, P1) | `write = active`, R = W = 1; weight `active` |
| `add`, `double`, `sha256`, `arith256_mod`, `curves[7]` | one shared CPU-side bridge, the secp word16 bridge `S` (`air/delegations/secp256k1/word16_bridge/equations.zig`), instantiated per `S.types.Kind` (add 1 .. bls12_381_g1_double 11); the truth AIRs (`delegations/{sha256,arith256,curves}`) touch only Wire35, never RAM | (a) `row[18+c] = AFTER[2c] + 256 AFTER[2c+1]`, every BEFORE/AFTER byte U8 (`layout.zig` U8 list); unwritten coordinates have `write = 0`, forcing `after = before` (b) | coordinate-0 OWNER tuple binds EPOCH/TICK, `TICK = LOW + 2^16 HIGH`, LOW U16, HIGH U8; continuation rows copy pointer/clock/call id | R/W columns shared by both tuples, `write => W = 1`; weight `active`, write flag `active * fixed(isWritten)` |
| `bulk[desc]` | `air/delegations/bulk_memory` desc | (b) packet reads only: `after = before` (same columns) | ECALL OWNER tuple, `TL` U16, `TH` U8 (bulk B1) | R = 1, W column shared; weight `active` |
| `bulk[copy]` | aligned copy body | (b) dst `after` = src `before` value columns (shared); src read `after = before` (bulk B7, edge E5) | token clock, continuation equality (bulk B2) | dst R = W = 1 constants; weight `active` |
| `bulk[set]` | memset body | (a) `257 * fill`, `fill < 256` ranged on the desc row and carried by the token | as copy | as copy |
| `bulk[ucopy]` | unaligned copy body | (c) dst limb `i` = `b0 + 256 b1` where `b0, b1` are bytes of the src before tokens of this row and the previous row of the same run; even bytes U8 (two U16 facts), odd bytes `< 2^16` by U16 and `< 256` because `lo + 256 hi` is the canonical before limb (I of a token with strictly smaller tau). Src read `after = before` (b). (bulk B10) | as copy | dst weight `active - start` (Boolean: start => active), R = W = 1 constants; src weight `active` |
| `bulk[cdesc]` | memcmp descriptor | packet reads (b); result word (a): limbs `(pos + 65535 neg, 65535 neg, 65535 neg, 65535 neg)` with `neg, pos` Boolean and `neg * pos = 0`, so each limb is in {0, 1, 65535} | ECALL OWNER tuple (as desc) | result write R = W = 1 constants; weight `active` |
| `bulk[cmp]` | memcmp body | (b) reads only: `after = before` for both operands | token clock, continuation equality | R = 1, W column shared; weight `active` |
| `bulk[jdesc]` | JUMPDEST descriptor (`bm/` jdesc, tag 0x30040) | (b) packet reads only: `after = before` (same columns; code limb 0 = `64 q`) | ECALL OWNER tuple, `TL` U16, `TH` U8 (as desc) | R = 1, W column shared; weight `active` |
| `bulk[jscan]` | JUMPDEST scan row (8 code reads + 1 bitmap write per 64 code bytes) | bitmap write (a): limb `l` = `sum_{i<16} j_{16l+i} 2^i`, each `j` a jtab table output in {0, 1} (OWNER19 lookup, per-proof closure) or forced 0 on invalid words, so `0 <= limb <= 65535` with no earlier token; code reads (b) `after = before`, value limbs `b + 256 b'` with table-ranged bytes | token clock, continuation equality (jumpdest doc J1/J2) | write R = W = 1 constants, weight `active`; read W column shared, weight `valid_w` (Boolean prefix bits, `valid_0 = active`) |
| `bulk[jtab]` | JUMPDEST transition table | no RAM tokens (OWNER19 table side only) | - | - |
| `sponge_plan`, `sponge[call]` | `air/delegations/keccak_sponge` call row | state lanes: `after = limbsOfBytes(new)`, `new` bytes consumed as IO11 direction-1 tuples whose only producer is the Keccak truth (bytes are sums of Boolean bits), so canonical after global IO11 closure (a, cross-component anchor; sponge doc S6/S7); packet reads (b) | ECALL OWNER tuple, `tick_low` U16, `tick_high` U8 | state R = W = 1 constants; packet W column shared; weight `a` |
| `sponge[perm]` | sponge permutation rows | reads only (b): message windows `after = before` | first row consumes the call token carrying the call clock; continuations copy | R = 1, W column shared; weight `read[j]` Boolean and only on active rows |

`core` is the CPU + LS + boundary source (sections 1-10). The JUMPDEST case
is argued in `rv64-jumpdest-service.md` J3-J6; its writer is case (a) like
memset, so no new dependency edge. `sponge_plan` is the
owned plan of the two sponge sources, not a component.

### 11.3 Notes and premises made explicit

* **IH-dependent byte bound (ucopy writes; cmp byte splits on reads).**
  Splitting a limb `L = lo + 256 hi` with `lo` U8 and only `hi < 2^16` gives
  `hi < 256` only if `L < 2^16`, i.e. only from I() of the consumed token.
  For a *write* (ucopy) this is case (c): the dependency is on src before
  tokens of the same call, `<lex (E, T)` by W3, so the edge is strictly
  decreasing. For reads (cmp) it is a consumer-side use of the lemma, not a
  producer case. Dropping the canonical-limb premise (e.g. giving a ucopy byte
  its own unconstrained high byte) breaks the ucopy case.
* **Cross-component anchors.** The sponge's written state relies on global
  IO11 closure and on the Keccak truth being the only direction-1 producer;
  LINK tuples use direction 2. This is an anchor outside the CPU proof and is
  valid in the same accepting contexts (section 7) that close IO11.
* **Sponge clock columns.** Sponge before-clock limbs and the call epoch are
  not range-checked locally; the gap equations rely on the consumed token's
  clock being canonical (P1, INIT) and on the OWNER-bound CPU epoch. This is
  P2 as stated, listed here because the bulk and secp bridges range the same
  columns.
* **Curve/field writers (`curves[7]`, bridge kinds 5..11).** Detailed in case
  C7 of [rv64-curve-services.md](rv64-curve-services.md) section 4. The packet
  is INLINE and 32-byte aligned (no pointer indirection), so every RAM word a
  curve call touches is a bridge coordinate row at `a0 + 32 c`; the outputs
  overwrite the leading `curves.writtenCoords` coordinates (BN254 G1 add and
  Fq2 mul 2 of 4, BN254 G1 double 2 of 2, BLS Fp2 mul and G1 add 3 of 6, BLS
  G1 double 3 of 3, arith384_mont 2 of 5: the 48-byte r spans coordinates
  0..1), and every other coordinate has `write = 0` (`after = before`, edge to
  a strictly earlier token). Written limbs are case (a): the 32 AFTER bytes of
  every bridge row are U8, independent of the truth AIR's own canonicity
  checks. No new edge kind; the evmone v3 client (`--v3-set ...,bn,bls`)
  only changes which kinds occur, not the equations.
* **Zero-length calls.** A memcmp descriptor proves `len / 8 != 0` (inverse
  column) and an unaligned-copy lead row is never the whole run: a zero-word
  run cannot reach `remaining = 1`, and a memcmp run that never reaches it could
  otherwise end on a forged difference after reading words outside the
  operands (bulk B9). This is a semantic (W1-independent) fact recorded here
  because it is the only constraint added during this re-check.

Verdict: the lemma of section 4 holds for every writer in the roster at
`codex/rv64-ge-bulk`; no writer has an unanchored written limb or a tick not
bound to `4r+4`. The only constraints added by this re-check are the two
zero-length rules for the new bulk kinds.
