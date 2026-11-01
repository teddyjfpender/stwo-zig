# LS joint REG/RAM write induction (LS48 -> LS32 gate)

Status: design gate (STEP 1) for removing the eight LS v2 U16 queries on the RAM
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
  gap16/gap8 ranges retained (`x/equations.zig:30-33`), REG closes locally.
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
* **P5 FUNCTION writers.** Every consumed FUNCTION fact is an active provider row
  satisfying its local AIR. Inherited premise (not re-audited here): each provider
  has an independent C anchor - ALU sum/difference ranges and Boolean predicates
  (`rv64-alu-canonical-input-ranges.md`, "Noncircular write anchors"), BINARY AND-table
  bytes, SHIFT table chunks (`rv64-shift-canonical-input-ranges.md:20-40`), MUL
  byte/limb ranges, DIV explicit U16 output anchors
  (`air/delegations/division/word16_product/README.md`), JALR/JAL link via ROM.
  The induction below only needs the weaker "canonical inputs => canonical C",
  and supplies canonical inputs anyway.
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
* **Tick residue is load-bearing.** If any RAM producer could emit a tick
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
producer's tick is `4r'+4` (or INIT 0). P5 is an inherited premise from the
existing provider notes and was not re-audited in this gate. MUL/DIV ranges are
not touched.
