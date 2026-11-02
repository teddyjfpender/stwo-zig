# Independent recovered LS32 review — 2026-11-01

## Verdict and scope

Reviewed committed `d873812af9d424ea99083df82ffe85b9f18e3d3a` (parent design `567823623`, base `eac3b7c07`) in `/private/tmp/stwo-rv64-perf2-air-ls32`, read-only. Also checked that main's newer DIV input trims retain the explicit C queries. I found **no soundness counterexample** to the joint REG/RAM canonical-value induction for the actual closed Word16 services receiver. The key production premises exist in code. This is an independent manual source review; I ran no new tests, generated no new proof, and give no formal soundness/security certification.

**Do not call the implementation fully qualified yet.** The remaining blockers are the specifically requested balanced-chain/cross-shard adversarial qualification and invariant guards, plus stale/incomplete design documentation. Existing isolated attacks prove rejection of open mismatches, not the fully balanced chain that motivated this architectural change. A successful honest prefix does not fill that gap. There is no identified fundamental design blocker requiring a new memory argument.

## Recovered original reviews

The workflow journal is `~/.claude/projects/-Users-theodorepender-code-cryptography-stwo-zig-rv64-frontend/41eff230-75ab-4f11-a53b-7db4dcd5a611/subagents/workflows/wf_335591ee-e99/journal.jsonl`. Exact relevant events are extracted to `/tmp/rv64-ls32-journal-recovered.json`.

- Design author `affee717f69d4ba0a`: implemented only the induction note, reported no counterexample, explicitly inherited P5 FUNCTION-provider anchors without re-auditing them.
- Critic `a129860c4f6452cb8`: `sound=true`, `proceed=true`; requested explicit JAL/LUI/AUIPC/FENCE handling, precise JALR link provenance, byte-parity coupling for SB, P5 source citations, stronger negative tests and layout/mass updates.
- Critic `a1e444ecf7d0f8700`: `sound=false`, `proceed=true`; importantly its notes state **“The core lemma holds”** and **“I found no counterexample.”** The false status reflects incomplete documentation/integration/test gates, not a discovered exploit. It additionally required explicit per-proof REG/OWNER closure and a balanced alias chain/cross-shard test.
- Implementer `a1127777ada097265`: committed d873812af, reports Safe suites and fresh prefix success, three new actual physical-proof attacks, intentional schema5 rejection. Its own report leaves P5 inherited and admits no full block.
- Post-implementation reviewer `a3b1de0a7a992cb5b`: review started, read substantial code, ran additional tests; **no result event** exists. It was interrupted. Do not represent that review as approved.

## Actual acceptance path checked

The production Ethereum route uses `word16_global_execution/services/execution.zig`, not only the old genesis receiver. Its `verify` independently admits the roster, checks the manifest, reconstructs shared challenges, checks stage-one roots, verifies each physical proof, then calls `encoded.claims.local()` **inside the CPU-proof loop**. The latter (`services/statement.zig:35–41`) checks `sum(all physical ledger fields) - RAM - service-truth = 0`. Only RAM/KIO/Wire are then accumulated across shards and closed globally.

This does **not** mean every named ledger field is an independent certificate. CPU, ALU, LS and other components authenticate combined prefixes. The justification is the randomized typed rational identity with independent relation challenges, conditional on the existing PCS/AIR/Fiat–Shamir and LogUp soundness assumptions. In particular, free ledger splits cannot be treated as separately authenticated REG/OWNER certificates.

`services/protocol.zig::drawCpu` binds the manifest and CPU ordinal before `word16_execution/protocol.zig::drawWithSharedRam`. `drawInternal` draws REG6, FUNCTION13, ROM30 and OWNER19 locally from that CPU transcript; only RAM14 is replaced by the manifest-derived shared relation. A later shard therefore cannot supply a missing REG or OWNER token for an earlier shard. REG tuples deliberately have no epoch coordinate; this local closure/challenge scope is a load-bearing property.

`global_execution/protocol.zig::validateInventory` restricts CPU count to65535, enforces epoch=index+1, contiguous CPU public boundaries, no repeated INIT/premature TERM, and exact admitted initial image words/rights at epoch0/tick0. Services admission bounds global RAM mass below M31's characteristic. CPU public validation bounds local clocks below4*steps, with steps<2^22. These integer sizes leave the retained clock-gap equalities far below the modulus; negative predecessor clocks cannot wrap into another produced clock.

## Producer/canonicality audit

Paths below are relative to `src/frontends/riscv/rv64/air/` unless prefixed `integration/`.

| Producer | Actual source authority | Why produced value limbs are canonical |
|---|---|---|
| Public REG endpoints | `word16_cpu/public.zig::word`, `boundary.zig::tupleFor/emitWithInputsFor` | Verifier-supplied u64 words are split into four actual u16 constants; initial clocks are0. Terminal boundary consumes, rather than creates, an earlier REG state. |
| INIT RAM | integration `word16_global_execution/protocol.zig::validateInventory`; `memory/load_store_v2/boundary_source.zig::expectedClaim` | Expected image u64 and rights are checked; the separately authenticated RAM claim is recomputed from the admitted public cell list. |
| REG slot0/1 | `word16_execution/tuples.zig::register/previousClock`; `equations.zig::weightsFor/emitFor` | After values copy the consumed A/B token. Fixed after clock is4r+1/4r+2, and gap16/U8 prove a strictly earlier predecessor. Disabled x0 slots emit no token and force zero. |
| ALU, including branches | `word16_v1/alu.zig::emitFor/rangeValueFor`; `alu_lookup.zig::emitFor` | Sum/difference limbs have unconditional U16 obligations. ADD/SUB select those limbs, W upper limbs are Boolean sign*65535, comparisons produce Boolean predicates with zero upper limbs. Multiplicity cannot disable these range queries. |
| LUI, AUIPC, JAL, FENCE | `word16_execution/features.zig::Entry.fromInstruction/romTuple` | All route through ALU ADD. LUI uses ROM immediate and x0, AUIPC uses ROM PC/immediate, JAL computes PC+4 using ALU; FENCE has no architectural nonzero result write. **JAL's C is not supplied by the ROM link field.** |
| JALR | `features.zig`, `tuples.zig::rom/function`, `jalr_equations.zig` | Architectural C is the ROM-authenticated PC+4 link because dynamic_next=1. The FUNCTION result is next_pc, using direct AND for zero immediate or the unit ADD→AND adapter otherwise. Those component outputs have their own canonical anchors. |
| BINARY | `word16_v1/binary.zig::derivePayloadFor/andTupleFor`, `binary_lookup.zig::emitFor` | Every byte A/B/AND tuple is checked against immutable AND truth with unit query weights. AND/OR/XOR byte results are bounded bytes, hence reconstructed limbs are u16. |
| SHIFT | `word16_v1/shift_word.zig::tableTupleFor/rangeValueFor/emitFor`; `shift_chunk_arithmetic.zig` | Immutable table gives bounded chunks with disjoint low/carry masks at a shared microshift. Boolean operation/offset/sign choices preserve u16 bounds; W upper limbs are0/65535 and C31 has a sign query. B-high range removal does not remove output anchors. |
| MUL | `delegations/multiplication/provider.zig::byteValuesFor`, `degree3_provider.zig::evaluateFor` | The first40 unconditional BYTE queries include all A/B/RESULT/product bytes; RESULT is columns16–23. Full FUNCTION projection reconstructs words from byte pairs, so C is canonical independent of input induction. |
| DIV | `delegations/division/word16_product/equations.zig::rangeValuesFor`, `layout.zig` | At d873 all A/B/C have explicit U16 queries. Main's later DIV trim removes A/B queries but retains C[0..4] as the first four queries. MUL/MULHU support remains required for full arithmetic semantics, but C canonicality itself is independently anchored. |
| LS load C | `memory/load_store_v1/equations.zig::emitLocalWithPublicFor` | C is copied from RAM-before limbs or is a selected byte plus sign*65280 / sign*65535. The load's RAM predecessor is earlier than the REG write, as detailed below. |
| LS store C / ECALL C | same LS equations; Keccak/secp `word16_bridge/equations.zig::ownerTuple` | Stores force C=0; service OWNER tuples have all four C coordinates zero. |
| LS RAM after | LS equations + `closed_ram/equations.zig::transitionLocalWithPublicFor` | Load preserves before. SH/SW/SD replace a window by canonical REG B limbs; other limbs are inherited. SB replaces one byte using immutable selection truth and retained b_low U8. |
| Keccak RAM after | `delegations/keccak/word16_bridge/equations.zig`, `layout.zig::U8` | Each after limb is low_byte+256*high_byte, and every after byte is unconditionally U8 queried. Before bytes also remain ranged. |
| secp RAM after | `delegations/secp256k1/word16_bridge/equations.zig::ramRow`, `layout.zig::U8` | Every before/after byte is U8 queried; each RAM value limb is recomposed from two bytes. Arithmetic truth correctness is additionally bound through Wire35; range inheritance does not rely on trusting a host hint. |

Pure FUNCTION-fact multiplicities may be arbitrary field elements. That is different from stateful OWNER/RAM activity. It does not provide a false canonical-input FUNCTION tuple: every supporting row must still satisfy its local output anchors and unconditional table/range obligations. Formal typed lookup soundness and mass bounds remain inherited assumptions, not something this review proves anew.

## Why the proposed balanced cycle does not evade the argument

Use a lexicographic order on `(epoch, clock)`, not register value or physical row allocation. RAM after tokens from LS have tick4r+4. REG writes of the same instruction are at4r+3; REG B is available at4r+2.

1. A register read depends on a strictly earlier token within the same shard. It cannot jump to another epoch because REG closes locally under that shard's challenges.
2. A load at rowr consumes a RAM token strictly before4r+4. An unanchored LS producer in the same epoch has tick divisible by4, so it is at most4r, earlier than the load's REG result at4r+3. Any predecessor in an earlier epoch is also earlier. An independently byte-anchored service producer is canonical directly.
3. A store after token at4r+4 depends on REG B at4r+2 and its strictly earlier RAM-before token.
4. Cross-shard RAM edges include the explicit epoch coordinate. They can only move to an earlier epoch, or an earlier tick in the same epoch, by the retained ranged strict gaps. REG state crosses shards only as canonical public u64 endpoints.

Thus a finite LD→REG→SD cycle containing a noncanonical limb would have a least-time bad token. Its producer either has an independent anchor or depends strictly earlier, contradicting minimality. Balancing interior lookup terms cannot create an anchored ancestor. To close a rootless cycle, an adversary must break the retained chronology, a local REG/OWNER obligation, or the expected INIT claim. **This is a source argument; the tests below are still needed to protect it.**

## Newly load-bearing guards checked in code

- **Unit coupling:** LS OWNER fraction numerator uses the same logical m[0] as RAM transition weight (`load_store_v2/local_lookup.zig::emitFor`, `closed_ram/equations.zig::transitionRamFor`). `transitionLocalWithPublicFor` makes it Boolean. CPU OWNER is active-function, and both weights are Boolean in CPU equations. Distinct raw opcode coordinates separate LS from service OWNER matches.
- **Clock coupling:** LS OWNER slot18 is logical m[3], expanded as after_low+65536*after_high. The CPU OWNER slot18 is fixed4r+4. Keccak/secp first-coordinate OWNER binds the same tick; continuation equations copy epoch/clock/call fields, and fixed tables identify coordinate starts. Calls form a constrained active prefix, so a continuation cannot invent an independent tick.
- **SB parity coupling:** Selection parity is the sum of odd one-hot offset flags (`load_store_v1/equations.zig::selectionTuple`); byte replacement factor is1/256 from those very same offsets. Together with selected_limb equality, table truth and b_low U8, the target limb is a byte replacement inside a u16 word.
- **Public boundary authority:** INIT claim is checked against expected u64 image cells, not a producer-provided alias encoding. TERM cannot act as an extra producer. These checks must survive the independently landed INIT/TERM width reduction as well.

## Concrete qualification blockers and tests still needed

1. **Balanced interior alias chain, actual physical proofs.** Existing new attacks mutate LS MAIN but leave CPU/REG/OWNER inconsistent; they correctly reject, but do not demonstrate ancestry as the sole remaining defense. Build a tiny `LD x1,[a]; SD x1,[a]; SD x0,[a]; ADDI x1,x0,0` style fixture. Use an initial word with limb2>=1; alias limb1+=65536, limb2-=1 (avoid limb0 because SD's b_low/b_high still range it). Propagate the alias through CPU C/A/B/previous_rd and REG metadata, LS before/after and OWNER tuples, so all interior CPU REG/OWNER/FUNCTION and retained range/selection obligations close. Reset RAM and x1 canonically before final public boundaries. Rebuild interactions from the actual committed forged MAIN. Bare physical verification must accept; the closed receiver must reject only the unmatched initial RAM ancestry. Compare all retained range/table ledger shares to the honest fixture to prevent rejection for an unrelated retained query.
2. **Cross-shard version under the production services receiver.** Carry the aliased state across a shard boundary in RAM, while restoring canonical public register endpoints in each shard. Prove every physical shard under the same sealed manifest; each CPU's local closure should pass; global shared-RAM closure must reject the earliest unanchored alias. Also attempt cancellation of equal/opposite REG debts across shards and require per-CPU rejection before global closure. Do not substitute constructor refusal or a stale proof-byte mutation for these attacks.
3. **Explicit invariant regression guards.** Test fractional/duplicated OWNER activity, OWNER C disagreement, off-residue LS ticks, and changed continuation ticks for both service bridges. Ensure CPU ROM/function/owner routing cannot reclassify an LS instruction to bypass unit RAM consumption. Existing comptime guard only pins query counts/width, not these premises.
4. **Finish documentation.** P5 still says inherited/not re-audited and misattributes JAL to ROM link; LUI/AUIPC/FENCE are absent. The ALU/SHIFT notes still list LS C4 as an independent output anchor. The old LS note gains a superseded pointer but retains conflicting historical statements; mark scope clearly. Add per-proof REG/OWNER closure and SB parity coupling alongside the two existing headline invariants. A source-level proof can be complete without pretending each ledger share is independently authenticated.
5. **Requalify the actual merged composition.** Main already changes CPU/ALU/SHIFT layouts, DIV input queries and INIT/TERM boundaries. Their output anchors remain in the reviewed code, but merged tests and a fresh complete block must pin the resulting layout/schema. This isolated branch's schema6 bump collides numerically with other schema6 changes; independently changed protocol identities still have to reject stale layouts. No new recursive Word16 acceptance is established by this change.

The first three are meaningful promotion gates, not a request to redesign the lane. After they pass on the actual merged source, I see no manual-source objection to the LS32 reduction.
