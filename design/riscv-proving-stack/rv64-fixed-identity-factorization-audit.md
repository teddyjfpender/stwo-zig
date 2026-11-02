# Why one program currently produces29 immutable fixed keys

The keys differ because independently sized chip schedules are concatenated into one FIXED commitment. They do **not** contain execution PC/register endpoints, RAM boundary values or service call contents. Moving those values to MAIN would add work to solve a problem the current lane already avoids.

For the pinned complete block, all25 CPU shards have distinct ordered FIXED column-log vectors. Therefore whole-key identity differs before examining coefficient values. The five truth workers require four identities: the two log-18 Keccak truths share one setup; ADD has two geometries and DOUBLE one. This explains29 identities and zero whole-cache hits. Each key is immutable per program/geometry, but the request selects geometry, so this is not one immutable setup per program.

## Source map

| FIXED part | What the columns contain | Source |
|---|---|---|
| CPU,3 | logical row index, FIRST, LAST | `air/word16_cpu/fixed.zig:6` |
| ROM,32 |30 instruction/PC/feature coordinates from the independently loaded program, FIRST/LAST | `word16_execution/program.zig:120` |
| Register boundary,34 |32 one-hot register selectors, FIRST/LAST | `air/word16_cpu/fixed.zig:16` |
| ALU/BINARY/SHIFT/JALR | legacy FIRST/LAST scheduling columns; unused by the current GKR MAIN authority | `word16_execution/setup.zig:70`; `gkr_local/shape_metadata.zig` |
| MUL/DIV,3 each | relative row index, FIRST, LAST | `air/delegations/multiplication/trace.zig:56`; `division/word16_product/source.zig:61` |
| LS/INIT/TEARDOWN,3 each | relative row index, FIRST, LAST; no addresses or values | `word16_execution/setup.zig:98`; `memory/load_store_v2/source.zig` |
| U16/U8/AND/SHIFT/selection tables | universal table values and domain selectors | `word16_execution/setup.zig:94`; `word16_v1/shift_word_packed_table.zig` |
| Keccak bridge,6 | relative row, first/last, lane index/group start, relative call index | `air/delegations/keccak/word16_bridge/source.zig:12` |
| Secp bridges,8 | relative schedule plus immutable RCB output-wire mapping | `air/delegations/secp256k1/word16_bridge/source.zig:11` |
| Keccak truth,32 | phase selectors, relative slot index/completeness | `air/delegations/keccak/trace.zig:148` |
| Secp truth | immutable operation/wire/use schedule plus relative call/phase indices | `air/delegations/secp256k1/trace.zig:188` |

Frontend paths in the table are relative to `src/frontends/riscv/rv64/`; integration paths are under `src/integrations/riscv_cpu/`. The CPU source-key constructor accepts image authority, geometry and bridge geometry, not requests (`ethereum/keys.zig:40`). Public register words/clocks enter selector coefficients, not the fixed buffer (`air/word16_cpu/boundary.zig:18`). Keccak FIRST_ID/call count select public spans and MAIN activity; its fixed constructor takes log only. Secp truth constructors likewise use immutable program kind and geometry; execution wire values stay in MAIN.

Initial/final memory cardinality affects **chosen log**, not fixed row contents. Dynamic PC is CPU MAIN/public endpoint state; ROM PC is the immutable list of code addresses. This distinction matters when describing request independence.

## Actual30-worker census

The additive `rv64-om-retention-plan` diagnostic now emits source-derived fixed parts using the production geometry and role authorities. It constructs no coefficient rows or setup key. Its ordered-log signature is a diagnostic, never coefficient/root authority.

Across the25 CPU references:

| Category | Native coefficient reference bytes |
|---|---:|
| Guest ROM, log20 |3,355,443,200 |
| Geometry-only schedules |2,017,009,664 |
| Universal tables |209,792,000 |
| Universal register selectors |108,800 |
| Secp bridge program schedules |4,767,744 |

CPU ROW/FIRST/LAST alone account for1,258,291,200 of the geometry bytes. Unused legacy ALU/BINARY/SHIFT/JALR columns account for210,354,176 reference bytes. Deleting every unused fixed column would reduce ordered-log classes only25→23: workers12,13,21 would then share a log layout; all others still differ. Equal logs alone would still require exact content validation before key reuse.

The ROM log20 reconstruction is checked by the actual trusted-key coefficient census: the metadata totals, excluding the second identical Keccak key, exactly equal1,416,141,376 native cells and3,732 planes recorded by the real29-key cache. The program contributes the same32-column ROM to every CPU setup. Four varying role schedules already distinguish all25 CPUs; for example ALU tail, Keccak bridge, SHIFT head and SHIFT tail.

These are **reference byte totals**, not current resident duplication. Qualified coefficient interning already reduced native payloads to279.7MB and whole-cache live bytes to2.001GB. Factorization must not claim another3.35GB resident ROM saving that interning has already delivered. What remains is repeated preparation/hash work and roughly1.72GB of whole-key Merkle/descriptor data.

## What can change without a protocol change

Existing native coefficient interning is the bounded exact-reuse mechanism. Whole-key lookup cannot merge these25 different ordered-log vectors while preserving the existing identity/root. Canonicalizing unused geometry fields does not address the actual roster. No additional speculative cache is implemented by this audit.

The measured candidate setup cost is not all FFT:29 expanded CPU coefficient commits took4.58s extension and11.14s Merkle, versus31.36s total setup including source-key construction and validation. A prepared-LDE cache alone cannot eliminate the larger hashing/reconstruction costs. Changing the root or silently pretending a different geometry has the same key would be incorrect.

## Program-only setup requires explicit factorization

The target is a shared program/universal-provider authority plus independently bound execution/layout identity. Two designs deserve costed prototypes:

1. **Implicit geometry polynomials with a program-only fixed root.** Known FIRST/LAST/index schedules are derived from admitted log and immutable chip/program semantics rather than committed in every whole key. Existing uncommitted public Eq/anchor preparation is a useful engineering seam, but it is not automatically a proof for every schedule. Native domain evaluation, OODS and circuit lanes must share a reviewed authority; especially logical ROW and periodic Keccak/secp schedules need efficient independent evaluation. Table values still need their own authenticated/known authority. Do not replace them with unconstrained MAIN or host-supplied OODS values.
2. **Immutable provider keys composed by an admitted layout registry.** Commit each program/table/schedule family at its own geometry once, then reuse roots. This avoids uniform padding and may reduce lifted-table work. It requires a PCS mapping for multiple fixed authorities and a cost model for added Merkle paths/openings and recursion. More roots can make verification worse; native cells alone are insufficient evidence.

Simply moving ROW to MAIN adds a witness column and recurrence constraints, while moving FIRST/LAST could be redundant with already known anchors. Such trades need complete committed-cell/constraint/opening/receiver costs, not an assumed win. No statement-dependent column was found that needs moving to a new boundary tree.

A production switch requires a new explicit protocol, not a cache flag: bind every role's geometry/presence/layout and the program/profile into the worker statement and manifest even when the fixed root stops identifying geometry implicitly; preserve complete physical/global closure; update source bounds, degrees and masks; derive receiver authority independently; qualify native/circuit parity, changed geometry/endpoint/program attacks, allocation failures and recursion key/topology admission. Keep the current candidate/control as measured controls. No whole128, GPU or unmeasured factorization speedup is claimed.
