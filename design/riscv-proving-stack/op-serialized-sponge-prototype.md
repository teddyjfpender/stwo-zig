# Serialized sponge bridge source prototype (admission closed)

The retained heavy CPU's widest native opening vector has 5,896 columns;
2,513 belong to the two sponge bridges. This isolated prototype serializes
whole state words while preserving the existing complete RAM14, OWNER19 and
IO11 tuples. It changes no production selector or schema2 admission.

The descriptor has 74 MAIN, 3 FIXED and 56 modeled OM31 INTER columns. It
retains the four packet reads, the original CPU/first-permutation OWNER tuples,
and emits exactly 25 unit-weight lane tokens. Each state-word row has 46 MAIN,
3 FIXED and 48 modeled INTER columns and consumes one full lane token binding
the complete packet/state pointers, after clock, first/last permutation IDs,
flags and lane. State rows emit complete before/after RAM pairs, old-state LINK
when not fresh, and final output IO. No word, clock or rights coordinate is
truncated. Interaction widths are source-derived estimates; a concrete PCS/GKR
component has not yet qualified them.

## Complete measured and modeled accounting

| Item | Existing call | Descriptor plus state words |
|---|---:|---:|
| Opening columns | 1,161 | 133 + 97 = 230 |
| Main constraints per role row | 325 | 54 / 20 |
| Local fractions per role row | 69 | 47 / 37 |
| Padded local fractions per row | 128 | 64 / 64 |
| Active rows for retained ordinal 3 | 74 | 74 / 1,850 |
| Padded rows | 128 | 128 / 2,048 |
| Modeled native cells | 148,608 | 215,680 |
| Padded local GKR facts | 16,384 | 139,264 |
| Raw source-binding denominator coordinates | 105 | 533 + 55 = 588 |

This is a 5.05x call opening-width reduction with 1.45x native cells and 8.5x
padded local facts for this class. The unchanged permutation role still has
1,352 columns: the partial whole sponge becomes 1,582 rather than 2,513 columns,
and the complete widest CPU becomes 4,965 rather than 5,896. These are source
costs, not a measured proving speedup. The new descriptor bounds covering-word
count using a U16 low limb and a two-bit high limb, independently of the future
permutation join.

The exact existing recursive GKR verifier was also evaluated on synthetic
source-legal dimensions, holding a common CPU sentinel at 26 layers and using
four coefficients per sumcheck polynomial. This probe excludes AIR binding,
PCS, FRI and permutation semantics. Existing versus candidate: 83,073 to 87,879
QM31 arithmetic rows; 3,272 to 3,456 P2 calls; 2,536 to 3,053 native OM31
products. Thus the recursive kernel adds 4,806 QM31 rows, 184 P2 calls and 517
native products. It does not erase the opening-width opportunity, but it is a
real cost and the larger source projection remains unqualified. The 25 lane
metadata tuples share an affine prefix; exact source-owned denominator
factoring can avoid repeated projection work, but is not implemented or claimed.

## Qualification and remaining gates

Four source tests pass: exact whole RAM14/IO11 multiset parity for fresh and
continuation calls with same/cross-epoch clocks; full OWNER19 token closure;
high-word/address/clock/range mutation rejection; and degree-at-most-three
finite differences under arbitrary fixed inputs. The complete original sponge
source suite also passed before the last independent word-count range tightening;
the focused suite passed after that tightening. The GKR cost probe passes.

Message reads and absorption/permutation lanes remain to be serialized. Unaligned
message bytes must use authenticated byte facts so adjacent lanes never duplicate
a RAM read at the same clock. Initial/final state links, capacity lanes, call
spans and padding must close to the unchanged Keccak truth. Empty input, full
blocks, shifted addresses, missing/duplicated lane/read facts and cross-call
substitutions require adversarial tests. Concrete component/worker/physical
proofs and independently derived receiver authority remain mandatory. No
execution acceptance or production performance claim is made by this prototype.

## Complete serialized permutation source follow-up

The permutation source is now split into a 44-MAIN header, 35-MAIN covering-word
row and 67-MAIN absorption-lane row. Each has three source-owned fixed columns;
modeled interactions are respectively16,32,32. The complete five-role bridge
therefore exposes465 columns instead of2,513 (5.40x narrower). The widest retained
CPU opening vector becomes3,848 instead of5,896, before concrete PCS qualification.

The header retains the complete old26-coordinate control prefix and18 read flags.
It supplies18 distinct full message-slot metadata tokens and two absorption-chain
endpoints. Each message row emits exactly its original full RAM14 pair, with the
same read weight. It provides full eight-byte WINDOW tuples with unit multiplicity
at slots0/17 and multiplicity2 at slots1..16. Continuation slot0 consumes the
previous permutation's slot17 carry token; it does not issue a second RAM read.
Each absorption row consumes the complete metadata/count/mask predecessor token,
emits its successor, and keeps the exact original two IO11 tuples. The count drops
by the sum of eight Boolean thermometer bits. Capacity lanes keep the count and
mask unchanged; fresh state is zero. Fixed lane16 alone supplies final0x80 padding.
The header authenticates the start count (136 or final remaining bytes), terminal
zero count and exact final mask. Source-owned fixed selectors are field values in
all emitters, including OODS; no evaluator extracts an integer lane from OODS.

Retained ordinal3 has74 calls and210 permutations. Including padding, old sponge
native cells494,720 become1,354,112 (2.74x more), and local padded facts81,920 become
540,672 (6.60x more). The added native work is859,392 cells in a CPU proof whose
whole-system cost is hundreds of millions of cells. These figures include all
five roles; they are not a prediction of wall time. All interaction counts remain
modeled until a concrete native component is qualified.

The complete dimension-only recursive GKR probe (sentinel26 layers, native
four-coefficient representation) measures old87,861 versus new102,282 QM31 rows,
3,456 versus4,010 P2 calls and3,044 versus4,598 native OM products. The increases
are14,421,554 and1,554 respectively. Raw source denominator coordinates are640
old versus1,207 new. PCS/FRI/opening savings and exact source-binding rows remain
unmeasured, so there is no end-to-end speed claim yet.

The source suite covers fresh and continuation, all eight byte alignments,
lengths0/1/7/8/135/136/137/272, exact legacy RAM14/IO11 multisets, complete internal
OWNER/WINDOW/carry closure, byte/clock/address/mask/shift mutations and degree3
finite differences for all role constraints. Packet-state, input-state and
input-packet overlap constructors reject exactly as the old ABI. Adjacent calls
reusing packet/input addresses at identical or different clocks preserve exactly
the old global tuple debt: this is not a local acceptance of inconsistent RAM.
Global RAM closure remains mandatory. Query-count tests bind the model constants
to actual emitter counts.

Next is an independently versioned, closed physical component/GKR authority with
all five source roles, source-owned OODS masks and exact cross-role closure. It
must pass physical proofs and fresh receiver mutations before any runtime/schema
switch. Existing schema2 and its retained artifacts remain the controls.
