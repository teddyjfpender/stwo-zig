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
