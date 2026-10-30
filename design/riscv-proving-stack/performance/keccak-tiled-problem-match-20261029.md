# Keccak tile architecture: exact schedule before protocol integration

Status: isolated constrained-kernel experiment. No released Keccak, caller,
lookup registry or proof protocol is replaced by this experiment.

## Problem match before implementation

**Task.** Preserve paired Keccak-f[1600] and its complete call/round/state
ownership while reducing recursive verifier input width. Cost is committed
field cells, exact OODS scalar inventory and recursive leaf/path/hash work,
not width alone. Existing 32-row minimum has 6,399 columns, 204,768 raw cells
and 18,781 original OODS scalars, excluding shared tables and caller companions.

**Structure.** The state permutation is a fixed, bounded tensor transpose and
rotation, not a search problem. Twenty-four rounds and 25 lanes are constants.
Two calls share each slot through `a + 8*b`; 29 state groups include all input,
round and output boundaries. Layout conversion is a bijective reindexing only
if every original bit, parity, lookup and boundary remains constrained.

| Candidate | Relation and guarantee | Cost/fit | Risk |
| --- | --- | --- | --- |
| Fixed shifted lane views | Exact reindexing, with independent fixed schedule | O(slots × rounds × 1600) work | Wider masks can erase recursion gains |
| New state permutation bus | Reduction via exact multiset equality | More main/interaction columns and typed identities | Missing producers, multiplicity and cross-call aliases |
| Compact packed chi/xor table inputs | Exact injective encoding over bounded original tuple domains | Same 8,192/1,024 table universes; fewer committed input accumulators | Must enforce ranges through exact table membership, not modular packing assumptions |
| ZisK five-output chi table | Equivalent nonlinear operation, different table geometry | 2^21 chi rows; amortizes more outputs per lookup | Large fixed-table cost on small callers |
| One bit per row | Exact only with all dataflow constraints | Tiny width but ≥65,536 rows per pair | Cannot match old raw area with only three columns |

**Source.** ZisK commit `1e22630bb7e143c30705a1603ed87cfd3da8c6ec`
parameterizes 25/5/1 lanes per row, uses 29 paired state groups and shifted
fixed views, and materializes masked chi inputs in a committed accumulator.
[Original PIL](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/precompiles/keccakf/pil/keccakf.pil).
Its MIT/Apache-2.0 license was inspected. The first Zig experiment independently
uses our original compact tables and constants; it does not copy PIL code or
claim ZisK performance transfers to Stwo.

**Chosen transfer.** First implement an independently derived fixed tensor
index schedule, then a generic scalar constraint kernel over exact shifted
views. Keep two-call encoding and compact table universes. Commit packed chi
and xor inputs to hold lookup denominator degree down; check packed inputs
against a canonical table image, so packing is injective over admitted values.
No new unconstrained state bus is introduced. Original memory/caller I/O is an
explicit integration obligation, not an inferred successful receipt.

**Geometry limits.** Converting all 29 state groups gives:

| Paired lanes per row | Rows per state | Active rows per pair | Padded domain | Equal-area column budget |
| ---: | ---: | ---: | ---: | ---: |
| 25 | 1 | 29 | 32 | 6,399 |
| 5 | 5 | 145 | 256 | 799 |
| 1 | 25 | 725 | 1,024 | 199 |

A separate-call one-lane variant needs two copies and a 2,048-row domain;
its equal-area budget is 99 columns. Mask/selector, interaction and provider
columns must all be included in a final model. These are derived bounds, not
qualified alternative trace geometries or end-to-end forecasts.

**Falsifier.** Reject the layout if extra committed cells, quotient degree or
mask unions negate the full recursive savings. Do not report a width ratio as
a speedup. The current caller merge saves only 7–8% of arithmetic verifier
rows; this experiment must address the physical bases to do substantially more.

**Correctness.** Reconstruct from the existing paired witness and compare every
state, compact chi/xor tuple and two-call output. Check odd trailing calls,
zero activity, boundaries, next-round moves, all rho/pi indices and padding.
Mutate state bits, parities, packed inputs, tile/round indices, active counts
and cross-call links. The generic equations must reject them before any STARK
integration. A later actual proof needs independent geometry/key derivation,
physical claim transcript binding, exact table/caller closure and hostile proof
replays. Prototype row checks alone do not provide proof authority.


## First constrained kernel and exact mask census

`air/guest_precompile/keccakf_tiled_kernel_v1.zig` is an isolated generic-scalar
kernel. Real original paired witnesses for zero, one, two and three calls pass
all 24 round constraints and exact original compact-table predicates. Tests
reject state, parity, packed accumulator and boundary mutations. The private
lookup census is exactly 38,400 chi and 7,680 xor events per paired slot.
The final dummy B output on an odd slot remains its genuine zero-input Keccak
output; it must not be incorrectly constrained to zero.

The main/fixed columns and every shifted main read are implemented. Interaction
columns below are a two-fractions-per-batch model with separate chi/xor
partitions, not yet generated or proven. Caller I/O and shared table area are
not included in the proposed counts, so comparisons are incomplete:

| Core | Main | Fixed | Interaction | Padded rows | Raw cells | OODS scalars |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original shard (includes its caller columns) | 2,204 | 31 | 4,164 | 32 | 204,768 | 18,781 |
| Paired one-lane prototype | 154 | 56 | 156 modeled | 1,024 | 374,784 | 3,953 |
| Paired five-lane prototype | 768 | 36 | 768 modeled | 256 | 402,432 | 5,924 |

Thus one lane reduces modeled OODS input by 4.75× while increasing core raw area
1.83×. It does not establish an end-to-end improvement. Exact framing gives
23,912 original leaf G rows per query plus 2,016 unshared path G rows at
blowup1. One-lane modeled leaves require 1,456 G/query and paths 3,696; five
lanes require 5,992 and 3,024. This excludes query deduplication, caller I/O,
all other components, table proofs, transcript, DEEP/FRI and prover execution.
A real proof adapter must verify these estimates before any performance claim.

Next required work is the exact private lookup registry/table image, LogUp
interaction producer and AIR adapter, original caller I/O equivalence, actual
base proof differential tests, independent recursive fixed/key compilation,
then a matched quiet-host comparison. A row evaluator and matching original
outputs are not a complete proof system.

## Full table universes and the rejected area-only hypothesis

The prototype now supports all four compact/full χ and compact/three-position
XOR combinations, at one or five paired lanes. Original paired witnesses for
one, two and three calls pass each variant, including odd trailing calls.
Every full χ output and XOR parity remains an independent lookup coordinate.
Combining those unconstrained output cells into one packed felt would admit
carry aliases; the hostile `+16/-1` paired-output mutation is rejected. The
full table variant is therefore arity six, not an invented two-column table.
Its exact power-of-two provider domains cost 25,952,256 committed cells
(12 columns × (2,097,152 + 65,536)), versus 110,592 for the existing compact
arity-six providers. Compact prototype tuples have two coordinates and require
separate, new table identities if integrated.

The cost test includes two explicit **unimplemented caller-storage options**:
(1) retain the original 284 metadata/I/O columns and 324 caller/I/O LogUp
columns on the tiled domain, or (2) retain a separate original-domain caller
with all original boundary state bits, metadata, I/O and interaction columns,
then add four tiled bridge columns and two carried call-identity columns. Option 2 deliberately counts duplicated
boundary state work; it is not described as witness-once. Both still require
actual caller equations, authenticated I/O census and proof qualification.
Neither omits table providers from its totals.

| Calls | Original full compact | Five-lane full tables + detached caller | Five-lane full tables + embedded caller |
| ---: | ---: | ---: | ---: |
| 2 | 315,360 | 26,209,760 | 26,292,224 |
| 128 | 13,215,744 | 42,432,512 | 47,710,208 |
| 1,024 | 104,951,808 | 157,794,304 | 200,015,872 |
| 8,192 | 838,840,320 | 1,080,688,640 | 1,418,461,184 |

Units are source-derived raw committed cells, not milliseconds, peak memory or
an accepted alternative proving profile. This **falsifies a base-area speedup
claim** for directly transplanting the narrow full-table layout. Narrow masks
can still save recursive work, but that must beat the extra base cost in an
actual combined measurement; no total speedup has been demonstrated.

The existing 25-lane adaptive candidate is a better area control. The new
model cross-checks these totals against `keccakf_adaptive_profile_v1.compile`
instead of creating a competing selector:

| Calls | Compact | Three-position XOR only | Full χ and XOR | Area-selected candidate |
| ---: | ---: | ---: | ---: | --- |
| 2 | 315,360 | 1,075,936 | 26,061,536 | compact |
| 16 | 1,748,736 | 2,414,336 | 26,826,496 | compact |
| 128 | 13,215,744 | 13,121,536 | 32,946,176 | XOR only |
| 1,024 | 104,951,808 | 98,779,136 | 81,903,616 | full tables |
| 4,096 | 419,475,456 | 392,462,336 | 249,757,696 | full tables |

Full tables are amortized once per shared table proof, so global sharing across
many caller shards matters. These figures do not justify independently
rebuilding or proving those tables for each tiny caller. Existing adaptive
modes remain `production_active=false`; their semantic/materialization tests
are not a replacement for original proof and recursive-key qualification.
The next production priority is the actual v7 caller recursive seam, alongside
native and joint-memory children, rather than promoting a larger-area tiled
prototype solely because its opened columns are narrower.
