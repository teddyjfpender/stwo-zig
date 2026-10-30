# Next encoding architecture: reduce committed work and recursive input together

Status: source-derived design and accounting, written while the retained full
Ethereum execution is being proved. No production source, frozen campaign
input, proof, transcript, or benchmark is changed by this note. No new timing
experiment was run. Projections below are field-cell or verifier-input models,
not measured speedups or soundness qualification.

## Decision

The next large change should have two coordinated parts:

1. Replace the wide, compact Keccak caller profile with a versioned profile
   selected by **original plus recursive closure cost**, sharing authenticated
   table work across a bounded source group. Qualify the already-written narrow
   Keccak kernel against this profile instead of inventing a second tiled
   layout. A narrower caller is the strongest opportunity on the measured
   caller-rich window: caller main and arithmetic-interaction columns alone
   occupy 79.8% of its original proof's physical width.
2. Introduce a canonical two-halfword native value ABI and operation-specific
   load/store and ALU relations. Preserve register clocks and all authenticated
   relation closures; remove redundant value representations, opcode-selector
   storage and universal load/store machinery. The retained full execution
   supports a source-derived **2.414 billion unpadded native-main-cell saving**
   for the three dominant families before new provider costs. This is a useful
   architecture budget, not an order-of-magnitude end-to-end prediction.

These changes address different workloads and compose at an explicitly
versioned register/RAM boundary. Neither smaller ALU aliases nor removing the
extra caller projections by themselves can deliver the requested order of
magnitude. The current full-block proof remains the functional reference.

## Evidence and scope

The retained execution census is
`vectors/reports/riscv-cpu-architecture-20261029/full-execution-pc-census/summary.json`.
It records 139,214,856 retired cycles, 139,181,943 native rows, 32,835 Keccak
calls, 78 recovery calls, and no SHA precompile calls. It is a full execution
census, not itself a proof. The ELF, input and expected output hashes are
recorded in that file. `pcs.json` gives the actual instruction frequencies;
`functions.csv` attributes 37,487,157 native rows (26.93%) to `copy_bytes` and
11,356,884 (8.16%) to software SHA-256 compression. The first 4M window's 90%
copy-loop share must not be extrapolated to the whole block.

`vectors/reports/riscv-frontend-work-ledger-20261029/native-families.csv`
accounts for the original 266-segment, 65,536-row-shard native-main encoding:

| Family | Actual rows | Columns | Padded main cells | Unpadded main cells |
| --- | ---: | ---: | ---: | ---: |
| Load/store | 56,231,701 | 50 | 2,933,593,600 | 2,811,585,050 |
| Immediate ALU | 29,396,043 | 35 | 1,121,003,520 | 1,028,861,505 |
| Register ALU | 19,280,758 | 35 | 790,982,080 | 674,826,530 |
| All native families | 139,181,943 | mixed | 6,625,111,062 | 5,838,661,634 |

Those three families account for 73.14% of the ledger's padded native main.
The ledger excludes interactions, table providers, B8 halt auxiliaries, V3
direct-clock limbs, LDE, tree storage and recursion. Its compatibility
interaction column is not the current B8 physical profile. Aggregate cell
work is also not peak resident memory. New wide-shard consolidation changes
padding; it does not make these old shard counts a current benchmark.

There are 298,427,187 register accesses and 57,876,727 RAM accesses in the
retained census. **Register traffic has already been removed from global RAM
proving.** That gain must not be claimed again. The remaining register value
and clock representation is local to native/caller relations. A replacement
that introduces a new 298M-row sorted register table could erase its savings.

## The caller cost is now precisely attributable

The saved real 890-Keccak, 131,072-cycle mixed original is
`vectors/reports/riscv-cpu-architecture-20261029/keccak-131072-mixed-wide-closed-originals-v1/artifacts/local-0.proof`.
Its 15 polynomial-tree widths, including composition, are:

```text
94, 515, 23, 1, 0, 101, 2317, 492, 44, 8, 4, 24, 4176, 324, 16
```

There are 8,139 physical columns and 21,439 OODS samples. Caller main 2,317
plus caller arithmetic interactions 4,176 is 6,493 columns, or 79.78%.
This is one caller-rich window, not a whole-block weighted average.

The source gives an exact decomposition:

| Caller inventory | Columns | Authority |
| --- | ---: | --- |
| Paired Keccak state | 1,600 | `keccakf_trace.Layout.state` |
| Theta parities | 320 | `keccakf_trace.Layout.parity` |
| Two state-I/O tuples | 218 | 2 × (call identity + 54 input + 54 output chunks) |
| Two in-use flags | 2 | Paired call activity |
| Embedded caller metadata | 64 | Register/pointer/clock/span plus 50 previous RAM clocks |
| **Keccak arithmetic main** | **2,204** | Sum above |
| Per-access halt auxiliaries | 100 | 2 × 50 authenticated RAM descriptors |
| Chi/xor multiplicities and shared byte table | 13 | 1 + 1 + 11 |
| **Caller main total** | **2,317** | Exact saved width |
| Permutation interactions | 3,844 | (1,600 chi + 320 xor + 2 I/O events) / 2 × 4 |
| Embedded caller interactions | 320 | 160 events / 2 × 4 |
| Chi, xor and shared-byte provider interactions | 12 | 4 + 4 + 4 |
| **Arithmetic interaction total** | **4,176** | Exact saved width |
| Additional RAM projections | 200 | 50 × 4 |
| Additional program and CPU-state projections | 8 | 4 + 4 |
| Additional typed table projections | 116 | 29 × 4 |
| **Relation interaction total** | **324** | Exact saved width |

Sources are `air/guest_precompile/keccakf_{authority,trace,caller,interaction_plan,relations}.zig`,
`secp256k1_component_config.zig` (`ByteTable`), and
`prover/block_v8_endpoint_caller_plan_v1.zig`.
Each packed state cell represents two operations through `a + 8*b`.
There are 445 paired slots × 29 rows = 12,905 live rows, padded to log14.
The compact chi and xor tables have log13 and log10; shared byte log8.
Thus the following **raw cells** follow from the existing geometry:

| Inventory | Cells |
| --- | ---: |
| Caller main including halt/table columns | 37,760,768 |
| Caller arithmetic interactions including providers | 68,260,864 |
| Additional relation interactions | 5,308,416 |
| State/parity subset of main | 31,457,280 |
| Chi/xor subset of arithmetic interactions, excluding I/O | 62,914,560 |

Do not add the subset rows to the totals. These figures exclude fixed columns,
LDE and commitment storage. The additional 324 columns are authenticated
projections of the same arithmetic, not another companion proof. Their removal
alone saves only 3.98% of total physical width. It cannot explain a 10× gain.

The state mask is `{0,-2,-1,+1,+2,+27}` in
`air/guest_precompile/mask_layout.zig`: 1,600 state columns alone contribute
9,600 OODS scalars. Four secure limbs per interaction and previous/current
interaction reads add another large recursive input. This is why counting
base-proof files without their widths badly mispredicts reduction cost.

## Caller architecture: qualify the cost frontier, then share it

Existing throughput equations reduce a Keccak shard's interactions from 4,164
to 1,180, a 3.529× interaction-width reduction. They increase table universes
from 8,192/1,024 to 2,097,152/65,536. The source-derived table area is 25,952,256
cells instead of 110,592. The saved actual proof would still have 5,155 total
columns after replacing only this interaction width: a 36.66% width reduction,
not 3.529× whole-proof or whole-root acceleration.

The already-written isolated tiled kernel is documented in
[the exact tiled problem match](keccak-tiled-problem-match-20261029.md).
Its one-paired-lane candidate has 154 main, 56 fixed and 156 **modeled**
interaction columns, with 1,024 padded rows for a paired slot. It models
3,953 OODS scalars versus 18,781 for the original shard, but 374,784 core cells
versus 204,768: 4.75× fewer OODS inputs at 1.83× core area. Its caller I/O
integration and actual original/recursive proof are still obligations.
The existing five-lane/full-table area model also explicitly counts detached
caller overhead and rejects an area-only speedup claim. Do not resurrect the
same rejected hypothesis under a new name.

The coherent next experiment is therefore a finite set of **fully closed**
profiles, selected over combined original-and-root work:

1. Current compact spatial profile as the immutable control.
2. Spatial throughput profile with one shared large-table authority across a
   bounded group. Every arithmetic/table physical sum remains transcript-bound.
3. Existing narrow compact kernel with independently stored call metadata and
   exact input/output-state links, then the same complete caller, RAM, ROM,
   lookup and halt obligations. Avoid repeating 64 metadata, 218 state-I/O and
   100 halt-auxiliary columns across a taller tiled domain merely to narrow the
   permutation component.

Each profile must report original raw/LDE cells, actual maximum degree and
padding, fixed universes, multiplicity work, original proof time, recursive
sample and Merkle work, and complete root time. A 1.83× original-area penalty
can still be worthwhile if recursive verification dominates, but that requires
the complete measurement. No existing width model establishes a 10× result.

Shared table proof work needs a shared challenge schedule: all source main
roots and the provider roots committed before the draw, or an explicit new
same-root late table-bridge proof. Independent old local lookup fractions
cannot be added under different challenges. Caching immutable fixed columns
does not eliminate input-dependent multiplicities. Keep counts below M31's
modulus and include every source; no host-computed total is proof authority.

HALT remains an access-level property. A call may write one then clear it, so
checking only final endpoints is insufficient. Separating the caller metadata
must preserve the current authenticated current/+27 state masks, all 50 RAM
accesses and the nonterminal caller halt rule. A proposal to replace 100 halt
auxiliaries with a span test needs an actual constrained selection of the
potential halt word; simply forbidding all overlapping calls changes valid
execution semantics.

## Native architecture: canonical two-halfword ports

Current physical layouts repeat values in a universal operation row:

- Register ALU uses 35 columns: clock/PC; RD address, previous bytes/clock and
  next bytes; two source address/value/clock records; five opcode flags; four
  result bytes; RD-nonzero and inverse hints.
- Immediate ALU uses 35 columns, including four repeated source-after bytes
  despite a read-only source. It also stores three immediate limbs/sign cells,
  four operation flags and four result bytes.
- Load/store uses 50 columns: three access records, operation flags/selectors,
  offset markers, byte result and signedness auxiliaries, immediate, aligned
  address decomposition, and x0 hints. V3 adds three RAM-gap limbs and B8 adds
  two halt hints per load/store row; those five are not silently removed here.

Use `Word32 = {lo16,hi16}`, never one M31 felt for an arbitrary u32. Keep
register and RAM relation domains distinct, each with a four-coordinate tuple
`{address, clock, lo16, hi16}` instead of seven coordinates containing space
plus four bytes. Carry the existing per-access clocks; source and destination
aliasing and three subclocks remain explicit. Byte-oriented callers/bitwise
tables derive halfwords algebraically from authenticated bytes. This avoids a
new global register memory argument.

Range authority transfers along the exact typed value graph: initial register
and RAM boundary producers, every instruction write, every caller write, and
x0. Reads reuse a proved bound; they do not invent it. Register input bytes
already have an inductive invariant today, so removing read checks must not be
counted as a new saving. New halfword-producing arithmetic needs its own
range provider. A free witness declared `Word32` is not a range proof.

### Operation-specific main-column budget

The following is a proposed representation budget, not implemented AIR.
It keeps actual RD-after fields separate from computed results where needed
to keep relation ports affine and avoid increasing the LogUp degree through
x0 gating. All table, interaction and padding costs must be measured next.

| Operation class | Retained rows | Old main width | Proposed main width |
| --- | ---: | ---: | ---: |
| ADD/SUB | 8,000,656 | 35 | 20 |
| XOR/OR/AND | 11,280,102 | 35 | 25 |
| ADDI | 27,639,406 | 35 | 17 |
| ANDI/XORI/ORI | 1,756,637 | 35 | 22 |
| LW | 19,835,752 | 50 | 20 |
| SW | 16,696,290 | 50 | 16 |
| LB/LBU | 11,275,540 | 50 | 26 |
| LH/LHU | 433,139 | 50 | 24 |
| SB | 7,985,739 | 50 | 23 |
| SH | 5,241 | 50 | 19 |

ADD/SUB keep two halfwords for each value port and use derived carry/borrow
constraints. ADDI needs a **new ROM schema** admitting the signed immediate
as a canonical field constant; the current immediate-ALU ROM uses u12, so it
cannot silently be reinterpreted. Ternary carry constraints can have degree3,
and with a fixed active selector degree4; quotient2 qualification still needs
an independent compiler degree audit. Logic retains the byte views needed by
the fixed bitwise table, with algebraic halfword assembly. It does not assume
32-bit bitwise behavior follows from an unchecked field operation.

The load/store split has constant width/opcode semantics per component. SW
aliases the after-word to the authenticated source register; LW derives its
result from the RAM read. Partial stores keep two explicit after halfwords
and prove exact byte replacement, preserving all unchanged bytes. Partial
loads keep selected byte/halfword views, sign bit, offset bits and fixed
signed/unsigned opcode binding. Do not discard the source high bytes merely
because an SB result uses one byte: the register relation still carries the
whole canonical word.

Represent the aligned byte address by two 14-bit quarter-address limbs.
`byte_address = 4*qlo + 2^16*qhi + offset`. The low quarter requires **both**
R16(qlo) and R16(4*qlo); scaling alone admits the field alias qlo=4^-1.
The high quarter is independently bounded by its equality to a canonical
base high16 plus a ternary carry before scaled R16(4*qhi) membership. This
enforces the platform's aligned
address bound without a modulo-M31 u32 alias. Address addition needs integer
carry constraints and signed immediate treatment, not a single field equality.
Initial RW permission, native/caller halt rules and terminal policy remain
part of the source and global admission.

### Source-derived main work projection

Applying those widths to the actual instruction counts gives:

| Main-only unpadded inventory | Existing | Proposed |
| --- | ---: | ---: |
| Load/store | 2,811,585,050 | 1,151,186,632 |
| Register ALU | 674,826,530 | 442,015,670 |
| Immediate ALU | 1,028,861,505 | 508,515,916 |
| Three-family total | 4,515,273,085 | 2,101,718,218 |
| All families, holding all others unchanged | 5,838,661,634 | 3,425,106,767 |

This projects 53.45% less main work in these families and 41.34% less in the
whole native main inventory, before new providers. It is **1.70× main-area**,
not 1.70× end-to-end. The unchanged five V3/halt columns per load/store add
281,158,505 cells to both sides and lower that ratio further. New R16/table
requests, carry equations, component count, fixed tables and padding may
reduce the gain. Existing halfword/global endpoint tuples permit a migration
bridge, but changing local tuple schemas still changes interaction challenges
and every relevant key.

The source-only namespace's corrected exact LS request census is four R16
requests for LW/SW/LBU/LHU/SB/SH and five for signed LB/LH, plus the byte-pair
requests for partial views. The unscaled qlo check adds 56,231,701 R16 requests
over this retained execution compared with a scaled-only draft. The main-cell
projection above is unchanged; its provider/interaction cost must be charged.
The dormant hostile test uses qlo=4^-1, base=1 and immediate/offset=0: all direct
polynomials can hold while the purported aligned LW address is 1, and the new
unscaled lookup rejects it. A fresh global RAM alignment check must not be used
to excuse a locally false integer-bound claim.

Do not rely on zero x0 writes or equal-source operands in the retained corpus:
the new AIR must handle the entire admitted ISA. All producer classes, padding
and inactive rows must satisfy the same canonical value invariant. A future
SSA/basic-block optimization could remove additional repeated register ports,
but a dense 32-register checkpoint per small block or an unproved host-chosen
template is not an acceptable shortcut. It needs its own full live-in/out,
control-flow, program-membership and memory ordering proof and cost ledger.

## Migration and qualification

### Source-only physical lowering delivered for the dominant subset

`air/word16_v1/projection.zig` implements a finite explicit flat-cell layout
for ADD/SUB, ADDI, LW and SW. Its focused M31 local-algebra gate passes; it
remains inactive and unqualified for any complete original/recursive proof. It
did not change the full-block proof. The columns are actual explicit
arrays in the new source, not a count of semantic struct fields:

| Profile | Committed main | Additional fixed | Source-counted residual calls | R16 requests | Register/RAM fractions | Clock requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ADD/SUB | 20 | 3 | 29 | 2 | 6 / 0 | 3 |
| ADDI | 17 | 3 | 26 | 2 | 4 / 0 | 2 |
| LW | 22 | 3 | 61 | 4 | 4 / 2 | 3 |
| SW | 18 | 3 | 62 | 4 | 4 / 2 | 3 |

Every row additionally emits one ROM request and two CPU-state fractions.
The three fixed columns are independently derived `active_prefix`,
`domain_first` and `domain_last`; activation is not a main witness. Opcodes
are finite component identities, not an omitted runtime opcode-selector cost.
Residual counts include semantic padding and zero/alias equalities before DCE;
the local replay gate measured these exact counts. Declared degree4 still
needs an independent inferred compiler audit. The
future key authority must independently derive profile, row domain and active
count. The matrix writer's recorded count is not an admission receipt.

LW's committed memory address is replaced by `4*qlo + 65536*qhi`, and its
computed result aliases the authenticated RAM word. Zero offset bits, byte
views, sign and selected-value fields are derived zero. Its actual RD-after
halfwords remain committed, so x0 gating does not turn a linear register tuple
into a product expression. SW's memory-after halfwords alias the source
register, and its address and unused fields are derived similarly. All aliases
are affine or zero. The generic expander feeds the **same** arithmetic,
register/RAM, ROM, CPU/clock, range, x0 and HALT equations. Two HALT auxiliaries
are explicitly included in the LW/SW main counts; the original 20/16 core
budget did not include them.

The new matrix writer allocates only `main_columns * padded_rows` M31 cells in
final column-major storage, with fixed capacity and byte bounds. It never
retains a semantic-width trace and then copies it into compact storage. Its
seal operation initializes all padding and prohibits later appends. This is
source implementation of witness lowering, not a PCS proof or performance
measurement.

The same subset has 72,172,104 rows in the retained full execution. Holding
padding aside, its main work including the same two HALT auxiliaries on both
old and new LW/SW is 3,147,068,354 cells versus 1,366,802,786. New fixed fields
add another 216,516,312 unpadded cells. There is no comparison against old fixed
work because the retained main-only ledger does not supply that inventory.
Interaction/prover/provider work is **additional**.

For transparency, pairing at most two fractions within each independently
closed domain would model 32 source interaction base columns for ADD/SUB, 24
for ADDI, and 36 for LW/SW. This recipe is not generated or qualified. It would
already add 2,234,520,248 unpadded interaction cells over this subset, before
positive range/clock/ROM/register/RAM providers, padding and LDE. Clock-order
requests remain explicit OPEN obligations: the compact arrays do not secretly
implement or omit a clock-gap proof. Any extra clock witness or range-provider
cells must be charged to the complete profile. Thus neither the main ratio nor
these narrower arrays establish an end-to-end speedup.

The local lowering tests compare every residual, declared degree and ordered
event against semantic replay for all five profiles. Host packers reject
inconsistent dropped fields only as hygiene. Separate tests bypass packers and
mutate committed cells: x0 and transient HALT violations reach polynomial
residuals; qlo=4^-1 reaches the required unscaled R16 membership. They ran only
after the full-block campaign stopped: the focused ReleaseSafe gate passed all
16 tests, including per-slot inactive mutations, operand aliases, LW-to-x0 and
exact terminal-cycle guards. No production namespace imports
the new lowering.

Use a new explicit encoding/profile namespace and ROM/tuple versions. Bind
profile, table recipe, range-transfer graph, exact component geometry and all
first roots before challenge draws. Keep old proof codecs and independently
derived keys readable under their old versions. New witness bytes and old
fixed/verification keys are never interchangeable. No old frozen bundle should
be regenerated in place.

Qualification should be a large, coherent vertical slice: one canonical native
word16 group, one real caller-rich mixed group using the selected Keccak
profile, exact endpoint late bridge and compact global closure, then one
independently verified recursive root from serialized artifacts. Include both
initial and terminal boundary cases. Preserve q70/26 and actual degree audits.
Tests need malformed range/carry values, x0, equal operand aliases, signed
immediates, address wrap, partial write preservation, current/+27 caller mask
tampering, odd trailing Keccak calls, incorrect lookup multiplicity, opposite
physical-claim changes, transient halt writes and changed snapshot permissions.

The external encodings research provides a useful proof discipline, not a
drop-in product speedup. The local `mission-ideas/ideas/stwo-encodings` asks
for full committed-cell accounting; the proximity challenge's
`research/encodings/NOTES.md` demonstrates producer-bound range transfer only
for a fully closed positive typed graph with bounded multiplicities. Its
batch4 example saves cells but runs slower, and its MUL/MULH/DIV improvements
affect a small fraction of this retained execution. Keep original proof time,
recursive work, memory, and exact soundness obligations together when choosing
the next architecture.
