# Thin Word16 CPU on a 2n quotient domain

Status: working implementation proposal for `cpu_word16_v1`. Supersedes the
byte-and-bit CPU row (`limbs24_v2` control, `cyclic_canonical_v3` state,
`division_multiplication_services_v3` arithmetic) for Ethereum proving. The
qualified BINARY chip in `src/frontends/riscv/rv64/air/word16_v1/` and the
cost model in `rv64-family-providers.md` are the inputs; the schema and budgets below require the reconciliation ledger before they
are a complete implementation contract.

## Reconciliation ledger before production implementation

The qualified register-only prototype has 44 main / 56 interaction CPU columns;
the ALU/branch diagnostic extends that foundation. Neither is the full protocol
below. The proposed 66/56 count and 271-cell total are budgets, not qualified
layouts. Resolve these obligations against real code and degree tests:

- Define the immutable ROM tuple explicitly. Dynamic `next_pc` and service
  counters are not instruction-derived ROM fields. PC, opcode, register indices,
  feature flags, immediate and static-next fields are; the claimed 31-coordinate
  ROM tuple must not indiscriminately copy the control frame.
- Bind store data. The proposed 24-coordinate bus contains A, R and C but no B,
  although section 2.5 names B as a STORE input. Options include C carrying
  store data with an authenticated store flag and C=B constraint, or LOAD/STORE
  deriving its immediate through a PC-authenticated ROM lookup while R carries
  store data. Charge all required staging/lookup columns and preserve affine
  paired REG denominators. Never leave store data as unbound chip advice.
- Specify each family's unused bus coordinates. Gating a PC/time coordinate by
  a committed family flag makes it quadratic, not affine. A single inverse
  times that denominator has degree three; pair batching it may exceed three.
- Re-derive the REG interaction authority. Legacy 3/3/2 grouping covers eight
  events with degree four; it cannot be called a retained degree-three scheme.
  Six local REG events can use a newly qualified 2/2/2 cyclic scheme, while the
  current thin proof uses three strict inverse pairs plus one prefix (16 base
  columns). Charge the chosen construction explicitly.
- Account for all 16 proposed range requests: four C limbs, six clock u16 limbs,
  and six clock u8 limbs, before spare/service work. The existing text counts
  only three u8 limbs. Prefix storage must be counted alongside any separate
  inverses. Alternatively qualify canonical predecessor clocks through the
  closed state argument and omit redundant range work explicitly.
- Current services have three call families (Keccak, ADD, DOUBLE), not two.
  A separately sized service-argument component can keep counters and extra
  ABI register reads out of every CPU row, but its REG, call and owner-row
  relations must close. Two unspecified counters are not sufficient authority.
- Partition every admitted opcode, including MUL/DIV, fences and static jumps.
  Existing MUL/DIV internal buses may remain behind adapters, but the CPU's
  single outgoing bus obligation must still close exactly once where enabled.
- Reuse provider-proved canonical outputs and static ROM-derived targets when
  that removes redundant CPU work. The qualified 44-column prototype is the
  starting evidence; adding fields to meet a hand budget is not a requirement.

Fixed-log accounting also needs reconciliation. With one instance per CPU
batch at the stated logs, ALU/LOADSTORE shares are exactly 0.5 and
BINARY/SHIFT/CONTROL shares exactly 0.25, not the varying shares in section 6.
Using its draft widths gives **296.5**, not 271, cells per CPU row including the
seven-cell allowance. The qualified ALU is 60 main + 52 interaction rather than
40 + 32: substituting it gives **316.5** before other corrections. These are
arithmetic checks, not a new performance forecast.

Confining padding to one partial instance per chip across the entire execution
requires global chip packing and exact ownership/coverage. It does not follow
from one full fixed roster inside every CPU batch. Resolve this against the
aggregation document's single batch-shape requirement: either charge every
padding instance or qualify separate fixed-key chip proofs and their aggregate
obligations. Do not choose request-specific keys or silently omit providers to
make the cost table fit.

The production protocol must have one concrete schema and one physical roster.
Keep intermediate diagnostics out of its hot path; retire superseded production
profiles only after full-ISA, RAM, fresh-receiver and semantic-parity gates pass.

## 1. Principles

1. The CPU row proves control flow, register consistency and operand
   selection, and emits exactly one typed bus request per active row. It
   computes no arithmetic.
2. Every 64-bit value is four little-endian u16 limbs. Canonicality of a limb
   is a range16 lookup, never a Boolean decomposition.
3. Every constraint has degree <= 3 after multiplication by its selector, so
   the composition is evaluated on 2n points (`EXPANSION = 1`). LogUp batches
   hold two fractions.
4. Opcode selectors are not committed. The ROM lookup authenticates a compact
   feature set per instruction; constraints use features, never 65 one-hots.
5. Each family chip has a fixed log size per protocol version. Request counts
   choose how many instances, never how many columns.

## 2. CPU row schema

All columns are M31 unless marked Q (QM31 = four M31 columns). `n = 2^22`.

### 2.1 Control frame, ROM-authenticated (31 main)

| Name | Width | Meaning | Constraint |
| --- | ---: | --- | --- |
| active | 1 | 1 on retirement rows | Boolean; prefix-closed (active rows first), first/last bound to public steps |
| pc | 3 | 24/24/16 limbs | ROM tuple coordinate; next_pc adjacency |
| next_pc | 3 | 24/24/16 limbs | from CONTROL chip result or pc+4 (static ROM field) |
| opcode | 1 | global opcode id 0..64 | ROM coordinate |
| fam | 6 | one-hot family: alu, binary, shift, loadstore, control, service | Boolean, sum = active; ROM coordinates |
| eff | 5 | reads_rs1, reads_rs2, writes_rd, uses_imm, w32 | Boolean; ROM coordinates |
| rs1, rs2, rd | 3 | register indices | ROM coordinates |
| imm | 4 | u16 limbs of the sign-extended immediate | ROM coordinates |
| static_next | 3 | pc+4 limbs | ROM coordinate, used when fam.control = 0 |
| svc | 2 | Keccak/secp counters | existing service bus, unchanged |

The ROM provider (`air/program/`) gains these fields in its immutable table
and its tuple. Features are computed from the raw instruction at setup by
`program/setup.zig`; the receiver recomputes them from the expected ELF. This
removes 65 selector columns and 66 selector constraints from the CPU row and
adds 13 fixed columns to the ROM at its own height (2^20 for this guest).

### 2.2 Operands and result (20 main)

| Name | Width | Source |
| --- | ---: | --- |
| A | 4 | rs1 value (register state read) |
| B | 4 | rs2 value (register state read) |
| R | 4 | effective right operand: `R = (1 - uses_imm) * B + uses_imm * imm`, degree 2 |
| prev_rd | 4 | rd value before the write (register state BEFORE tuple) |
| C | 4 | result written to rd (register state AFTER tuple) |

`C` limbs carry range16 lookups on rows with writes_rd = 1 (the canonical
write anchor of `rv64-state-range-review.md`). `A`, `B` and `prev_rd` inherit
canonicality from the strictly ordered state argument and carry no lookups.

### 2.3 Register clocks (15 main)

Three slots (rs1 read, rs2 read, rd write). Per slot: `prev_lo` (u16),
`prev_hi` (u8), `gap_lo` (u16), `gap_hi` (u8), `carry` (Boolean). The AFTER
time is fixed geometry `tick = 4*row + slot + 1` as two limbs. Strict order:

    prev_lo + gap_lo + 1 = tick_lo + 65536 * carry
    prev_hi + gap_hi + carry = tick_hi

Both sides are below 2^17. Six u16 limbs go to range16, three u8 limbs to
BYTE. Local batch clocks remain 24-bit; the global memory argument adds an
epoch coordinate to RAM only (see `rv64-global-memory-argument.md`).

### 2.4 Interaction (56 base columns = 14 Q)

| Relation | Q columns | Content |
| --- | ---: | --- |
| state (registers) | 3 cyclic prefixes = 3 Q | existing cyclic 3/3/2 grouping of six signed events, retained |
| ROM | 2 Q | inverse + prefix of the 31-coordinate ROM tuple |
| typed bus | 2 Q | inverse + prefix of the single typed request (2.5) |
| range16 / BYTE | 6 Q | 4 C limbs + 6 clock limbs + 2 spare in pairs = 6 batches |
| service buses | 1 Q | existing Keccak/secp headers |

Draft CPU subtotal: 66 main + 56 interaction + 3 fixed, subject to the
reconciliation ledger above. Budget in
`rv64-family-providers.md` was 80/64; this schema is inside it.

### 2.5 The single typed bus request

One tuple shape for every family, unused coordinates are zero:

    (opcode, A[4], R[4], C[4], pc[3], static_next[3], next_pc[3], tick_lo, tick_hi)   24 coordinates

The CPU emits it once per active row with multiplicity `active`. Every
family chip emits the tuples it proves with multiplicity 1 per row. Denominator
`offset + sum(coef_i * x_i)` is linear in committed and fixed columns, so the
request residual `inverse * D - active` has degree 2 and the prefix update
degree 1. Family chips bind their own opcode sets: a chip row constrains
`opcode` to its family's range through the ROM-derived `fam` on the CPU side
and a one-hot opcode selector on the chip side (chips are narrow enough to
afford selectors). Unused coordinates on the CPU side are set from fixed
geometry or forced to zero by `fam` (degree 2).

Family-specific semantics of the coordinates:

| Family | Uses | C means |
| --- | --- | --- |
| alu | A, R, C, w32 via opcode | add/sub/slt/sltu/lui result |
| binary | A, R, C | and/or/xor result |
| shift | A, R, C | shifted result |
| loadstore | A (base), R (imm), B (store data), C (load result), tick | memory value; chip emits the RAM event |
| control | A, R (for branch compare), pc, static_next, next_pc, C (link register) | jal/jalr/branch/auipc |
| service | existing headers | unchanged |

The MUL/DIV providers keep their existing typed buses in this version to avoid
re-qualifying them; a later version folds them into the same tuple.

## 3. Family chips

Each chip is one independently sized component with its own fixed `log`,
proving the typed tuple plus its internal relations. Payload columns repeat
the bus coordinates the chip uses. All constraints degree <= 3.

### 3.1 ALU (main 40, interaction 32, log 21)

add/addw/sub/subw/addi/addiw/slt/sltu/slti/sltiu/lui. Limb adds with carries:
`A_i + R_i + c_{i-1} = C_i + 65536 c_i`, `c` Boolean; subtraction as add of
the two's complement computed by the chip (`~R + 1` per limb with borrow).
w32 ops constrain the low two limbs and sign-extend into the high two via a
Boolean sign and `C_2 = C_3 = 65535 * s`. slt/sltu produce a Boolean C_0 from
the final borrow and the operand sign bits; sign bits come from a BYTE lookup
of `limb_3 >> 8` on both operands (two requests). C limbs range16 (4 requests),
carries Boolean. Interaction: bus 2 Q + range16 pairs 4 Q + BYTE 2 Q = 8 Q.

### 3.2 BINARY (main 41 + multiplicity, interaction 28, log 20)

Already implemented and qualified in `word16_v1/binary.zig` on 2n with pair
batching: 13-coordinate payload, 3 selectors, 24 byte auxiliaries, 8 AND
requests closing against the fixed byte-AND provider (2^16). Change needed: the
payload becomes the 24-coordinate bus tuple with zero pc/time coordinates, and
or/xor derive from AND as today.

### 3.3 SHIFT (main 60, interaction 36, log 20)

sll/srl/sra and w variants. Amount `s = R_0 & 63` (w: & 31) split as
`s = 16 q + r`, q in 0..3 one-hot (4 Boolean), r in 0..15. Per input limb a
lookup into the shared SHIFT16 table keyed by (limb, r, dir) returning
(lo, hi), the two 16-bit halves of `limb << r` (left) or `(limb << 16) >> r`
(right): table size 2^21 rows, 2 value columns, shared across all SHIFT
instances. Output limb `C_i` is the sum of the two neighbouring halves selected
by `q` (degree 2 with the one-hot). sra fills the vacated limbs with
`65535 * sign` where sign comes from one BYTE lookup. w variants mask to two
limbs and sign-extend like ALU. Requests: 4 table lookups, 1 BYTE, 4 range16 on
C. Interaction: bus 2 Q + table 2 Q + range/byte 4 Q + prefix 1 Q = 9 Q.

### 3.4 LOAD/STORE (main 78, interaction 60, log 21)

Owns the RAM slot. Address `addr = A + imm` as four limbs with carries (degree
2), alignment by width from `addr_0 & (width-1) = 0` through a BYTE lookup of
`addr_0`'s low byte with a width-specific mask table (256 x 4 widths), permission
and page policy through the existing policy provider, old value `before[4]`,
new value `after[4]`, predecessor clock limbs and gap limbs exactly as the CPU
register clocks (five columns), and the RAM event tuple of
`rv64-global-memory-argument.md`:

    (space=1, addr[4], epoch, tick_lo, tick_hi, value[4], readable, writable)

emitted twice (BEFORE with predecessor time, AFTER with slot-3 time). Loads
select and sign-extend the addressed sub-word from `before` through a lookup
table keyed by (limb, byte offset, width, signed) returning the extended u16
limb pair (2^20 rows); stores merge `B` into `before` to produce `after` by
the same table family. Byte-level width handling is where the old CPU spent
64 memory-before bytes; here it is two lookups per access.
Interaction: bus 2 Q + RAM 2 pairs 4 Q + extension/merge lookups 2 Q + range16
on addr/after/C (12 limbs in pairs) 6 Q + policy 1 Q = 15 Q.

### 3.5 CONTROL (main 48, interaction 36, log 20)

beq/bne/blt/bge/bltu/bgeu/jal/jalr/auipc. Compare via limb subtraction with
borrows (A - R), equality via a per-limb inverse-or-zero gadget (degree 2),
signs via BYTE. Target `pc + imm` in the 24/24/16 PC coordinate system: the
chip splits imm into the PC grouping with an authenticated byte split (one
BYTE lookup on the boundary byte, as required by `rv64-family-providers.md`),
computes `taken ? target : static_next`, jalr clears bit 0 and uses `A + imm`.
Emits `next_pc` into the bus tuple; the CPU copies `next_pc` into the next
row's `pc` (adjacency constraint, degree 1). Link value `C = static_next`
widened to u16 limbs for jal/jalr. Interaction: bus 2 Q + BYTE/range 6 Q +
prefix 1 Q = 9 Q.

### 3.6 Shared tables

| Table | Rows | Owner | Notes |
| --- | ---: | --- | --- |
| range16 | 2^16 | `providers/` | new; replaces per-byte ranges for limbs |
| BYTE | 2^8 | existing | signs, alignment masks, boundary splits |
| byte-AND | 2^16 | existing | BINARY |
| SHIFT16 | 2^21 | new | (limb, r, dir) -> (lo, hi) |
| EXTEND | 2^20 | new | (limb, offset, width, signed) -> extended pair |

Tables commit one multiplicity column each; their values are preprocessed.

## 4. Degree and domain budget

| Constraint class | Degree | Notes |
| --- | ---: | --- |
| Boolean, limb carries, w32 sign fill | 2 | |
| effective-R selection | 2 | |
| typed request residual `inv * D - sel` | 2 | D linear |
| LogUp pair batch `prefix' - prefix) * D1 * D2 - (n1 D2 + n2 D1)` | 3 | numerators are selectors |
| cyclic state groups (3/3/2) | 3 | unchanged from v3, which already fits |
| SHIFT limb selection by q one-hot | 2 | |
| CONTROL equality gadget `d * inv = 1 - e`, `e * d = 0`, Boolean e | 2 | e=1 iff d=0 |

`MAX_DEGREE = 3`, `EXPANSION = 1`, quotient domain 2n, two coset parts in
`full/coset_evaluation.zig`. The Keccak and secp providers keep their 4n
domains until re-batched; mixed domains per component are already supported
(each component owns its `compositionLogSplit`).

## 5. Witness and interaction generation

- Capture is unchanged: the compact 48-byte tape per retirement. The row
  filler writes CPU columns and appends a request record to the per-family
  list `(row, opcode, A, R, C, pc, next_pc, tick)` in one pass.
- Family chips are filled from their request lists by the existing planner
  (`rv64_ethereum_chip_plan.zig`) extended with `alu`, `binary`, `shift`,
  `loadstore`, `control`; capacities are fixed per protocol version:
  ALU 2^21, LOAD/STORE 2^21, BINARY 2^20, SHIFT 2^20, CONTROL 2^20 per
  2^22-step batch, from the measured shares (ALU 28.6%, load/store 30.7%,
  bitwise 16.4%, shift 10.3%, control 11.4%). A batch whose family count
  exceeds capacity is split by the planner, never widened.
- Interactions: existing prepared-row generation in `range/cpu.zig` and
  `providers/table_component.zig`, generic over the lane type (SIMD lanes for
  domain, QM31 at OODS). Pair batching replaces triple batching in
  `providers/tables.zig` and `range/cpu.zig`.

## 6. Cost model

Per original CPU row, family rows charged at their padded shares:

| Component | main | interaction | share | cells per CPU row |
| --- | ---: | ---: | ---: | ---: |
| CPU | 66 | 56 | 1.00 | 122 |
| ALU | 40 | 32 | 0.48 | 34.6 |
| LOAD/STORE | 78 | 60 | 0.48 | 66.2 |
| BINARY | 42 | 28 | 0.21 | 14.7 |
| SHIFT | 60 | 36 | 0.137 | 13.2 |
| CONTROL | 48 | 36 | 0.159 | 13.4 |
| tables, ROM growth | | | | 7 |
| **total** | | | | **271** |

Provisional comparison against 533: about 49 percent fewer cells. This
requires the corrected layout/lookup ledger and measured padding; it is not an
implemented reduction. CPU/family cells are intended to be evaluated on 2n
instead of 4n points for composition. Projected composition 0.25x, commit
preparation, FRI, decommit and interactions 0.5x.

## 7. Implementation plan

| Step | Files | Gate |
| --- | --- | --- |
| 1. ROM features | `air/program/setup.zig`, `compact.zig`, `packed_control.zig`, receiver derivation | receiver recomputes features from the expected ELF; mutation of any feature rejects |
| 2. range16 and SHIFT16/EXTEND tables | `air/providers/` | table membership attacks; multiplicity mass below M31 |
| 3. CPU row `cpu_word16_v1` | new `air/word16_v1/cpu.zig`, `cpu_layout.zig`, `cpu_witness.zig`; `full/component.zig` dispatches by protocol version | degree bound at random QM31 (dense finite differences, as `air/full/component.zig` test), register-state attacks from `rv64-state-range-review.md`, PC wrap and JALR low-bit attacks |
| 4. ALU, SHIFT, CONTROL, LOAD/STORE chips | `air/word16_v1/{alu,shift,control,loadstore}.zig` + `_component.zig` | per-opcode exhaustive edge tests (every width, sign, shift amount, overflow), fresh-receiver proofs of each chip standalone (as the BINARY qualification) |
| 5. Joined coordinator | `integrations/riscv_cpu/rv64_authenticated_execution.zig`, chip planner | all claims close; omitted/duplicate/wrong-family request attacks; two real 2^22 batches freshly verified |
| 6. Ethereum driver switch | `rv64_ethereum_request.zig` profile, build catalog | full block, fresh receiver, statement parity with the current chain, new fixture pins, CI target `test-riscv64-word16-cpu` |
| 7. Delete the byte CPU | `air/layout.zig`, `encoding.zig`, `*_constraints.zig`, policy enums | no `_v1..v4` runtime branches remain on the CPU path |

Owners can run steps 1, 2 and 4 in parallel; 3 depends on 1 and 2.

## 8. Risks and their resolutions

- **Degree overrun in CONTROL and LOAD/STORE.** Resolved by committing the
  intermediate (`R`, `taken`, borrow bits) instead of composing selections;
  the degree test at arbitrary QM31 points is a hard gate.
- **Register canonicality without per-read ranges.** Resolved by the closed
  strict-order state argument and canonical write anchors (`C` range16); the
  lemma and its counterexamples are in `rv64-state-range-review.md`.
- **PC coordinate crossing.** The CONTROL chip owns the 24/24/16 boundary
  split; no full-u64 field equality is ever used.
- **Clock cap.** Unchanged at 2^22 - 1 steps per batch in this version; the
  epoch coordinate of the global memory argument removes the cross-batch
  dependency, not the local cap.
- **Keccak and secp at 4n while CPU at 2n.** Supported by per-component
  split; re-batching those providers to pairs is a follow-up with its own
  cell comparison.
