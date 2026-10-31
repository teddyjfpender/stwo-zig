# Arithmetization and memory program (branch `codex/rv64-arith-memory`)

Started 2026-10-31 from `a06c0992f`; reconciled with qualified merge
`caeb185e1` on resumption. Current status: implementation and qualification
in progress; the coordinator did not exist when this plan was first written.
The requested 3–5x arithmetization and 1.5–2x memory improvements are measured
acceptance targets, not achieved results. Goal: take the RV64 Ethereum batch
from 533 main+interaction cells per retirement on a 4n quotient domain to
at most 150 cells per retirement on 2n (3.5x on cells, about 7x on
composition work), and replace the Poseidon2 RAM tree (about 107 RAM cells
per retirement at batch 0, plus the RAM witness and the serial root chain)
with the LogUp memory relation (under 10 RAM cells per retirement, batches
provable in any order). Legacy baseline observations concern batch 0 of block24,628,607
(4,194,303 retirements, `run7`). Proposed widths, shares and speedups below
are hypotheses until the new coordinator produces proof/receiver receipts.

## 1. Baseline (legacy lane, batch 0)

| Quantity | Value |
| --- | ---: |
| CPU main / interaction columns | 385 / 148, quotient on 4n, degree 4 |
| Main / interaction columns per batch, all components | 1188 / 620 |
| Of which private RAM providers | 712 / 308 |
| Cells per retirement, main + interaction (all components) | 533 |
| Prove, M5 Max, 16 workers | 16 to 22 s |

Round-5 census (104,253,913 retirements): ALU 27.6%, load/store 32.1%,
binary 13.0%, shift 12.2%, branch 8.9%, dynamic jump 2.2%, static result
2.4%, MUL/DIV 1.6%, service 0.05%, fence 0.002%.

## 2. Thin lane as inherited

CPU `alu_binary_v2`: 3 fixed, 46 main, 56 interaction, degree 3 on 2n;
relations REG (6-tuple, three slots), FUNCTION (13), ROM (23), U16, U8, each
with its own inverse and prefix columns. Chips: ALU 52/52, BINARY 42/28,
SHIFT packed 53/48 (not routed), U16 1/8, AND table 1/8. ALU/BINARY including branches classify49.5% of guest retirements;
61.7% additionally includes SHIFT, which is not yet routed. This is opcode
classification coverage, not an accepted partial Ethereum proof. measured 224.6 cells per retirement on a 3-opcode loop. Not
covered: loads/stores, JAL/JALR/LUI/AUIPC, MUL/DIV, services, RAM, fixed
geometry, the Ethereum driver.

## 3. Design decisions that set the budget

1. **One LogUp accumulator per component.** All of a row's fractions,
   whatever their relation, are pair-batched into one prefix: the CPU's 11
   fractions (3 REG products, FUNCTION, ROM, 6 range) become 6 inverses and
   one prefix, 28 interaction columns instead of 56. Soundness is the
   standard single-sum argument: distinct relation challenges make cross
   cancellation negligible; every component's claim is one QM31 and the
   receiver sums all claims with the tables' to zero.
2. **ROM carries static results.** LUI, AUIPC, JAL's link value and every
   static next pc are functions of the instruction word and pc, so the
   immutable ROM row supplies them as tuple coordinates; the CPU binds
   `C = rom.result` on static-result rows. No CONTROL chip. JALR is one ALU
   operation `jalr_target(A, imm) = (A + imm) & ~1` whose result the CPU
   binds to `next_pc`; its link value is static.
3. **Two buses from the CPU.** The FUNCTION bus (opcode, A, B, C) stays
   row-independent so exact-fact reuse keeps working for ALU, BINARY,
   SHIFT, MUL and DIV. A MEMORY bus (opcode, A, B, C, tick) carries
   load/store rows to the LS chip, which owns the RAM tuples. A row emits
   exactly one of the two; the ROM family flag selects which inverse column
   is active, so the degree stays 3.
4. **32-bit program counters.** Two u16 limbs per pc (the ELF lives below
   2^32; the ROM is the authority), 4 fewer main columns.
5. **Load/store chip owns memory.** One row per access: address limbs and
   carries, before/after value limbs, predecessor epoch/time and gaps,
   sub-word select, two RAM tuples (14 coordinates each) and the MEMORY bus
   consumption, with one accumulator. INIT and TEARDOWN per execution are the
   closed-RAM foundation's sorted tables. The Poseidon2 RAM tree, chunk,
   cell, leaf, node, side, permit components and the RAM witness go away.
6. **Fixed geometry per protocol version.** CPU 2^22; ALU 2^21, LS 2^21,
   BINARY 2^20, SHIFT 2^20, MUL 2^18, DIV 2^10, service providers at their
   existing logs; batches that exceed a capacity are split by the planner,
   never widened.

## 4. Budget per retirement (target, 2n)

| Component | main / interaction | share | cells per retirement |
| --- | ---: | ---: | ---: |
| CPU v3 | 42 / 28 | 1.00 | 70 |
| ALU (merged accumulator) | 52 / 28 | 0.37 | 30 |
| BINARY | 42 / 20 | 0.13 | 8 |
| SHIFT packed | 53 / 28 | 0.12 | 10 |
| LS v2 with RAM tuples | 80 / 60 | 0.32 | 45 |
| MUL, DIV adapters | existing providers | 0.016 | 3 |
| Services | existing providers | 0.0005 | 1 |
| INIT, TEARDOWN per execution | 23 / 48 at 2^22, over 25 batches | | 3 |
| Tables (U16, U8, AND, SHIFT16) | fixed | | 4 |
| **Total** | | | **174** |

The stretch to 150 comes from the ALU and LS interaction widths once the
accumulators are merged and measured, and from dropping the `enabled`
columns when the degree budget allows it.

## 5. Ownership (parallel, disjoint files)

| Workstream | Files | Deliverable and gate |
| --- | --- | --- |
| A: CPU row v3 | `air/word16_cpu/` new profile `full_v3`, `word16_v1/operations.zig` (JALR op), `word16_v1/alu*` (jalr op, merged accumulator) | Row proves every opcode family of the census through FUNCTION/MEMORY buses and ROM results; degree 3 on 2n; dense finite-difference degree test; adversarial list; cells table |
| B: LS chip v2 and global RAM | `air/memory/load_store_v2/` (new), `air/memory/closed_ram/` reuse, `rv64_load_store_v2*.zig` | LS chip consumes the MEMORY bus and emits RAM tuples; INIT/TEARDOWN from the expected image; batch-local closure first, then the cross-batch epoch relation; attack list |
| C: thin Ethereum coordinator and harness | `rv64_thin_ethereum_*.zig` (new), chip planner activation | Routes the real batch-0 capture into CPU v3 + chips, proves and freshly verifies, and prints coverage, cells per retirement, prove time per stage against the legacy baseline |
| D: delegations layout | `air/delegations/` reorganization, service buses into the thin row | After A lands |

Each workstream measures with the harness in C before claiming a number.

## Resumption engineering corrections

- A merged LogUp prefix does not permit pairing two already paired REG
  denominators at degree three. Count all affine fractions and selector
  degrees explicitly. CPU28, ALU28 and LS60 interaction budgets above are
  unqualified; preserve D3 rather than silently upgrading the quotient.
- Do not add a third diagnostic profile enum. Implement one concrete full
  execution protocol while keeping qualified historical controls unchanged.
- Preserve all64 address/value bits unless an explicit independently admitted
  program restriction proves narrower encoding safe. Four saved PC columns
  do not justify truncating JALR semantics.
- CPU-memory ownership must retain base, immediate, store data, load result,
  epoch and local tick. Distinct relation tags are not a substitute for
  authenticated request identity across shards.
- Range elision requires the joint strict REG/RAM chronology and canonical
  initialization/write induction, with adversarial proof tests.
- Reuse immutable setup, construct native witnesses once from compact tapes,
  and measure actual independently padded rows, tables and verifier work.
