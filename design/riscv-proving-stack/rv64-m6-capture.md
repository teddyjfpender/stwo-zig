# RV64 M6 capture: traced fast emulator and capture critical path

Stream `capture`, branch `codex/rv64-m6-capture` (from `95d40063d`). Producer scheduling only: no proof,
statement, transcript, identity or receiver byte changes. Gate: `captured_values_sha256` equal to the M5
digests on both dev blocks (607 `e5f5e760…`, 156 `c9f3d40f…`) and, end to end, proof hashes equal to the
M5 default receipts.

## 1. What was slow (M5 receipts)

Per traced step the M5 walk ran four re-validating layers (`Session.step` building a full `Retirement`,
`Tape.append`, `boundary_capture.Capture.append` with two `mappings.check` calls and a scattered hash probe,
`Batch.observe` re-decoding the pc through `ProgramAuthority.instructionAt`): ≈120 ns/step, 7.2–7.6 MIPS
per worker, against ≈7 ns/step for the untraced first pass. On 24628607 the traced walk was 3.3 of
3.7 CPU-s of walking and batch 0's walk (0.78 s) sat on the critical path.

## 2. The traced fast engine (`fast_execution.Engine.runTraced`)

The untraced first-pass engine already pre-decodes the program into slots, runs threaded dispatch over
straight-line blocks with direct page tables, and stops *before* any instruction whose effect could
differ from `machine.Cpu.retire` (ECALL/EBREAK, illegal words, misaligned or absent/odd-rights pages,
watched pages and pcs, the budget) so the reference session retires it. `runTraced` is the same loop
that additionally writes, per fast instruction:

| reference record | written directly |
|---|---|
| `Tape.append` → `compact_tape.Step` (next_pc, lhs, rhs, previous_rd, result, memory_index, flags) | same 48 bytes |
| `Tape.memory_before` (8-byte word before a load/store) | same word, capacity reserved per round |
| `Capture.append` → first/last word, terminal clock 4·(k+1), rights | `Capture.fastWord` |
| `Batch.observe` → register clocks 4k+1/+2/+3, division/multiplication requests | same counters |

**Why the bytes are identical.**
- *Values.* Every fast op computes the reference formula (shared `alu`, the same load sign/zero
  extension and store merge); lhs/rhs/previous_rd use the slot's operand registers, which `lower` sets
  from the same `isa.effects` the reference uses (unread operand → x0 → 0; non-writing op → sink → 0,
  with the sink register kept at 0). JAL/JALR record `taken = 1` and the link as result, as `retire`.
- *Admission.* The traced program is a copy of the first-pass program restricted (`Engine.restrict`)
  to pcs where `ProgramAuthority.instructionAt` returns the very raw word and decoded instruction the
  engine lowered (`Native.admitsFast`); every other pc is a slow slot, so `Batch.observe`'s ROM check
  and its error happen on the reference path at the reference step.
- *Boundary rights.* A page is traced-fast only when every 8-byte word has the same
  `mappings.check(read)`/`check(write)` outcome (`captureMask`); stores additionally need mask 3.
- *Refusals.* A capture discontinuity, the cell budget or any allocation failure makes `fastWord`
  return false with the capture unchanged, and the engine stops before that instruction; the
  reference `captureNext` then retires it and reports exactly the reference error.
- *Stops.* The terminal pc is a stop pc, so completion is checked after exactly the step that reached
  it; the tape capacity and `Session.max_retirements` bound the run, so `TapeFull`/`StepLimit` come
  from the reference step.
- *Continuity.* Fast stores mark the segment's dirty observer (`fill`), so the existing
  segment-vs-checkpoint continuity check (`checkpoint.matches`) sees every written page.

Differential tests: `fast_execution_test.zig` "traced fast engine: …" — 800 random RV64IM/Zbb programs
with traps, misaligned and partial-rights accesses, random run budgets and a random third with
authority-refused pcs: tape steps, memory_before, sorted boundary cells, register clocks, request counts,
CPU state, stop error and memory bytes equal the reference traced walk; plus a stale-cell test showing the
engine stops before the instruction. The existing serial-vs-segments parity tests in
`capture_prefetch_test.zig` now run the traced engine (default on) against the serial reference walk.

## 3. Boundary capture representation (`boundary_capture.CellMap`)

The cell set moved from `AutoHashMap(address, Cell)` (≈1M scattered entries per batch, a likely DRAM miss
per access) to page blocks: page index → 512-word block with a present bitmap, plus a last-page cache.
`sorted()` reads blocks in page order, so the address-sorted list needs no sort. Same contents, same
errors, same atomicity (an empty reserved block publishes nothing; OOM test unchanged).

## 4. Capture critical path (scheduling)

- **Async walk boot** (`direct.Started`): the walk's own request init (ELF/input pin, ROM authority,
  policy) and segment start run on a thread, overlapping the caller's expected image/program init
  instead of preceding it (`STWO_RV64_CAPTURE_ASYNC_START=0` restores the old order). Errors surface
  from `capture`; `deinit` always joins.
- **Critical first batch** (`cpu_source.critical_capture`): batch 0 gates the ordered ledger; its CPU
  capture now takes all its range helpers regardless of the shared FCFS budget
  (`STWO_RV64_CAPTURE_CRITICAL=0` off). Any helper count yields the same Source (M5 chunked capture).

- **Parallel boundary cells** (`collector.Ledger.boundaries`): first-touch cells sorted in 8 chunks + pairwise merges
  and terminal states looked up in parallel (unique addresses: same order as pdq). `STWO_RV64_CAPTURE_PARALLEL_BOUNDARIES=0` off.

## 5. Flags (all scheduling only)

`STWO_RV64_TRACED_ENGINE=0` (M5 reference loop), `STWO_RV64_CAPTURE_ASYNC_START=0`,
`STWO_RV64_CAPTURE_CRITICAL=0`, `STWO_RV64_CAPTURE_PARALLEL_BOUNDARIES=0`. Defaults: on. `STWO_RV64_TAPE_POPULATE=1`: opt-in, measured net loss.

Measurements: `vectors/reports/rv64-m6-20261105/capture/`.
