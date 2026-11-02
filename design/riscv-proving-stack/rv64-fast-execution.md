# RV64 fast first pass and parallel segment capture (track C1)

Status: implemented on `codex/rv64-ge-fastexec`, prover-side only (no AIR,
statement, wire or identity change). Receipt:
[fast-execution-v1.json](../../vectors/reports/rv64-ethereum-20261102/fast-execution-v1.json).
Plan context: `rv64-gpu-2s-block-plan.md` §3 stages 1–2, §9 C1, critic note K6.1;
baseline: `rv64-minimal-trace-design.md`, `capture-parallel-v1.json`.

## 1. Where execution time went (before)

`/usr/bin/sample` of `rv64-ethereum-execution` (reference interpreter), block
24,628,607, 34.1 M instructions, 1.24 s (27.5 MHz):

| Bucket | Share |
| --- | ---: |
| `run` loop body: report/census bookkeeping on the 150 B `Retirement` row, inlined `retire` | ~48% |
| `Session.step` (fetch, decode-cache probe, permission check, effects) | ~37% |
| `Pages.lookup` (hash map behind a 4-entry cache) | ~5% |
| `Mappings.check` | ~5% |

Once dispatch was fast, the next wall was in the **services**, not the
interpreter: secp256k1 `execute` and `arith256_mod` reduce with a generic
`u512 % m`, which LLVM lowers to a bit-serial shift-subtract loop. On the
largest basket block (26,235,159: 86 k secp ADD, 81 k DOUBLE, 174 k arith256
calls) that was ~34% of all samples after the engine change.

## 2. What changed

1. **`fast_execution.Engine`** (`src/frontends/riscv/rv64/fast_execution.zig`).
   - Every executable word is pre-decoded once into a 16-byte slot (op, rd,
     rs1, rs2, target, imm). AUIPC/JAL links and branch targets are
     precomputed; x0 writes go to a sink register.
   - Slots form straight-line blocks: a per-slot "instructions to block end"
     array means the step budget is checked once per block.
   - Dispatch is a labelled `switch` with `continue :sw` (threaded jumps).
   - Loads and stores go through direct read/write page-pointer tables in
     front of the reference `Pages`, filled lazily from the hash map. A page
     is admitted only if its rights cover the whole page.
   - Anything the engine cannot prove equal to `machine.Cpu.retire` stops
     *before* the instruction, with state untouched: ECALL/EBREAK, illegal
     words, misaligned or out-of-table accesses, absent pages, watched pages
     (the halt flag), stop pcs (the terminal pc), the step budget. The caller
     retires that one instruction with the reference session, so every trap
     and every service keeps reference semantics by construction.
   - Census counts (opcodes, loads/stores, pc profile) come from a per-slot
     difference array, so the execution tool's report is unchanged.
   - No JIT: the interpreter already meets the ≥ 250 MHz bar (§4), and a
     template compiler would add a second instruction semantics to keep equal.
2. **Exact fast service reductions.** secp256k1 folds with
   2^256 ≡ 2^32 + 977 (mod p) three times plus one conditional subtraction;
   arith256 uses Knuth algorithm D on 64-bit limbs. Both return the canonical
   residue and are differentially tested against the previous `u512 %`.
3. **Checkpoints** (`checkpoint.zig`). `Pages` gains an optional dirty-page
   observer on `store`/`storeWords`. The engine clears its write table at
   every checkpoint, so its first store to each page re-registers it as
   dirty, at no per-store cost. A checkpoint is the CPU, every service counter
   (call ids depend on them), and a persistent memory image: every allocated
   page as a shared, refcounted immutable copy. Only pages written since the
   previous checkpoint are copied again.
4. **Parallel segment walks** (`rv64_ethereum_segments.zig`).
   - A first-pass thread runs the guest to the end on the request's memory
     and publishes checkpoint k at every batch boundary. It is throttled to
     2·workers + 2 checkpoints ahead of the consumer.
   - Up to `workers` segment walks start from checkpoints. Each one is the
     unchanged serial `Walk.next` (tape, boundary capture, batch statement)
     on its own materialised image.
   - The consumer receives batches strictly in index order.
   - **Continuity is enforced**: each segment's end state must equal the next
     checkpoint, or the run fails with `EthereumSegmentContinuity`. The
     compared state is the CPU, the counters, the allocated page set, the
     *set* of written pages and the bytes of every written page.
   - A guest error stops the first pass silently. The segment that
     re-executes that batch hits the same error, and it surfaces in the same
     order as in the serial walk.
   - Wiring:
     - `nativeprepare --segment-workers=N`;
     - `plan-direct` / `produce-direct --segment-workers=N`;
     - default 0 is the serial walk.

## 3. Correctness evidence (completeness only)

Proof soundness does not depend on this code: the proof checks execution.
Equality with the reference is enforced by tests and receipts.

- `zig build test-riscv64-execution -Doptimize=ReleaseSafe`:
  - 1,500 random RV64IM programs, interleaving the engine with reference
    steps at random budgets. Programs cover all opcodes, in-range and
    misaligned branch/JAL/JALR targets, RW/RO/partial-rights/absent pages,
    and ECALL/EBREAK/random words. Registers, pc, clock, trap, page set and
    bytes, and per-opcode counts all equal reference-only execution.
  - Watch, stop-pc and mid-block budget cases.
  - The dirty set covers every changed page.
  - All 18 admitted v3 service tags plus an unsupported tag, interleaved
    with fast stores, equal the reference session and run to the step limit.
  - Checkpoint continuity holds for more than 300 re-executed segments.
    Tampering is rejected: a flipped byte, a clock off by one, or a counter
    off by one.
  - The secp and arith reductions match `u512 %` on 200 k and 400 k cases.
- `zig build test-riscv64-capture-prefetch`: on the fixture, for batch sizes
  1/2/3/4/7, with and without `max_batches`, and 1/2/3/8 workers:
  - nativeprepare output trees are byte-identical to the serial walk;
  - direct capture with segments equals on-disk packet capture (natives and
    capture digest).
- Basket (`bench.py --engine fast`): every `execution.json` field except
  timing is identical on all 15 blocks, and G1–G6 pass.
- Real blocks: nativeprepare job trees are byte-identical serial vs 8
  segment workers, and plan-direct `captured_values_sha256` are equal (see
  receipt).

## 4. Measured

M5 Max, 18 cores, AC power, on a host shared with other agents. Raw numbers
are in the receipt.

**Execution** (`rv64-ethereum-execution`, `execution_ns`, single job, best of
3; ELF f625c083…, profile v3):

| Block | Instructions | Reference (before) | Reference + service fix | Fast engine |
| --- | ---: | ---: | ---: | ---: |
| 24,628,607 | 34.1 M | 1.241 s, 27.5 MHz | 34.6 MHz | **0.121 s, 281.9 MHz** |
| 26,235,159 (basket max) | 327.2 M | 11.48 s, 28.5 MHz | 35.9 MHz | **0.889 s, 368.2 MHz** |

Over the whole basket (4 parallel jobs) the fast engine averages 267 MHz,
range 218–342 MHz. 99.6% of retirements are fast. The rest are services,
first touches of absent pages and halt-flag stores.

**Direct capture** (`plan-direct`, captured_values_sha256 equal in every row;
ELF 6f2f8842…):

| Block | Mode | capture | walk share | RSS |
| --- | --- | ---: | ---: | ---: |
| 24,628,607 (26.9 M steps, 7 batches) | serial, inflight 8 | 2.09 s | 1.40 s | 5.1 GB |
| | segments 8, inflight 8 | **1.74 s** | 0.57 s | 8.2 GB |
| 24,628,608 (38.6 M steps, 10 batches) | serial, inflight 8 | 3.06 s | 2.24 s | 6.5 GB |
| | segments 8, inflight 8 | **1.94 s** | 0.63 s | 11.2 GB |

24,628,608 is the largest basket block that the Word16 expected image
accepts today. Blocks with adapted inputs above 4 MiB fail `FileTooBig` in
serial too (`expected_image.zig:24`, pre-existing).

How the capture breaks down:

- The first pass takes 0.10–0.15 s.
- The remaining walk share (~0.6 s) is one traced segment: the first batch
  cannot start before checkpoint 0, and traced capture runs at ~10 MHz.
- After that, the critical path is the per-batch admission/capture jobs plus
  the ordered ledger.
- Going from 8 to 16 workers changes nothing.

Checkpoint pages copied: 4,699 (24,628,607) and 6,941 (24,628,608), i.e. 19
and 28 MB in total.

**nativeprepare**: all 15 basket blocks are byte-identical serial vs 8
workers. Every output file has the same sha256: 8 completed collections, and
7 identical partial collections that stop on `StepLimit` (the template's
max_steps 1e8). Wall is unchanged (±2%) because the publisher is serial.

## 5. What is not done / next

- **The first pass is still a hosted interpreter.**
  - The engine is ~57% of the samples on the largest block; the rest is
    native services (Keccak-f, bulk memory through the `Memory` API, SHA-256).
  - Reaching 500 MHz+ needs the same treatment for bulk memory (direct page
    copies) before a JIT is worth its second semantics.
- **Traced segment rate.**
  - Each segment walk runs at the serial walk's ~10 MHz (tape, boundary
    capture and batch statement per step).
  - With ≥ (segments) workers the critical path is first pass + one segment
    + its capture.
  - The plan's ≥ 50 MHz traced target needs the compact per-step record
    format (C2), not this change.
- **nativeprepare wall barely moves.** It is bound by the serial publisher:
  frontier graph, fsynced packets, sparse-cache root chaining. The direct path
  is the one that benefits.
- **Memory.** Segments trade RSS for latency: +3–5 GB at 8 workers, from the
  in-flight tapes and images.
- **Large inputs.** The 4 MiB expected-image input cap still blocks direct
  capture of 7 basket blocks. That is independent of this change.
- **K6.1 (cross-segment RAM).** Segments here re-run the unchanged serial
  capture, which keeps first/last RAM cells per batch (batch-local RAM), so
  no global prev-timestamps are needed. A global-memory design would carry
  last-access clocks in the checkpoint.
