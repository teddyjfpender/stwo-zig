# RV64 M9 lever #9: GPU capture replay from first-pass checkpoints (prep stream `m9-gpu-replay`)

Status: prototype + evidence, 2026-11-07; adversarial review the same day (§9: guards widened, op corpus added, numbers corrected). Branch `codex/rv64-m9-gpu-replay`, cut from `codex/rv64-m7-integrate` @ `786429aca`.
Flag `STWO_RV64_M9_GPU_REPLAY` (default off; nothing in the request path reads it yet).
Plan of record: `design/riscv-proving-stack/rv64-m9-plan.md` rev 3 (`origin/codex/rv64-m9-plan`), §4.1 row 9, §5 wave 3b.
Receipts: `vectors/reports/rv64-m9-prep/m9-gpu-replay/` (README there). Labels: [M] measured, [D] derived, [E] estimate.

## 0. Verdict

1. **GPU replay works and is exact.** A GPU RV64 interpreter replays every chunk of a segment independently from first-pass seeds. Its output is the compact tape (`compact_tape.Step`, 48 B per step), and it is **byte-identical to the CPU recorder** (`Walk.nextTaking`, the production traced walk):
   - 24628607: 7/7 segments (26.9 M steps) at chunk sizes 64, 256, 1024 and 4096. Segment 2 was also compared byte by byte (201 MB).
   - 26235159: 49/49 segments (204.8 M steps) [M].
   - The kernel implements the whole fast ISA (69 engine ops plus `slow`: RV64IM and the Zbb subset). **The two real blocks execute only 50 of the 69**; the other 19 (nop, slt, sra, sraw, sraiw, mulh, mulhsu, rem, divw, divuw, remw, remuw and all 7 Zbb ops) are covered by the synthetic op corpus against the reference interpreter (§9.2). Precompiles and traps stay host-retired steps.
2. **GPU throughput is not a constraint.** On one RTX 5090 [M]:
   - one 4.19 M-step segment replays in **0.46–0.48 ms (8.7–9.1 GIPS)** at chunk 64–256;
   - whole blocks: 3.7 ms for 24628607 (7.3 GIPS) and 37 ms for 26235159 (5.5 GIPS).
   - That is 46–83× the serial seeded first pass (whole block: 46× on 24628607, 71× on 26235159; one segment: 83× at 105 MIPS) [D].
   - The transport in is **4.3–4.7 B/step**, against 16 B/step for the existing MinimalRecord route and 48 B/step for the tape itself.
3. **The plan's factor is wrong in its basis but about right in its effect.**
   - The basis: "fast pass 168 MIPS [M]" holds for 2024 blocks only. Over the 15-block basket the serial first pass runs at **114 MIPS (plain) / 105 MIPS (seeded)** [M].
   - On 2026 curve-heavy blocks it runs at 58–82 MIPS: **26235168, the p50 block, is at 62.8 MIPS**, and 26235159 at 81.9.
   - Precompile services take **64% of first-pass time** (8.02 s of 12.47 s over the basket) [M]. The curve services alone take 4.86 s, at 11–54 µs per call, because they use `u768 %` and compute a modular inverse on every call (`candidate_curves.zig`). Ordinary instructions run at 320 MIPS.
   - The effect: in the plan model the lever's wall effect survives (p50 9.58 → 7.99 s, p95 15.66 → 13.75 s, cut 59%/58%) **only if the whole capture moves to the GPU** (full_now, §5). After the other cuts, pre-seal is bounded by Stage 1, not by the capture rate. The only block that pays is a curve-heavy p50-like one: 26235168 at 9.84 s instead of 9.49 s (+0.35 s). Fixing the service arithmetic recovers it (§5). The full_now variant also leaves out ~1.6 ms/segment of checkpoint capture and assumes recycled pre-faulted tape buffers (§9.4).
4. **What actually decides the factor is not the replay.**
   - The traced walk this prototype moves to the GPU is about 23% of per-step capture CPU [D]. The other ~77% stays on CPU workers: narrow capture (`Prepared`), local ledger, boundary capture and event prefault.
   - **Replay alone is worth about a quarter of the lever**: p50 9.58 → 9.19 s (9.14 s before charging the tape read-back, §9.3) instead of → 7.99 s, and the basket cut stays at 53% instead of 59% [E, §5].
   - The 8 points need **the narrow capture and the ledger on the GPU as well**. That is the main M9 3b work item (§7, step 5).
5. **The precompile boundary stays on the host.** Services are serial, write memory and are about 0.2% of steps (440 k service calls, plus 119 k ordinary traps/absent pages, in 559 k host steps of 204.8 M on 26235159: 0.27% all told) [M]. The first pass must execute them anyway. So they are retired by the reference session, recorded as finished host steps, and followed by a fresh seed. The GPU never models them.
   - Moving them to the GPU would put a launch or round trip on the serial path for every call (3.28 M service calls, 4.31 M host steps per basket pass [M]). Not worth it.
   - Making them fast on the CPU (Montgomery 6×64-bit limbs, constants precomputed once) is worth up to 4.8 s of serial time over the basket and 1.26 s on the p50 block [M/E].

## 1. The lever in the plan

- §4.1 row 9: `GPU capture replay (M10 → M9; _GPU_REPLAY)`, "fast pass 168 MIPS [M], replay 160 MIPS [E]". Its p50/p95 effect bites late: cumulative 9.6 → 8.0 s and 15.7 → 13.8 s.
- Model: `cap = head + Minstr / cap_mips + 0.2` with `cap_mips` (120, 160, 250) [E]. Without the lever: `cap = CAP_A + CAP_B·Minstr` (T1 fit: 1.51 s + 20.7 ms/Minstr) [D].
- Dependencies (§5, 3b):
  - GPU-native `Feed` must have landed;
  - T1 must be promoted (local ledger + inflight 16);
  - target: pre-seal ≤ 2 s at p50.

## 2. Design

```
first pass (1 CPU thread, serial; unchanged control flow)            GPU (per sealed segment)
  Engine.run  ──▶ runSeeded: same loop + per-block seed check           H2D seeds | mem tape | host steps (~18 MB)
                  + aligned before-word of every load/store             replay<<<chunks/128,128>>>: 1 thread per chunk
  Session.step (services, traps, absent pages) ──▶ host step + seed     scatter_slow: host steps into the tape
  checkpoint per segment (as today)                                     → compact tape (48 B/step), device resident
```

- **Seed** (280 B): the 32 registers and the pc, plus the segment-local step and memory-tape cursors, at the first block entry at least `chunk` steps after the previous seed. A seed is also taken after every host step, so a chunk never contains one. `check_next` marks a chunk that ends exactly where the next seed starts; the GPU checks its end registers, pc and memory cursor against that seed (continuity).
- **Memory tape**: the aligned 8-byte word *before* each load or store, in retirement order. This is exactly the CPU recorder's `Tape.memory_before`, so `memory_index` is the running count. The GPU never reads guest RAM: no page tables, no image upload, no store-to-load forwarding across chunks.
- **Host steps**: `Session.step` retires them as today; `appendRecord` turns them into the finished `Step` (and its memory word); a scatter kernel writes them.
- **ROM**: the first-pass engine's pre-decoded `Slot` table (16 B per code word), exported with a stable opcode number (`OP_NAMES`). The kernel uses the same `op/rd/rs1/rs2/target/imm` semantics as `Engine.runTraced`: SINK register, precomputed LUI/AUIPC/JAL values, slot-index branch targets.
- **Why not memory images per chunk**:
  - A per-chunk image would cost a dirty-page copy every few hundred steps.
  - A speculative replay over the segment-start image would need fix-up rounds, because prologue/epilogue stack traffic crosses chunk boundaries all the time.
  - The tape is 8 B per memory op (0.37 per step [M]) and makes every chunk independent.
- **Not done on the GPU in this prototype:**
  - register clocks (`Batch.register_clocks`) and mul/div counts (`Batch.observe`);
  - boundary capture (`Capture.fastWord`);
  - the narrow capture (`Prepared`: 56 B CPU metadata, ROM counts, ALU/BINARY/SHIFT facts with stable dedup, memory records);
  - local ledger phase 1.
  
  §7 gives the plan for each.

## 3. Files (all new except two build lines)

| file | what |
|---|---|
| `src/integrations/riscv_cpu/rv64_m9_gpu_replay.zig` | `runSeeded` (the `Engine.run` loop plus seeds and memory tape), `SegmentTape`, `Seed`/`SlowStep`/`GpuSlot` ABI, ROM export, `enabled()` for `STWO_RV64_M9_GPU_REPLAY` |
| `src/integrations/riscv_cpu/rv64_m9_gpu_replay_dump_main.zig` | `rv64-m9-gpu-replay-dump CONFIG OUT CHUNK REF_SEG [MAX_SEG]`: plain pass (timed, host steps by service), seeded pass (timed), CPU recorder per segment (parity of memory tape and host steps; SHA-256 of the reference tape), GPU inputs. Env: `STWO_RV64_M9_PREFAULT=1`, `STWO_RV64_M9_SKIP_REF=1`. `--op-corpus OUT`: the synthetic per-op corpus (§9.2) |
| `src/integrations/riscv_cpu/rv64_m9_gpu_replay_opcorpus.zig` | the op corpus: every fast op on edge/random operands, expected tape from `machine.Cpu.stepCached` (Zbb decode set) |
| `src/backends/cuda/native/rv64/m9_gpu_replay.cu` | `replay` kernel (1 thread per chunk), `scatter_slow`, `stwo_rv64_m9_gpu_replay_on(stream, job, ...)`; `-DM9_STANDALONE` harness: CUDA-event timing, SHA-256 per segment, byte comparison against `seg<k>.ref`, chunk-end census, `M9_INJECT=pc|mem|end|reg` fault injection |
| `scripts/rv64_m9/gpu_replay_bench.sh` | nvcc build under `build.3.lock`; run under `gpu.lock` with `timeout 300` |
| `scripts/rv64_m9/gpu_replay_model.py` | re-runs `plan_model.py` (rev 3) with the measured capture variants |
| `build_support/products/{riscv_cpu,catalog}.zig` | +1 line each: the `rv64-m9-gpu-replay-dump` tool |

Nothing under `rv64/jobs/`, `NAT/rv64/jobs/` or the gn-* streams is touched.

## 4. Measurements

All on pod `rv64-resident-2x5090` (shared; 1-minute load 15–26 during the runs). CPU numbers are single-thread. GPU numbers are CUDA-event medians of 10 iterations (5 for the whole of 26235159) on GPU 0 under `gpu.lock`; each hold was under 1 minute, and no process held GPU memory afterwards.

### 4.1 Parity [M]

| check | 24628607 | 26235159 |
|---|---|---|
| seeded first pass: memory tape == CPU recorder `memory_before` (all segments) | 7/7 at chunk 64/256/1024/4096, 16 runs, 0 mismatches | 49/49, 0 mismatches |
| host steps == CPU recorder steps at their positions | 72,936/72,936 | 559,074/559,074 |
| GPU compact tape SHA-256 == CPU recorder | 7/7 at all 4 chunk sizes | 49/49 (204.8 M steps) |
| GPU vs CPU byte comparison | segment 2: 201,326,544 B identical | — (SHA only) |
| review re-run (2026-11-07), widened guards: GPU SHA == CPU recorder, status 0 | 7/7, chunk 256 (same 7 digests) | not re-run |
| synthetic op corpus vs `machine.Cpu.stepCached` (§9.2) | 106,496 cases, all 69 GPU ops, byte-identical | |
| kernel status (slow slot, misalignment, pc range, continuity) | 0 | 0 |

### 4.2 GPU replay throughput [M] (RTX 5090, thread per chunk, 128 threads per block)

| input | chunk target | chunks | mean steps/chunk | kernel ms | GIPS | input B/step |
|---|---|---|---|---|---|---|
| 24628607 segment 2 (4.19 M) | 64 | 58,321 | 71.8 | 0.461 | 9.10 | 6.96 |
| 24628607 segment 2 | 256 | 18,797 | 222.9 | 0.481 | 8.72 | 4.32 |
| 24628607 segment 2 | 1024 | 7,521 | 557.1 | 1.448 | 2.90 | 3.57 |
| 24628607 segment 2 | 4096 | 4,892 | 856.4 | 4.488 | 0.94 | 3.39 |
| 24628607 all 7 (26.9 M) | 64 / 256 / 1024 / 4096 | — | — | 5.37 / 3.69 / 2.29 / 5.22 | 5.0 / 7.3 / 11.7 / 5.2 | 7.18 / 4.61 / 3.94 / 3.79 |
| 26235159 segment 20 | 256 | 16,857 | 248.7 | 0.465 | 9.02 | 4.29 |
| 26235159 all 49 (204.8 M) | 256 | 1,099,938 | 185.7 | 37.35 | 5.48 | 4.68 |

- Per segment, latency is bound by the thread count: fewer than 20 k chunks leave the 170 SMs short of warps. Chunk 256 is the right setting (seeds below 1/3 of input bytes; single-segment latency under 0.5 ms).
- At chunk 64 the whole-block rate drops because the thread-strided 280 B seed loads are uncoalesced. A warp-cooperative seed load would fix it if it ever mattered.
- The output is 48 B/step: 201 MB per segment and 9.8 GB for all of 26235159. In production the consumer must eat it per segment (§7).
- H2D is about 18 MB per segment, about 0.7 ms at the in-request 24.6 GB/s [D].

### 4.3 First pass, plain vs seeded [M] (`STWO_RV64_M9_PREFAULT=1` unless noted; chunk 256)

24628607, 2 reps per arm:

| arm | MIPS |
|---|---|
| plain | 176–181 |
| seeded, prefaulted, chunk 256 | 159–164 (−9%) |
| seeded, prefaulted, chunk 64 / 1024 / 4096 | 155–159 / 159–164 / 159 |
| seeded, **not** prefaulted | 105–133 |

Without prefault, first touch of fresh per-segment tape and seed buffers costs more than the recording itself. Production must recycle pre-faulted per-segment buffers: the large-block recycler, with a step-count size class.

Over the basket, 15 blocks, 1 rep (`first_pass_basket.json`):

| block | Minstr | plain s | plain MIPS | seeded s | seeded MIPS | host-step s | of which curve s | top host costs (ms) |
|---|---|---|---|---|---|---|---|---|
| 26235156 | 15.3 | 0.115 | 133.1 | 0.124 | 123.3 | 0.063 | 0 | secp 30, bulk 15, sponge 13 |
| 24647140 | 24.6 | 0.153 | 161.2 | 0.166 | 147.8 | 0.072 | 0 | secp 26, bulk 23 |
| 24628607 | 26.9 | 0.153 | 176.0 | 0.169 | 158.8 | 0.064 | 0 | bulk 22, secp 21, sponge 16 |
| 25229957 | 27.1 | 0.172 | 157.0 | 0.186 | 145.8 | 0.084 | 0 | secp 34, bulk 24 |
| 24628608 | 38.6 | 0.221 | 174.7 | 0.243 | 159.0 | 0.094 | 0 | secp 39, bulk 27 |
| 24626900 | 49.1 | 0.315 | 156.1 | 0.331 | 148.3 | 0.152 | 0 | secp 64, sponge 39 |
| 24697070 | 57.8 | 0.493 | 117.2 | 0.535 | 108.1 | 0.314 | 0.160 | bn254_fp2_mul 134, secp 76 |
| 24697073 | 60.4 | 0.889 | 67.9 | 0.939 | 64.3 | 0.702 | 0.521 | bls12_381_fp2_mul 360, arith384_mont 161 |
| **26235168 (p50)** | 113.4 | **1.806** | **62.8** | 1.948 | 58.2 | **1.468** | **1.261** | bn254_fp2_mul 660, bls12_381_fp2_mul 360, arith384_mont 162 |
| 25229955 | 122.5 | 1.082 | 113.1 | 1.163 | 105.3 | 0.712 | 0.488 | bn254_fp2_mul 268, bn254_g1_double 178 |
| 24628590 | 157.6 | 0.855 | 184.3 | 0.969 | 162.6 | 0.351 | 0 | secp 162, bulk 86 |
| 25229951 | 165.9 | 1.046 | 158.6 | 1.154 | 143.8 | 0.538 | 0.244 | bn254_fp2_mul 134, secp 126 |
| 24628595 | 172.8 | 1.110 | 155.7 | 1.255 | 137.7 | 0.555 | 0.145 | secp 199, bn254_fp2_mul 134 |
| 24628611 | 187.7 | 1.553 | 120.8 | 1.713 | 109.5 | 0.963 | 0.535 | bls12_381_fp2_mul 371, secp 195 |
| 26235159 | 204.8 | 2.502 | 81.9 | 2.646 | 77.4 | 1.885 | 1.507 | bls12_381_fp2_mul 722, arith384_mont 323, bn254_g1_double 266 |
| **basket** | 1,424.4 | 12.47 | 114 | 13.54 | 105 | 8.02 | 4.86 | |

Host-step cost per call over the basket [M]:

| service | calls | ms | µs/call |
|---|---|---|---|
| bls12_381_fp2_mul | 33,835 | 1,814 | 53.6 |
| bn254_fp2_mul | 133,776 | 1,463 | 10.9 |
| secp | 1,375,423 | 1,428 | 1.04 |
| arith384_mont | 36,515 | 810 | 22.2 |
| bulk | 1,016,715 | 790 | 0.78 |
| sponge | 273,562 | 664 | 2.43 |
| bn254_g1_double | 37,005 | 627 | 16.9 |
| bn254_g1_add | 10,752 | 148 | 13.7 |
| ordinary traps / absent pages | 1,030,593 | 126 | 0.12 |
| sha256 | 198,819 | 69 | 0.35 |
| keccak | 105,626 | 64 | 0.61 |
| arith256_mod | 54,328 | 16 | 0.30 |

The curve services do 384- and 768-bit arithmetic with `%` on `u768` (LLVM's generic wide division), and `mont384` recomputes `invMod(R mod m)` on every call (`src/frontends/riscv/rv64/ethereum_services/candidate_curves.zig:147-166`). A 6×64-bit-limb Montgomery implementation with precomputed constants should run each call in well under 1 µs [E]. That makes it the cheapest serial cut on the critical path.

### 4.4 The CPU work replay removes [M]

- CPU recorder (`Walk.nextTaking`, traced walk plus `batch.finish`), single thread:
  - 24628607: **40.3–44.4 ns/step**, 16 runs;
  - 26235159: 45.8 ns/step (finish is 11–13% of it).
- That matches T1's "53 ns/step for the traced replay walk" (contended).
- Per segment it is 0.17–0.19 s single-thread. On 26235159 it is 9.4 CPU-s per request, which leaves the CPU when the replay moves to the GPU.

## 5. Factor, corrected (`scripts/rv64_m9/gpu_replay_model.py` → `model.json`)

Four variants of row 9, applied after levers #1–#8 in the plan's order, central (pess/opt):

| variant | basis | p50 wall (cut) | p95 wall (cut) | 26235168 | basket (cut) |
|---|---|---|---|---|---|
| — after #1–#8 | plan | 9.58 | 15.66 | 11.16 | 144.8 |
| **plan** | `cap_mips` 160 [E] | 7.99 (59%) | 13.75 (58%) | 9.49 | 121.1 (59%) |
| **full_now**: replay + narrow capture + ledger on GPU, seeded first pass as measured | first pass per block [M]; fit 103 MIPS marginal for synthetic blocks [D] | 7.99 (59%; 53/65) | 13.75 (58%) | **9.84** (cap 2.55 s) | 121.8 (59%) |
| **full_fixed**: as full_now with the service arithmetic fixed | curve calls at 1 µs [E]; fit 169 MIPS marginal [D] | 7.99 (59%) | 13.75 (58%) | 9.49 (cap 1.36 s) | 121.2 (59%) |
| **replay_only**: this prototype; narrow capture and ledger stay on CPU workers | walk share of per-step capture CPU 0.23 (0.30/0.15) [D/E] | 9.14 (54%) | 14.81 (55%) | 10.62 | 138.0 (53%) |
| **replay_only_net** (review): replay_only, charging the CPU read-back of the 48 B/step GPU tape | walk share − 0.026 (0.039/0.013) [E, §9.3] | **9.19 (53%)** | **14.91 (55%)** | 10.68 | **138.8 (53%)** |

How to read it:

- In the model, pre-seal is `max(head + S1/(G·busy), cap + S1/seg/busy)`. After the cuts, the first term dominates once capture is below about 2.3 s at p50 and 3.5 s at p95. The capture *rate* therefore matters only when it pushes capture past the Stage-1 bound, which today's first pass does on 26235168.
- The 168 MIPS basis is wrong on the very blocks that matter (p50 62.8 MIPS). The 160 MIPS factor is roughly right only *after* the service fix (169 MIPS marginal).
- The walk share (0.23) is derived from per-step costs:
  - traced walk 41–46 ns [M];
  - narrow capture after T10 ≈ 85 ns: T1's 107 ns × T10's 235/296 tick ratio [D];
  - phase-1 ledger 26 ns, event prefault 14 ns, admission 16 ns (T1's summed job times / 204.8 M steps, contended) [D].
  
  It is the least certain input here. A pod run of `rv64-capture-bench` with only `STWO_RV64_TRACED_ENGINE` toggled would measure it directly. That is an M9 3b gate.
- **The 60% target still needs every lever.** The best 2-GPU set reaches a 58% minimum cut in every variant except replay_only (53%), the same as the plan. The prototype changes neither conclusion. It does show that the lever's value is in the narrow-capture port, not in the interpreter.

## 6. Feasibility: full ISA and precompiles

- **ISA: done.** All 69 fast-engine ops (RV64I, M, the Zbb subset; FENCE as nop) are in the kernel. Byte identity rests on two corpora: 231.7 M real steps (24628607 + 26235159), which execute 50 of the 69 ops, and the synthetic op corpus against the reference interpreter, which executes all 69 in 106,496 cases (§9.2) [M].
  - Everything the first pass cannot retire fast is a host step: illegal words, misalignment, absent pages, out-of-table targets, watched pages, the step budget. Their share is 0.06–0.08% of ordinary steps (21 k of 26.9 M on 607).
  - The GPU never sees a step the first pass did not retire fast. That does **not** make divergence impossible: the kernel is a second implementation of the engine's semantics, and its evidence is parity (231.7 M real steps plus the op corpus, §9.2). At run time every chunk end is now checked (§9.1); a wrong value that never reaches a register, the pc or the memory cursor at the chunk end (for example a wrong `lhs`/`previous_rd`/`flags` field, or a register written wrongly and overwritten before the end) is not caught on the GPU. The tape is untrusted advice (`compact_tape.restore` plus the AIR), so such a bug costs a rejected proof (liveness), never soundness.
- **Precompiles: host, by design.** keccak, sponge, secp, sha256, arith256_mod, bulk and the 7 curve ops are state transitions on guest memory. The first pass must run them anyway, because control flow depends on their results.
  - The GPU replay treats each one as a finished host step plus a reseed. Their witness families (call lists) come from the same `Event` the first pass already holds; today the walk's session re-creates them.
  - So the first pass must also append the per-family call records. That is cheap: about 560 k events on 26235159.
  - **Required fix** (independent of the GPU work, CPU only, byte-identical by test): Montgomery limb arithmetic for `bls12_381_fp2_mul`, `bn254_fp2_mul`, `arith384_mont` and the bn254/bls12 G1 ops. It is up to 4.86 s of serial first-pass time over the basket and 1.26 s on the p50 block.
- **Narrow capture on the GPU: feasible, and it is the real work.**
  - CPU metadata (56 B: A, B, C, old rd, next pc, 3 register clocks, ROM row) is a function of the tape. The register clocks need a cross-chunk "last access per register" scan: 32 lanes × chunks, the same shape as the existing `cpu_unpack`.
  - ROM counts are atomics.
  - ALU/BINARY/SHIFT stable dedup in first-occurrence order is a radix sort on (key, first index), then unique, then a sort back by first index.
  - Memory records, boundary capture and the local-ledger first-touch table are a sort by (address, tick) plus segmented first/last.
  - Every output has a field-wise T10DIGEST, so parity is mechanical.
  - No new proof authority: it is a prover-side producer, and receivers re-check everything.

## 7. Integration after GPU-native lands (owner: driver/capture; jobs files stay frozen to this stream)

1. **Prerequisites (M9 wave 0):** promote T1 (local ledger + inflight 16) and T10 (recorder) to default. GPU-native default with `Feed` / `CaptureSink` per sealed segment.
2. **Service arithmetic** (CPU, wave 1, any time):
   - replace the `u768 %` / per-call `invMod` paths in `candidate_curves.zig` with limb Montgomery;
   - parity: a randomized corpus against the current implementation, plus `captured_values_sha256` and `advice_all_sha256` on the basket;
   - expected 26235168 first pass 1.81 → about 0.6 s [E].
3. **Seeded first pass** behind `STWO_RV64_M9_GPU_REPLAY=1` in `rv64_ethereum_segments.zig` (`runFirstPass`):
   - `R.runSeeded` replaces `engine.run`, and host steps call `SegmentTape.hostStep`;
   - per-segment `SegmentTape` buffers come from the large-block recycler (pre-faulted; size class from `batch_steps`), never fresh;
   - the tape is published next to the checkpoint (a new `FirstPass` field; `Checkpoint` unchanged);
   - the first pass also appends the service call records from the `Event` it already has.
4. **Device replay stage** (driver stream, new file `rv64/m9_capture_replay.zig` + `NAT/rv64/m9_gpu_replay.cu` linked into `libstwo-rv64-native.so`):
   - per sealed segment, H2D seeds/mem/host steps on the h2d stream (about 18 MB);
   - `stwo_rv64_m9_gpu_replay_on` into a `capture_resident` region of the memory plan (201 MB per segment in flight, recycled after Stage 1);
   - status words go into the slab;
   - the first set bit **fails closed** to the CPU walk for that segment, with byte-identical outputs.
5. **Narrow capture on the GPU** (the factor; M9 3b): CPU metadata, ROM counts, family routing and stable dedup, memory/boundary records, `Batch` aggregates, local-ledger phase 1, each kernel gated by T10DIGEST field parity on the basket. Phase 2 (ordered ledger merge, about 0.6 s on 26235159) stays on the ordered CPU thread over the D2H first-touch table (about 4.7 M words, under 40 MB).
6. **Retire the CPU walk** on the flag-on path (keep it as the parity oracle in `rv64-m9-gpu-replay-dump` and in tests).
7. **Gates:**
   - `rv64_gate.sh` flag off/on byte-identical to the frozen golden;
   - 3+3 on 24628607 + 26235168 with capture and pre-seal reported;
   - E8 production miss run;
   - the replay-only walk share measured with `rv64-capture-bench` (§5);
   - **pre-seal ≤ 2 s at p50** (plan §5 3b).

## 9. Adversarial review (2026-11-07)

Receipts: `vectors/reports/rv64-m9-prep/m9-gpu-replay/review/`. Everything [M] re-run on the pod on 24628607 at chunk 256 (one GPU hold under 1 min per batch; dumps, caches and binaries deleted afterwards).

### 9.1 Runtime guards: half the chunks were unchecked (fixed)

- **Finding.** The kernel compared a chunk's end state only when the next kept seed started exactly where the chunk ended (`check_next`). On 24628607, 64,864 of 145,859 chunks (44%) end at a host step and 1 at a segment end [M, `g607-all.json` `chunk_ends`]. On segment 6, 17,560 of 20,297 do. None of those chunk ends were checked. Nothing bounded the seed's step range or the memory-tape cursor either: a bad seed read and wrote device memory out of range.
- **Fix** (`m9_gpu_replay.cu`, `rv64_m9_gpu_replay.zig`):
  - `SlowStep` grows from 56 to 64 B. It now carries `pc_slot` (the host step's own ROM slot) and `rd`. `Segment` gains steps, tape length, the host-step range and `end_slot`.
  - A chunk that ends at a host step must stop at `pc_slot`, with its memory cursor at the step's memory index. It must also hold `r[rd] == previous_rd`. When the seed after the host step survives (it does unless another host step follows at once), every other register, the pc and the memory cursor must equal that seed's.
  - A chunk that ends at the segment end must stop at `end_slot` with the cursor at the tape length.
  - New status `ST_BOUNDS`; out-of-table fallthrough sets `ST_PC_RANGE`.
  - `SegmentTape.verifyPartition` (called by the dump tool) proves that chunks and host steps tile each segment.
- **Evidence** [M]:
  - 7/7 SHA match with status 0.
  - Fault injection (`M9_INJECT`) fires status 4 on each class: `pc`, `mem`, `end`, `reg` (a register at a seed boundary) and `regh` (a register across a host step).
  - In an intermediate build that had only the pc and memory end checks, a register corrupted across a host step went undetected: status 0 with 6/7 SHA [M]. The original kernel had no check at all on these chunk ends (by inspection).
  - Kernel time is unchanged within noise: 3.68 ms for the whole block; 0.50–0.52 ms for segment 2.
  - Input grows to 4.63 B/step (from 4.61).
- **What is still not caught on the GPU:**
  - a wrong `lhs`/`rhs`/`previous_rd`/`flags` field that never feeds a register;
  - a register written wrongly and overwritten before the chunk end;
  - registers at a segment end.
  
  Such a bug costs a rejected proof, not soundness. The tape is untrusted advice: `compact_tape.restore` re-checks each step against the admitted ROM, and the AIR proves it. The soundness claim stands: "prover-side only, no new proof authority". The claim "divergence is impossible by construction" did not, and §6 now says so.

### 9.2 Parity coverage: 19 of 69 ops were never executed (fixed)

- **Finding.** The op census of both parity blocks (`cpu/cpu607-c256-p-r1.json`, `cpu/cpu159-c256-p.json`) has zero executions of nop, slt, sra, sraw, sraiw, mulh, mulhsu, rem, divw, divuw, remw, remuw, andn, orn, xnor, rev8, sext_b, sext_h and zext_h. `mulw` runs twice and `div` 598 times. "Byte-identical on the whole fast ISA" was therefore unproven for 28% of the kernel's opcodes. Those include every signed 32-bit division edge (INT32_MIN/−1, /0) and `mulhsu`, the classic hand-written-intrinsic bug.
- **Fix.** `rv64-m9-gpu-replay-dump --op-corpus OUT` (`rv64_m9_gpu_replay_opcorpus.zig`):
  - 77 instruction variants: every op, with immediates and shift amounts at their edges, `rd = x0` forms, branches both ways, jal/jalr forwards and backwards, and loads/stores at every width and offset.
  - Operands: 24 edge values squared, plus 256 random pairs for ALU ops and branches; random aligned addresses for memory ops.
  - The expected tape comes from the **reference interpreter** (`machine.Cpu.stepCached` with the Zbb decode set). It does not come from the fast engine or the M9 code. The ROM comes from the production `Engine.init`.
  - Every case is followed by a host step whose `pc_slot` is the reference next pc, so each case also exercises the new end check.
- **Evidence** [M]:
  - 106,496 cases (319,488 steps). All 69 GPU opcodes appear in the ROM slots executed (checked from `rom.bin`).
  - **Byte-identical**, status 0 (`review/g-corpus.json`, `review/corpus.json`).
  - Injection `pc` gives status 4.

### 9.3 Numbers corrected

| claim | was | is | basis |
|---|---|---|---|
| services' share of steps (26235159) | about 0.4% (559 k of 205 M) | 0.21% service calls (440 k); 0.27% host steps (559 k, incl. 119 k traps/absent pages) | [M] `first_pass_basket.json` |
| service calls per basket pass | about 1.4 M | 3.28 M service calls, 4.31 M host steps | [M] same |
| GPU replay vs serial first pass | 50–100× | 46–83× | [D] §0 |
| replay alone's share of the lever at p50 | about a third (9.58 → 9.14 s) | about a quarter (→ 9.19 s, replay_only_net) | [E] `model.json` |
| plain vs seeded first pass, basket | +8.6% (12.47 → 13.54 s) | about +10.5% | [D]: the plain pass timed each host step with 2 clock reads (24–25 ns each [M] on the pod, TSC), about 0.21 s over 4.31 M host steps, so plain is about 12.25 s / 116 MIPS. Per-call service costs carry the same ~25–50 ns (it matters only for "ordinary" at 0.12 µs) |
| seeded overhead on 24628607 | −9% | −9% in the original 2-rep runs, but **±0** in the review re-run (plain 159.3–159.6, seeded 160.2–160.8 MIPS, pod load 10–22) | [M] `review/cpu607.json`. The overhead is inside pod-load noise; a quiet-host A/B is needed before quoting it |

`replay_only` was optimistic. A replay-only deployment leaves the narrow capture on CPU workers, which then need the tape back from the GPU:

- D2H of 48 B/step: 5.4 GB on 26235168, 9.8 GB on 26235159 [D];
- then DRAM reads instead of an in-cache walk.

`replay_only_net` charges the read at 4.8 ns/step [E] (48 B at about 10 GB/s per worker), against 184.5 ns/step of capture CPU [D]. Result: p50 9.19 s (53%), p95 14.91 s (55%), basket 138.8 s (53%).

The PCIe time (1.95 ns/step on one link [D]) overlaps the CPU-bound capture, so it is not charged. It does compete with proving H2D. **Conclusion:** replay without the narrow-capture port is not worth integrating on its own.

### 9.4 Integration costs the plan did not carry

- **Serial first-pass extras left out of `seeded_s`.**
  - Checkpoint capture: plain `total_ns − exec_ns` = 12.7 ms / 7 segments on 24628607, 45 ms / 28 on 26235168 and 82 ms / 49 on 26235159 (about 1.6–1.8 ms per segment) [M].
  - First touch of fresh tape buffers: 0.79 s on 26235168 (seeded `total_ns − exec_ns` with the prefault memset); +34% exec time without prefault on 24628607 [M].
  - The large-block recycler with pre-faulted per-segment buffers is therefore **mandatory**, not an optimisation: about 38 MB per in-flight segment, about 0.6 GB at inflight 16 [D].
- **Device memory.**
  - The tape is 201 MB per in-flight segment (48 B × 4.19 M), plus about 18 MB of inputs, plus the narrow-capture sort scratch [E: about 0.2–0.3 GB].
  - The OCC lever runs two jobs per 32 GB GPU at 12.4–13.4 GB each. Earlier in this review the resident services held 30.3 GB of each GPU [M, nvidia-smi].
  - The capture region has to come out of the memory plan, and 2 in-flight segments cost about 0.9 GB [D].
  - Better: fuse the narrow-capture producers into the replay kernel. Each thread already holds the step it would write, so it can emit narrow records directly and never materialise the 48 B/step tape: about 5× less device traffic and memory than tape-then-capture [E].
- **GPU-s.** Replay is 0.48 ms per segment. The narrow-capture kernels (sorts/scans over about 4 M records per segment) are estimated at about 5 ms per segment, about 0.25 GPU-s on 26235159, against about 59 GPU-s of proving [E]. That is off the critical path except for the first segment (head).
- **The full_now factor depends on work not built.** −59% at p50 requires narrow capture, ROM counts, dedup, memory/boundary records, `Batch` aggregates and ledger phase 1 on the GPU, with every other per-step CPU cost hidden behind Stage 1. None of that exists. The prototype proves only the first stage (the replay) and its parity.

## 8. Reproduce

```sh
# laptop: sources to the pod (git archive of the branch), then on the pod:
zig build rv64-m9-gpu-replay-dump -Dimplementation-commit=<sha> -Dimplementation-tree=<tree> -Dimplementation-dirty=false \
  -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Doptimize=ReleaseFast        # under build.3.lock
STWO_RV64_M9_PREFAULT=1 rv64-m9-gpu-replay-dump cfg-24628607.json d607-c256 256 2 > cpu.json   # CPU parity + inputs
scripts/rv64_m9/gpu_replay_bench.sh build
scripts/rv64_m9/gpu_replay_bench.sh run d607-c256 10 -1 0     # all segments; '2' for one segment
STWO_RV64_M9_SKIP_REF=1 STWO_RV64_M9_PREFAULT=1 rv64-m9-gpu-replay-dump cfg-<block>.json tmp 256 -1   # first pass only
rv64-m9-gpu-replay-dump --op-corpus corpus && scripts/rv64_m9/gpu_replay_bench.sh run corpus 5 -1   # op corpus (§9.2)
M9_INJECT=pc|mem|end|reg|regh scripts/rv64_m9/gpu_replay_bench.sh run d607-c256 1 -1             # guards fire: status 4
python3 -I scripts/rv64_m9/gpu_replay_model.py --plan-root <checkout of codex/rv64-m9-plan> --first-pass first_pass_basket.json
```

Request configs: `/workspace/m3/inputs/requests/<block>.json` with `output_directory` set to a string (the dump tool's JSON parser rejects `null`).
