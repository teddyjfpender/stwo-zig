# Remaining score wins: instructions/gas, committed bits/gas, prove time

Read-only exploration at `origin/codex/rv64-guest-efficiency` `271ee1a42` (PR #308). Nothing was
committed. Scratch files are in `~/Coding/ge-cache/explore-score/`.

## What was run

- `bench.py run --keep-profiles` on 2 blocks (24,628,607 and 24,626,900) with the prebuilt v3 ELF
  `verify-curves/evm/client-evmone-v3.elf`, profile `ethereum_services_v3`, and the adapter host.
  Both blocks were exact. Execution-only, 2.5 s.
  - Results: 3.206 instr/gas and 35,871 bits/gas on these 2 blocks (the 12-block PR figure is
    3.283 and 34,785).
  - G5 fails only because the 2-block basket has no holdout block.
- `bench.py attribute` on both blocks, plus my own client-aware bucketing (`scripts/attr2.py`).
  `bench.py`'s regexes are tuned for the Rust guest and put secp/state/memory into "other".
- A per-PC profile of the `dispatch_cgoto` loop against an `llvm-objdump` disassembly, plus a U256
  4×LD/SD group detector.
- I could not get an EVM opcode histogram. `--ls-histogram` fails on this executor with
  `UnknownField`.
- Prove-time model: core-ns per cell by proof group, from `cost-per-cell.md` (fused2/m4, verified
  with `final2/prefix4`):
  - CPU segment: 53 core-ns per cell
  - Keccak truth: 99
  - secp truth: about 70
  - small truths: about 550, mostly PoW
- Applied to the complete v3 classic block proof
  (`origin/codex/rv64-pr308-integration-review:vectors/reports/rv64-pr308-v3-capture-20261102/classic-full-*`):
  - 7 CPU proofs (6 × 2^22 + 1 × 2^21) and 6 truth proofs
  - 5.41 G MAIN+INTER cells
  - **37.71 s prove, 372.6 user-s, 14-core M4 Max** (QM31, 70 queries, PoW 26, about 96-bit
    conjectured)

### Where prove time goes in the complete v3 block (24,628,607)

| Group | cells | core-ns/cell | est. core-s | share |
|---|---:|---:|---:|---:|
| CPU segments (CPU row, LS, ALU, bulk/sponge/jumpdest bridges) | 3.70 G (main 2.12, inter 1.58) | 53 | ~196 | **~55%** |
| Keccak-f truth (2 × 2^21: 506 M main + 168 M inter each) | 1.35 G | 99 | ~134 | **~37%** |
| secp row truth (2^18 + 2^17) | 0.34 G | ~70 | ~24 | ~6.5% |
| SHA-256 / arith / small truths | 0.03 G | fixed | ~3–5 | ~1% |

**Keccak is 25% of cells but about 37% of prove time.** Its composition runs at 53–85 core-ns per
cell (degree 4 on a 4n domain), against 13–25 for the CPU (degree 3 on 2n). Inside the CPU proofs,
interaction cells are 43% of CPU cells (inter/main = 0.74).

### Where instructions go (fresh attribution, v3 client)

| Bucket | 24,628,607 (3.648 instr/gas) | 24,626,900 (3.007) | instr/gas (607 / 900) |
|---|---:|---:|---:|
| `dispatch_cgoto` loop (opcodes inlined) | **37.2%** | **29.9%** | 1.36 / 0.90 |
| state DB (`zeg::` flat indexes, Storages/Accounts find) | **14.9%** | **16.2%** | 0.54 / 0.49 |
| out-of-line opcodes (mstore_slow, udivrem, sload, calldataload, shifts, call_impl, be load/store) | 13.7% | 11.2% | 0.50 / 0.34 |
| trie/MPT (`stwo::` scan_more, trie_get, encode, decode_dnode, insert) | **11.9%** | **13.8%** | 0.43 / 0.41 |
| memory functions (v3_copy_run head/tail, sub-threshold memcpy/memset, copy_forward) | 9.1% | 10.5% | 0.33 / 0.32 |
| secp software (double_mul, fe_mul, sc_mul) | 5.3% | 9.0% | 0.19 / 0.27 |
| Keccak glue (`ethash_keccak256`) | 3.2% | 3.6% | 0.12 / 0.11 |
| SHA-256 glue + SSZ merkleize | 1.1% | 1.8% | |
| alloc, validate, other | 3.5% | 4.0% | |

- **RISC-V mix (both blocks):**
  - LD 17.8%, SD 12.9%, LBU 4.4%, so memory operations are about 36%
  - ADDI 15.7%
  - SLLI, OR, SRLI and AND together are about 16%, mostly byte assembly that Zbb rev8 targets
  - JALR 3.5%
- **Dispatch loop:** 378,743 indirect jumps on 607 (≈ EVM ops dispatched), at **26.4 RISC-V
  instructions per dispatched op** inside the loop, plus about 10 more out of line.
  - The hottest block is the PUSH path: 4× `sd zero`, then byte loads with `slli`/`or`.
  - **13.4% of all instructions are LD/SD in 4×8-byte U256 groups** (same base, offsets
    o..o+24): stack-slot moves. The figure is the same on both blocks.

### Committed cells per gas by component (calibration.json coefficients)

| Component | 607 | 900 |
|---|---:|---:|
| CPU (119.9 cells/instr) | 70.5% | 68.9% |
| Keccak sponge (36,587 cells/permutation) | 22.6% | 22.5% |
| secp | 1.9% | 3.2% |
| Keccak-f direct | 1.4% | 1.7% |
| unaligned memcpy | 1.2% | 1.2% |
| SHA-256 | 0.8% | 1.2% |
| bulk memory and jumpdest | ~1.4% | ~1.3% |

## Ranked inventory (by effect on end-to-end prove time)

- **Δtime model:** about 0.55 × Δ(CPU cells) + 0.37 × Δ(Keccak time) + … on the complete-block
  split. Because CPU cells per instruction are flat, a −10% cut in instructions is about −5.5% of
  prove time.
- **GPU column:** whether the lever carries over to a resident GPU prover.
  - Per-cell work there (composition, LDE, hashing) is compute- or bandwidth-bound in about the
    same ratios.
  - PoW and per-proof CPU overheads mostly vanish.
- Deltas do not add exactly, because they compound.

| # | Lever | Δ instr/gas | Δ bits/gas | Δ prove time (CPU; GPU) | Effort | Soundness risk |
|---|---|---:|---:|---:|---|---|
| 1 | **GKR for global relations on v3** (RAM/register/ROM/service-bus LogUp out of commitment; extends #310 OM31 route; #311 is its CUDA engine) | 0 | −30 to −40% of CPU cells (inter 1.58 G of 3.70 G, plus truth inter 0.48 G); proxy bits do not model GKR | CPU: ≈0 or worse (OM31 CPU0 control: −39.7% cells, +6% time). **GPU: est. −15 to −25%** (removes interaction gen+LDE+hash+DEEP+LogUp composition share; adds bandwidth-bound sumcheck) | weeks; #310 lists open gates (v3 CPU roles, OM31 truth adapters, physical binding, LS-D64/U8/throughput-Keccak layouts) | **High**: LogUp/GKR terms not in any ledger; `om31_security_candidate` refuses promotion; OM31 q256 changes proof size and recursion |
| 2 | **Keccak composition: degree 3 on 2n (split chi), or a cheaper 4n evaluator** | 0 | 0 to +5% (split adds columns) | **−8 to −12%** (Keccak comp_eval is 55% of Keccak truth time; halving it is −27% of Keccak, and Keccak is 37% of total); same on GPU, where it is compute-bound and the critical-path proof | 1–2 weeks AIR + soundness rewrite | Medium: new AIR, but local; re-derive the degree bound |
| 3 | **Fused LS+CPU row for aligned LD/SD** (PATH #3) | 0 | −24 cells/instr ≈ **−14% bits** (CPU is 70% of cells) | **−10 to −11%**, both | ~30 h | **High**: PC/tick continuity and RAM timestamp ordering in one row |
| 4 | **State DB and trie with verified host hints** (advice: account/slot table index, branch-child offsets, pre-decoded node layout; guest checks equality and keccak-authenticates the node bytes) | **−0.20 to −0.35** (−6 to −10%; state + trie = 27–30% of instr) | −5 to −7% | −4 to −6%, both | 1–2 weeks client | Low/medium: hints are always re-checked; risk is a missed check (consensus bug), not a protocol risk |
| 5 | **256-bit LS row / U256 stack-move instruction** (custom `ld256`/`sd256` on 32-byte-aligned slots; intx/evmone intrinsic) | **−0.33** (−10%: 13.4% of instr collapse 4→1) | −8% (saves ≈290 of 552 cells per group) | **−4.5 to −5.5%**, both | ~2 weeks: ISA candidate → AIR → RAM argument with 4 word accesses per row | Medium: new memory width; 4 RAM events per row; alignment guard |
| 6 | **Interpreter second pass** (in-progress track: per-basic-block gas/stack checks cached per JUMPDEST, top-of-stack in registers, rev8) | −0.2 to −0.4 (dispatch 0.9–1.36 instr/gas; 26 instr/op in loop) | −4 to −8% | −3 to −6% | in progress | Low (guest-only; EEST and basket guards) |
| 7 | **AOT EVM→RV64 translation of hot contracts** | −0.5 to −0.8 (removes most of the 26 instr/op dispatch, folds PUSH constants, keeps stack in registers within a block) | −15 to −22% | −8 to −12% | months | **High**: the translator is in the TCB. Either prove translation per block (cost) or bind a precompiled image to code hash (dynamic ROM per block); diverges from ZisK's model |
| 8 | **U256 ALU service** (ADD/SUB/LT/GT/EQ/ISZERO/AND/OR/SHL/SHR/BYTE/MUL on 32-byte stack slots, ZisK arith256 style; a plain a·b+c service is already listed) | −0.12 to −0.25 (est.; no opcode histogram) | −3 to −6% (≈300–400 cells/row vs ≈40 instr × 120) | −2 to −4% | 1–2 weeks AIR + bridge | Medium: new truth AIR; carry-chain soundness |
| 9 | **Fewer Keccak permutations**: hash witness nodes lazily (authenticate when traversed) instead of eagerly in `NodeStore::add` | 0 to −0.05 | 0 to −3,000 (only if the witness has unused nodes) | 0 to −5% (Keccak is 37% of time) | days to measure: count nodes added vs resolved | Low: same digest checks, different order |
| 10 | **Compact CPU decode** (in progress, PATH #4) | 0 | −10 cells/instr target (−6% bits); `decode/prefix4` so far shows only −2.3% CPU cells (2,106 vs 2,155 M) | −2 to −5% | in progress | Low/medium |
| 11 | **Memory functions**: byte-granular head/tail in the service descriptor, lower copy/set minimums (64 → ~16 B) | −0.10 to −0.15 (9–10% of instr are wrappers or sub-threshold software) | −2 to −4% | −1.5 to −2.5% | days (bulk AIR byte masks) | Low/medium |
| 12 | **Composition kernel efficiency on CPU** (lazy u64 accumulation, M31×QM31 power multiply, measure the "reference evaluator" fallback share in `riscv_composition.zig`) | 0 | 0 | CPU −8 to −18% if composition gets 1.3–2x; GPU: write the kernels this way from the start | 1 week profiling first | None (prover-only, deterministic parity) |
| 13 | **Per-proof fixed costs** (PoW 26 bits ×13 proofs; 5 small truths; Keccak 2^21 tables ≈10.8 M cells per Keccak truth) | 0 | ≈0 | CPU: PoW ≈1.8 core-s/proof ≈ 6%, small truths ≈ 2.5%. A near-empty Keccak truth still costs 10.9 core-s (final2), so never open a third shard. GPU: PoW ≈0; merging small truths into the CPU PCS removes launch-bound proofs | days | Low |
| 14 | **secp remaining software** (double_mul/fe_mul/sc_mul, 5–9% of instr) | **already a track** (products on arith256_mod, client to ~3.13) | — | — | — | — |
| 15 | **Padding to powers of two** | 0 | −1 to −2% | ≈ −1% | — | — |

The ladder already emits a 2^21 last segment. CPU-component padding is 4.9%. The secp truths are
2^18 + 2^17 for about 200 K rows. Preprocessed columns are cached at setup and cost ≈ 11 core-ns per
cell per proof in DEEP/OODS: under 1%.

## Reading the ranking

- **For prove time on GPU,** the three biggest remaining levers are all prover-side:
  - GKR on v3 (#1)
  - Keccak's degree-4 composition (#2)
  - the fused LS+CPU row (#3)
- **The biggest client-side levers** are #4–#7: state/trie hints, a 256-bit LS row, the interpreter
  pass and AOT.
  - Together, excluding AOT, they could take the client from ~3.13 (after the current tracks) to
    about 2.3–2.6 instr/gas.
  - At ~100 cells/instr, that is ~14–16 K CPU bits/gas.
- **Keccak is now the most under-weighted cost in the bits/gas proxy.**
  - The proxy charges 36.6 K cells per permutation.
  - Time-weighted, a permutation costs about 4.5 core-ms, which is 1.9x its cell share.
  - A score that tracks prove time should weight Keccak cells ~1.9x CPU cells. Otherwise client
    work that trades hashing for instructions will look better than it is.
- **For the < 2 s goal:**
  - The complete v3 block is 5.41 G cells at 37.7 s on the M4 Max, so 19x is needed.
  - Cells per block after #1–#5 would be roughly 2.8–3.3 G.
  - At 0.2–0.5 ns/cell/GPU (cost-per-cell roofline at 10–30% efficiency), 4 GPUs give 0.15–0.4 s
    of cell work.
  - The binding items stay on-device witness generation, the Keccak critical-path proof and
    recursion latency, not the score.

## PR #311 (new GPU backend PR) — relevance to these wins

The head has moved to `771334a93` (4 commits, +5,264/−4, 72 files) on #310. It is the CUDA engine for
lever #1. Device-resident OM31 LogUp/GKR sumcheck:

- projection
- fraction trees
- Eq tables
- folds
- round control with device-side Blake2s Fiat–Shamir
- a 128-byte terminal mask checked by the native verifier

Observations:

- **No hardware execution** ("Exit 77: no NVIDIA device"). Every speed item (`fused_fold_sum`
  −268 MB of reads at 2^22, 4-level Eq fusion 21 → 6 launches, split reduction) is opt-in and
  unmeasured. Nothing in it moves prove time yet.
- **v3 is still excluded** upstream: #310 rejects v3 families with `GkrV3ServiceUnsupported`, and
  the LS-D64/U8-pair/throughput-Keccak layouts are not qualified. The GKR win (#1) on the
  instruction mix we actually score is gated on #310's open items, not on #311.
- **Latency shape:** each sumcheck round is several launches plus a single-thread round-control
  kernel. That kernel uses 128 registers and has stack storage (192 B on sm89). There is no CUDA
  graph capture.
  - That is about 22 rounds × ~22 layers × ~4 launches ≈ 2,000 launches per GKR instance, about
    6–10 ms at 3–5 µs each.
  - For a 2 s block budget, batch all relations of a proof into one GKR instance (layer-batched
    across components), and capture rounds in a graph or a persistent kernel.
- **Security and parameters:** the #310 route runs OM31, q256, P0, fold4 for the 128-bit target. It
  is not comparable to the 96-bit classic v3 timing (37.7 s). The v2 GKR 143.85 s figure is
  about those parameters and a different guest, not a GKR speedup over classic v3.

## Caveats

- Only 2 blocks were profiled. Block 607 is dispatch-heavy; block 900 is secp-heavy.
- Instruction deltas for #4, #5, #8 and #11 are estimates from symbol and PC shares, not prototypes.
- The time model applies M4 Max CPU core-ns per cell by group (fused2). GPU ratios are assumed
  similar for compute-bound phases and are unmeasured.
- The bits/gas proxy (`calibration.json`) is linear in instructions and does not model GKR.
