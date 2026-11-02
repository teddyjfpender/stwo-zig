# CUDA / GPU backend audit for RV64 Word16 block proving

Scope: stwo-zig-ge at `origin/codex/rv64-guest-efficiency` (271ee1a42, PR #308), plus PR #310
(`codex/rv64-pr308-integration-review`, f66f6b518) and PR #311 (`codex/rv64-cuda-resident-gkr`,
771334a93, the newest GPU PR; last updated 2026-11-02 10:19). I read the branches with `git show`
and committed nothing. PR #299 (l-henri, CUDA circuit FRI fix) is the only other open GPU PR. It
touches recursion only (section 6).

## TL;DR

1. **No RV64 Word16 proof has a GPU path today.** On #308, `src/integrations/riscv_cuda` is a
   350-line RV32IM boundary whose execution is deliberately closed: `requireExecution` fails, and
   the AOT product set for RISC-V has zero entries. `riscv_metal` is RV32 only. Nothing under
   `src/backends/{cuda,metal}` mentions `word16` or `rv64`.
2. **PR #311 is the first RV64 GPU code.** It adds about 5.3k lines, but only the OM31 LogUp/GKR
   *numerical* engine for one oracle: projection, fraction tree, Eq, sumcheck sums, folds, and an
   on-device Fiat–Shamir round loop. It has never run on a GPU (every hardware gate exits 77). It
   targets 4090/5090 (sm_89/sm_120), not H100/H200 (sm_90), where the rest of the backend is
   qualified. In the v2 GKR receipt this phase is about 3.4–4.9 s of a CPU segment's ~17 s
   (roughly 20–25%).
3. **A mature resident CUDA STARK stack already exists for Cairo, the circuit verifier and native
   examples.** It covers circle LDE, Blake2s Merkle (plain and prefixed), on-device transcript,
   PoW, LogUp relation kernels, AOT composition, OODS, DEEP quotient, FRI and decommit. One sync
   and one D2H per proof. It is **QM31 only**. Protocol-wise it matches the **classic RV64 route**
   (QM31 / 70 queries / 26 PoW bits / blowup 2 / fold 1 / Blake2s-prefixed). It does not match
   the OM31/GKR route (degree 8, ρ=1/4, 256 queries, PoW 0, fold 4).
4. **A CUDA porting hazard I did not expect:** the existing CUDA lifted-Merkle kernel hashes every
   column at the *lifted* (max) height. For RV64 segments, lifted leaf cells are **about 45× native
   cells** (CPU segment 0: 29.6 G lifted vs 0.66 G native MAIN+INTER). The CPU prover avoids this
   with hash-state expansion (`prover/vcs_lifted/leaves.zig`). The CUDA backend has no expand
   kernel.
5. **The fastest path to a measured GPU RV64 block is the classic route.** It is the only route
   that proves v3 today (37.71 s on CPU, 5.41 G MAIN+INTER cells, nominal 96-bit). GKR rejects
   v3 with `GkrV3ServiceUnsupported`. On CPU, per instruction, GKR v2 costs about 3.2 µs and
   classic v3 about 1.4 µs (different guests and security, so this is indicative only).
6. The goal says "< 2 s on average", which is a **throughput** target. Execution/capture (about
   2.5 s for v3) and recursion can be pipelined across blocks, so per-block GPU work is the binding
   cost. That work is 5.41 G cells: about 2.96 ns/cell of GPU time at 8 GPUs, or 1.48 at 4.

---

## 1. Inventory of the GPU code

| Area | Path | Size | State |
|---|---|---|---|
| Resident CUDA backend (runtime, ABI, AOT, native kernels) | `src/backends/cuda` | 279 files, 82k lines; 164 `.cu/.cuh` in the repo, about 33k lines outside autoresearch | Qualified on H100/H200 for Cairo and circuit; product distribution deferred |
| Native examples (xor, blake, state_machine, …) | `src/integrations/native_cuda` | 281 files, 49k lines | Hand-written driver per example |
| Circuit-recursion CUDA | `src/integrations/circuit_cuda` | 44 files, 8.6k lines | H100/H200 qualified; Rust byte-equal root |
| Cairo CUDA | `src/integrations/cairo_cuda` | 141 files, 43k lines | 4 SN PIEs on H200 accepted by the official Rust verifier |
| RISC-V CUDA | `src/integrations/riscv_cuda` | 5 files, 352 lines (#308) | RV32IM structural receipt only; execution fails closed |
| RV64 CUDA GKR | `src/backends/cuda/native/rv64/*`, `src/integrations/riscv_cuda/rv64/*` | #311 only | Compile-only; no device execution |
| Metal | `src/backends/metal` (268 files) plus `src/integrations/riscv_metal` | — | RV32 native AIR, Cairo and native; no RV64 |
| CuMetal (CUDA→Metal translation) | `src/backends/cuda/cumetal` | — | Portability/correctness screen only; never counts as NVIDIA evidence |

### Kernel families in `src/backends/cuda/native` (QM31, Blake2s)

| Stage | Files | Kernels (selection) |
|---|---|---|
| Circle FFT / LDE | `transform/{lde,n2b,b2n,n2b_fused,b2n_fused,b2n_retained,composition_split}.cu*` | `n2b_stage/final_{warp,block}`, `b2n_init/continue/stage`, `stage_lde_columns`, `stage_addressed_lde_columns`, `b2n_composition_split_final` |
| Merkle / Blake2s | `commitment/{merkle,progressive,blake2s_core}` | `progressive_{init,absorb,absorb_lifted,finalize}`, `contiguous_leaf`, `mixed_leaf` (mixed-height canonical), `child_layer`, `interior4`, `upper_tail`, `fri_leaf` |
| Transcript (device Fiat–Shamir) | `transcript/transcript.cu` | `mix_words(_pair)`, `absorb_pow`, `draw_words`, `draw_secure`, `draw_queries` |
| PoW grind | `pow/search.cu`, `circuit_cuda/native/circuit_grind.cu` | `prefix_kernel`, `search_kernel` |
| LogUp / interaction | `relation/{graph,batch_inverse,layout}` | `relation_fractions_tiled`, `fraction_chain/prefix_global`, `batch_inverse_ragged`, ragged scans, `finalize_claimed_sums_ragged` |
| Composition (constraint eval) | `aot/native/constraint_*.cu`, `aot/native/circuit_eval/*`, `aot/native/cairo_*`, `constraints/powers.cu` | One generated or hand-written kernel per AIR; Cairo uses 68 parametric AIR bodies; circuit uses `air_aot` |
| Witness | `cairo/*`, `circuit/{base_witness,interaction_fractions}.cu`, `aot/native/witness_*.cu` | Cairo: 64 witness kernels, including a native EC writer |
| OODS | `oods/{evaluate,barycentric}.cu` | `evaluate_first/reduce/many`, `inverse_tree`, `derive_points` |
| DEEP quotient | `quotient/{numerator,combine,prepare}.cu` | `accumulate_native_bucket` + `lift_native_bucket` (native-height accumulation), `combine(_compact)` |
| FRI | `fri/{fold,final}.cu` | `fold_circle`, `fold_line`, `fold_two/three/four`, `line_ifft_stage`, degree verdict |
| Decommit | `decommit/{query_planning,trace,fri,merkle_walk}` | `normalize_queries`, `prepare_trace/fri_queries` |
| Generic secure DAG codegen | `secure_polynomial_codegen_v1.zig` (CUDA and Metal) | Lowers `prover_engine.air.secure_polynomial_program_v1` to kernels. Used for RV32 word-memory/range16, not RV64 |

GKR/sumcheck existed nowhere in CUDA before #311. Nothing in the CUDA backend is OM31 (`om31`
appears only as `toM31Array` helpers).

### Residency and launch structure (from the Cairo H200 v18 receipt, `suite-v18.json`)

- One `Session` per proof with an arena planned up front (`persistent_bytes` = 98.6 GB for SN PIE
  1). There are zero allocations during the proof and `cpu_fallback*` = 0 by construction
  (`allows_cpu_fallback = false`).
- About 3,600 direct kernel launches per proof on one stream: `lane_count` 1,
  **`graph_launches` 0**, **`sync_calls` 1**, `d2h_proof_operations` 1 (7.3 MB). Transcript, PoW
  and query draws run on device, so nothing round-trips to the host mid-proof.
- H2D is about 3.35 GB per proof (CPI input plus static/preprocessed). Cold ingress is 4.66 s
  (`static_ns` 2.57 s, source 0.79 s, runtime init 0.52 s) against a 1.03 s proof execution.
  Ingress, not kernels, dominates end-to-end time.
- Multi-GPU: a context selects one device (`cudaSetDevice`). There is no peer access, NCCL or
  multi-device scheduler in the backend. #311 adds the first 2/4-device capacity ledger (section 3).
- CUDA graphs: `runtime/graph_execution.zig` exists, but qualified runs use none. #311 also avoids
  them, because the context rejects borrowed lanes during capture.

## 2. Measured GPU numbers in the receipts (all Cairo or circuit; no RV64)

| Workload | GPU | Number | Source |
|---|---|---|---|
| Cairo SN PIE 1–4, proof execute+decode (cold, v18) | H200 | 1.034 / 0.657 / 1.030 / 0.798 s; device peak 100 / 61 / 99 / 80 GB; adapted→publication 4.7–5.7 s | `cairo_cuda/README.md`, `autoresearch/notes/2026-09-29-cairo-cuda-subsecond/suite-v18.json` |
| Same, kernel attribution, PIE 1 | H200 | Quotient 161→19+3 ms (native-height accumulation); `n2b_continue` 111 ms; mixed Blake2s leaf 88 ms; leading AIR kernel ~78 ms; EC witness 127→5 ms | subsecond README |
| Cairo mainnet leaves 15627902-4 and -5-7 | H100 | Proof+decode 0.35–0.49 s; warm ingress 1.5–2.3 s; cold 5.4–7.0 s; 51 GB arena | `cairo_cuda/README.md` |
| Circuit R7 (Fibonacci, Blake G) | H100 | Prove 0.56–0.77 s; verify 0.14 s; arena 1.47 GB; device-stage sum only ~50–60 ms (host prep and launch dominate) | `circuit_cuda/README.md` |
| Two-PIE → root pipeline | H100 | 32.308 s = Cairo 9.494 + wraps 12.579 + fold 9.021 + overhead 1.214; resident circuit prove 2.3–3.0 s per wrap; 28 GB arenas | `recursive-product-20260918/cuda-resident-pipeline-h100-20261001/receipt.json` |
| Same pipeline, integrated | H200 | 15.2–15.3 s canonical (Cairo 7.3, wraps 4.0–4.2, fold 2.9); compact terminal root 13.363 s (fold 1.34 s, root GPU proof ~0.25 s); sampled peak 54.9 GB | `…/cuda-resident-pipeline-h200-20261001/{README.md,measurements.json}` |

Takeaways for RV64:

- The receipts contain no GPU per-cell throughput number. The Cairo receipts give no cell
  counts, so ns/cell cannot be derived.
- The evidence agrees with cost-per-cell.md: proving kernels run in about 1 s on large AIRs, while
  ingress, static setup and host-side circuit build/verify dominate wall time.
- The recursion pipeline (wrap ~2 s per leaf, fold 1.3–2.9 s on H200) is itself larger than the
  2 s budget per block. At steady state it must be amortized or pipelined.
- **Arenas are large.** Cairo uses 51–100 GB for one max-log-23 proof. An RV64 CPU segment is
  max-log 22 with about 7.3k committed columns, so it should fit an 80 GB card. #311's 24/32 GB
  consumer targets need explicit planning. The OM31 route's ρ=1/4 doubles LDE storage.

## 3. PR #311 in detail (resident RV64 CUDA sumcheck/GKR)

Base: #310 `a7f484e34`. Commits: `93bfb2fd` engine, `bccab607` resident feedback and assembly,
`43148eba` Eq fusion, `771334a9` fold/next-sum fusion. 72 files, +5,264.

New device code (`src/backends/cuda/native/rv64/`):

- `om31.cuh`: 8-coordinate OM31 arithmetic.
- `gkr.cu`: `project`, `layer` (adjacent and fused fraction tree), `eq_seed`, `eq_expand`,
  `eq_tile_kernel` (4-level fusion), `sum_first`, `sum_reduce`, `sum_secure_split`,
  `fold_layer`, `fold_sum_first`.
- `round.cu`: `round_init_kernel`, `round_advance_kernel`, `pack_mask_kernel`.
- C ABI: `stwo_rv64_gkr_{project,layer,eq,eq_fused,sum,sum_split,fold,fold_sum,pack_mask}_on`,
  `stwo_rv64_sumcheck_{init,round}_on`.

**What is resident.** Tuple planes, N/D fractions, trees, Eq, both fold banks, round state, the
Blake2s digest and the raw-mod-OM31 challenge all stay on device. Per round, the device computes
the cubic correction, trims and absorbs the coefficients, draws the challenge, updates the
claim/Eq, and folds. No host sync, allocation or field transfer happens inside the loop. Readback
at the end is a 32-word terminal mask, 40 state words and 44 words per round. The existing native
Zig sumcheck verifier then checks the compact record.

**Launch structure.** Direct launches on owned lanes. No graphs, no default stream, no CPU
fallback. Generation-tagged allocation registry and preflight checks; poisoned state on failure.

**Cost mechanisms. These are source-model claims, not measurements.**
- At 2²², fused fold+next-sum removes 20 launches and 256 MiB of table reads.
- 4-level Eq fusion: 21→6 launches for 21 variables.
- Cubic correction needs 1 inverse instead of 3.
- The split reduction grid uses 80 vs 128 registers.
- The round-control kernel uses local stack (192 B on sm_89).

**Multi-GPU.** `rv64/scheduler.zig` is a single-coordinator credit ledger for at most 4 devices.
It charges each job's exact bytes against `free_bytes - reserve`, picks the least-charged device,
needs no peer access, and keeps public order at assembly. It is not a worker pool yet. Engine
memory per oracle: base leaf 36n B, secure upper tree <64n B, fold scratch ≤32n B, Eq ≤8n B. At
the receipt's `max_gkr_variables` of 26 that is about 9.4 GB per oracle.

**What #311 does not do** (from its own PR body and design doc):
- Mixed-instance batched GKR. The CPU route batches up to 21 local instances; #311 handles one
  LogUp oracle.
- RV64 witness/metadata → resident tuple emission ("real RV64 witness-to-commit lowering is still
  unimplemented").
- Authenticated physical binding.
- OM31 PCS, DEEP or FRI.
- Whole-block transcript wiring and the native receiver roster.
- v3 admission, recursion or security claims.

**Hardware evidence.** None. sm_89 and sm_120 compile with no spills. Host-side numerical parity
passes (14 cases / 62 rounds per strategy), as do ASan/UBSan replay and a 4,196-case Python field
oracle. Device harnesses exit 77 because no device is present. sm_90/sm_100 (H100/H200/B200) are
not in its gencode list.

**Assessment.** Sound engineering: custody is right, transcript parity is right, and fusion is
sensibly opt-in. But it is about 20–25% of one route's per-segment work, and that route cannot
prove v3 yet. It does not move a full GPU block closer until OM31 PCS and witness ingress exist.

## 4. Which RV64 Word16 prover stages have GPU paths

| Stage (classic or GKR route) | CPU today | GPU today | Reusable CUDA pieces | Gap |
|---|---|---|---|---|
| Guest execution / capture / packet import | CPU, 2.46 s (v3) / 2.66 s (v2) | none | — | CPU-only. Pipeline it across blocks |
| MAIN witness fill (CPU segments, services) | CPU (`word16_execution`, `*_native_fill`) | none | Cairo-style device witness writers as a pattern | Port, or upload about 3–4 GB of MAIN per segment over PCIe |
| Interaction (classic LogUp columns) | CPU | none | `relation/*` ragged fraction / batch-inverse / prefix kernels (QM31) | RV64 relation layouts and tuple emitters |
| Interaction (GKR route) | CPU, `gkr_ns` 3.6–5.3 s per segment | #311, numerical only, unexecuted | — | Mixed-instance batching, tuple ingress, binding |
| Circle LDE | CPU | none | `transform/*` (M31 base, any height) | Plumbing only |
| Merkle commit (lifted, Blake2s-prefixed) | CPU with state expansion | none | `progressive_*` prefixed kernels | **Lifted absorb is ∝ lifted cells (about 45×)**. Needs an expand kernel |
| Composition (constraint eval) | CPU, `evaluateConstraintQuotientsOnDomain` per component | none | AOT pattern; generic secure-DAG codegen | RV64 AIR is hand-written Zig, generic over lanes. No CUDA lowering (section 5) |
| OODS / DEEP / FRI / decommit | CPU (QM31 classic; OM31 GKR) | none | All QM31 kernels | Classic: binding only. GKR: OM31, 256 queries, fold 4 all new |
| Transcript / PoW | CPU | none | Device transcript + PoW grind (QM31 rejection draws) | GKR uses raw-mod-OM31 draws (#311 has a version for sumcheck) |
| Truth proofs (Keccak, secp, SHA, arith256, sponge, bulk) | CPU; v3 has 6 truths and 1.72 G cells | none | — | Each truth AIR needs composition and witness kernels |
| Recursion / aggregation of RV64 | CPU (`rv64_recursion`) | none | circuit_cuda (Cairo leaves only) | RV64 verifier circuit on GPU |

## 5. What blocks a full GPU RV64 block proof (ordered)

1. **Composition kernels for the RV64 Word16 AIR.** Constraints are hand-written Zig, generic over
   lane types (`rv64/air/evaluation.zig`, `lane.zig`). An "external lane" contract already exists
   for in-circuit verification (`zero`, `one`, `fromU32`, `add`, `mul`, `inv`, …).
   - Cheapest route: a **recording external lane** that traces each component's emit function into
     the existing `secure_polynomial_program_v1` IR, or straight to CUDA source. Then reuse the AOT
     codegen and registry.
   - This covers both the classic and GKR routes and every v3 layout (fused-tail, LS-D64, U8
     pairs, throughput Keccak).
   - Composition is 36% of CPU core time, so this is the largest piece.
2. **Witness on device, or a budgeted upload.**
   - v3 MAIN is about 3.0 G cells, roughly 12 GB.
   - At about 50 GB/s PCIe 5 per GPU, spread over 8 GPUs, that is about 30 ms each, which is
     acceptable as an interim step.
   - The proper fix is device fill, as in Cairo's 64 witness kernels.
   - The capture/advice payload is about 3 GB (v2 `native_payload`).
3. **Lifted-Merkle state expansion in CUDA.**
   - The existing kernel would hash about 30 G lifted cells per CPU segment (×2 on the LDE
     domain), instead of about 0.66 G native.
   - Add an "expand states ×2^k" kernel and absorb each height group at its native size, as in
     CPU `vcs_lifted/leaves.zig`.
   - Small change, large effect.
4. **An RV64 integration package**, analogous to cairo_cuda or circuit_cuda. It needs:
   - geometry and statement binding, arena plan, controller, and proof assembly into the RV64
     `proof_wire` format;
   - fresh native receiver acceptance;
   - a multi-proof scheduler: 7 CPU segments plus 6 truths for v3, spread over N GPUs with no
     peer access.
5. **Route choice for OM31/GKR.** If the 128-bit route is the target, then transcript, OODS, DEEP,
   FRI and decommit all need OM31 variants, plus fold-4 FRI and 256-query decommit:
   - ρ=1/4 doubles LDE and commit work relative to blowup 2;
   - 256 queries is about 3.7× the decommit/hash-path work of q70;
   - PoW 0 removes the grind.
   None of this exists. #311 supplies only the GKR numerical core.
6. **v3 GKR admission (CPU-side, in #310).** v3 fails closed (`GkrV3ServiceUnsupported`; see
   `rv64-pr308-v3-capture-20261102/gkr-rejection.log`). Only the 9 bulk/JUMPDEST kinds have an
   authenticated OM31 tuple authority and local GKR projection. Still open:
   - the remaining v3 CPU roles and OM31 truth adapters;
   - global mass and claim authority;
   - a v3 security re-budget (the v2 envelope model rejects v3 providers, throughput Keccak and new
     CPU pair layouts);
   - qualification of LS-D64, U8 pairs and throughput Keccak.
   Every new v3 family also needs a resident GPU tuple emitter for #311 to consume.
7. **Recursion latency.** The CUDA wrap+fold is 1.3–4 s on H200, for Cairo leaves only. RV64 needs
   its own GPU recursion, and its latency must be pipelined to meet a throughput target.

## 6. How #308 v3 services and layouts interact with #310/#311 GKR

- **Two incompatible security and protocol profiles.**
  - Classic: QM31 / q70 / P26 / blowup 2 / fold 1, nominal 96-bit. It proves full v3 in 37.71 s,
    with 7 CPU + 6 truth proofs and 5,411,549,280 MAIN+INTER cells.
  - OM/GKR: OM31 / ρ=1/4 / q256 / P0 / fold 4, 128-bit target under assumptions. It proves only
    the admitted v2 guest: 143.85 s, 44.76 M instructions, 11 CPU + 4 truth proofs.
  - Fused-tail INTER savings in #308's v3 layouts "are not automatically GKR savings" (#310 body),
    because GKR replaces committed interaction columns with sumcheck work.
- **#308's bits/gas metric (34,785) is a classic-route number.** Under GKR, interaction cells are
  not committed. The comparable GKR metric would be committed MAIN cells plus a GKR-variable cost.
- **v2 GKR receipt breakdown per CPU segment** (wall time, 8 threads):
  - `main_commit` about 2.8 s, `gkr` about 3.7 s (of which numerical about 3.4 s), stage 1 about
    7.4 s, stage 2 about 9 s.
  - Two truth workers run about 37 s each. They are the run's critical path, use no GKR, and #311
    does not touch them.
- **#311's engine is family-agnostic below the tuple plane.** It takes `D = offset − Σ coeff·tuple`
  with an explicit active mask, so v3 families plug in once a family has (a) the OM31 tuple
  authority in #310 and (b) a device tuple emitter. Today only bulk/JUMPDEST has (a), and nothing
  has (b).
- **#299** fixes `circuit_cuda` FRI leaf packing when the last round folds by one level
  (`InnerLayerCommitmentInvalid`). It is H100-verified, recursion-only, and has no RV64 interaction.

## 7. Recommendations for the < 2 s/block GPU goal

1. Build the first GPU RV64 block on the **classic route**, which already has qualified kernels for
   every stage:
   - port composition via a recording lane, then the lifted-hash expand kernel, then the RV64
     integration controller;
   - upload MAIN witness from CPU at first;
   - target one CPU segment (2²², about 0.7 G cells) on one H100/H200 with a fresh receiver.
   That gives the first real **RV64 GPU ns/cell** number, which no receipt has today.
2. Hold #311 until (1) exists and an OM31 PCS plan has been costed. Under ρ=1/4 and q256, the
   GKR route's GPU PCS cost per committed cell is at least 2× classic. That is only worth paying if
   its interaction-cell savings (about a third of cells) and the 128-bit target are required.
   Before tuning the sm_89/sm_120 fused variants, compile #311 for sm_90 and run its hardware
   harness on whatever GPU will hold the fleet.
3. **Scheduling.**
   - v3 is 13 proofs, and the two Keccak truths at about 0.7 G cells each are the largest units.
   - At 8 GPUs, about 1–2 proofs per GPU per block with cross-block pipelining. Fixed per-proof
     latency matters, since circuit R7 device time is about 50 ms against 0.56 s total.
   - Persistent per-GPU sessions with prepared static images, which the Cairo `--cuda-static-image`
     work showed is the main ingress win.
4. Keep capture and recursion off the per-block critical path by pipelining. "On average" permits
   it.

## Caveats

- The GPU numbers are single runs on rented H100/H200 for Cairo and circuit workloads, not
  distributions, and not RV64.
- #311 has no device execution. Every #311 performance number is a source model.
- The 45× lifted/native ratio comes from `classic-full-cost.json` (`lifted_leaf_cells` excludes
  blowup). The claim that the CUDA lifted absorb costs ∝ lifted cells comes from reading
  `commitment/progressive.cu` and `runtime/stages/commitment.zig` (states sized to the max height,
  no expand kernel). I have not measured it on a device.
- The CPU per-instruction comparison of GKR v2 and classic v3 mixes guests, security levels and
  proof inventories. It is indicative only.
