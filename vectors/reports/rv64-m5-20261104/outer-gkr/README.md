# Stream outer-gkr, M5 iteration: outer LogUp-GKR section `outer_gkr_om31_strict_v1` (24628607)

Off by default: no request run uses it yet (the hook in canon-vk's files is proposed in `/workspace/m3/M5-INTERFACES.md`, section
outer-gkr). Labels: **[M]** measured here, **[D]** arithmetic on measured inputs (`scripts/rv64_m5_outer_gkr_census.py`), **[E]** model.
Argument: `design/riscv-proving-stack/rv64-m5-outer-gkr.md`.

| | CPU leaf class (node 0) | fold class (node 20) |
|---|---:|---:|
| committed cells today: PP + main + OM31 interaction [M] | 1,940.0 M (176 + 585 + 1,180) | 1,715.0 M (136 + 519 + 1,061) |
| committed cells with outer GKR, own [D] | **1,101.1 M (×0.568)** | **901.3 M (×0.526)** |
| GPU GKR prover, plain route, tree + traversal (median of 3, CUDA events) [M] | 182.3 ms (28.0 + 154.3) | 174.9 ms (26.7 + 148.2) |
| GPU GKR prover, fused fold+next-sum route (median of 5), byte-identical section [M] | **148.2 ms** (28.0 + 120.2) | **143.2 ms** (26.7 + 116.6) |
| GKR fractions / kernel calls / device bytes [M] | 257.9 M / 5,515 / 26.9 GB | 246.4 M / 5,337 / 25.8 GB |
| in-circuit verifier (valid circuit on the GPU-proved section) [M] | G 195,200, qm31 223,203, m31→u32 20,360, triple-XOR 19,520, eq 1,581; 432 strict draws | G 193,600, qm31 219,570, … |
| in-circuit verifier cells per verified child, today's widths [D] | 40.9 M (2.1 % of the leaf; kill line 25 %) | 40.5 M |
| section bytes [M] | 69,812 | 69,300 |
| fresh receiver on the GPU section [M] | accepted (terminal vs independently regenerated inputs) | accepted |

Tree, 33 nodes [D]: 53.39 G → **30.29 G** (today's widths in the parents) / 30.0 G (parents also on GKR widths), i.e. ×0.57/×0.56,
including the in-circuit verifier and the 176 fewer columns each parent opens per child. The model reproduces the measured
M4.0 totals exactly (interaction 32.617 G, total 53.391 G). GPU [D]: 4.8 GPU-s of GKR added (fold-sum route; 5.9 plain) vs 11.2 GPU-s removed at the M4.0
all-in rate (0.235 ns per LDE cell, b2): net ≈ −6.4 GPU-s of today's 25.1 recursion kernel GPU-s. Proof [E]: +69.8 KB section,
−76 KB of interaction openings at q = 108 → roughly neutral (−6 KB).

Correctness: GPU section **byte-identical** to the CPU reference prover (test-small class) [M]; 16/16 Zig tests (pod,
ReleaseSafe; review adds the edge-input completeness test; incl. the binding-column CPU reference at the real GKR point); exhaustive in-process single-word tamper sweep **3,469/3,469 rejected**; fresh-process corpus **28/28** (after the review fix: + G18/G18f class substitution)
(`outer-gkr-corpus.json`: header, salt, roots, poles, round coefficients (M01), leading-zero shape, masks, instance order,
non-canonical, truncation, terminal vs other inputs (M02), closure, and 3 tampers of the GPU-proved production leaf).

Not measured: end-to-end recursion with the flag on (needs hook H1–H5), the GPU time of the removed classic interaction work
itself (only the all-in [D] rate), the real root proof size.

| file | what |
|---|---|
| `24628607-outer-gkr-receipt.json` | headline receipt |
| `24628607-outer-gkr-census-foldsum.json` | same census with the fold-sum GPU route |
| `raw/routes-*.log`, `raw/*-bench-{plain5,foldsum,tail}.json` | route comparison (plain / fold-sum / tail), cmp byte identity |
| `24628607-outer-gkr-census.json` | per-node cells before/after (33 nodes), per-child parent deltas, tree factors |
| `outer-gkr-corpus.json` | fresh-receiver corpus, one process per case |
| `raw/leaf.log`, `raw/fold.log`, `raw/leaf-verify.log` | GPU bench + receiver + cost runs (load average and GPU clocks at start) |
| `raw/*-bench.json`, `raw/*-cost.json`, `raw/pp-by-node.json` | census inputs |
| `raw/test4.log`, `raw/tests-14.txt`, `raw/corpus.log`, `raw/cuda-build.log` | test and build logs |
