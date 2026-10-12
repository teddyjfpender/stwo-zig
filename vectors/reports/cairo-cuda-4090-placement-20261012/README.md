# Cairo CUDA 24 GB placement experiment — 2026-10-12

This experiment tests whether the current managed-memory policy, rather than sparse proof opening, limits dense Cairo PIE proofs on a small GPU. The source was `bf3a4b005a8d5a5bd643b21bc70f8782e0bf23c1` (PR #232); the measured production kernels were unchanged. The host was a Runpod RTX 4090 (`sm_89`, 25,252,724,736 bytes of device memory, 31 GB container RAM), CUDA 12.8, Zig 0.15.2, `ReleaseFast`, and the canonical preprocessed asset. The CUDA preflight passed. The pod was deleted after receipts were copied here.

Both inputs are ten-block, adapted `.cpi` files from the contiguous proving-service campaign. `15578440_15578449` has 4,281,672 steps and a 31.71 GiB planned arena; `15578420_15578429` has 1,987,048 steps and a 24.96 GiB planned arena. Each result is one otherwise-idle, cold command invocation, including input preparation, static initialization, proof execution, output publication, and process overhead. The whole-device peak is sampled every 250 ms. The stage times are the prover's CUDA device intervals; they need not sum to command wall time.

| PIE | Placement | Full command | Published proof | Device peak | Process RSS peak | Trace generation | Trace commitment |
|---|---|---:|---:|---:|---:|---:|---:|
| `15578440_15578449` | capacity (control) | 95.622 s | 93.547 s | 17.64 GiB | 18.50 GiB | 15.334 s | 51.559 s |
| `15578440_15578449` | interaction coefficients in HBM | 80.543 s | 78.601 s | 19.51 GiB | 16.61 GiB | 15.219 s | 36.710 s |
| `15578440_15578449` | interaction coefficients in HBM; 50% main evaluations and writer scratch host-backed | **66.727 s** | **64.879 s** | **22.26 GiB** | **14.31 GiB** | **7.884 s** | **30.663 s** |
| `15578440_15578449` | throughput | 52.208 s | 50.118 s | 23.52 GiB | 18.50 GiB | 2.546 s | 20.620 s |
| `15578420_15578429` | capacity (control) | 64.809 s | 63.169 s | 15.39 GiB | 13.52 GiB | 6.870 s | 32.101 s |
| `15578420_15578429` | same balanced placement | **47.578 s** | **45.915 s** | **17.89 GiB** | **11.39 GiB** | **4.200 s** | **18.031 s** |
| `15578420_15578429` | throughput | 33.212 s | 31.466 s | 23.52 GiB | 11.51 GiB | 1.562 s | 5.927 s |

The balanced placement reduces full command time by **30.2%** on the larger PIE and **26.6%** on the smaller one. It leaves about 1.26 GiB of device headroom on the larger case. The throughput policy is faster but fills essentially the entire device in both cases (25,251,807,232 bytes observed against 25,252,724,736 available), so it is not a robust 24 GB setting. A selective-main-evaluations policy failed with a container-RAM OOM on the larger PIE and is not a valid candidate. A 5% host hint on main coefficients did not lower the throughput policy's device peak.

All successful runs for a given PIE produced the **same proof bytes**: SHA-256 `7556e5f4e8559da72ae4767761b2e3741059e91b0a92c100892a43b11aa8f489` for the larger PIE and `d8f4885f5443c35e7259bd9938e69bbec9329e12a73fb3263f872ca10390fa7b` for the smaller. The pinned official Rust verifier accepted the larger control and throughput proofs and the smaller balanced proof; byte identity extends that verification to the other successful placement runs. Proof parameters remained canonical: Blake2s, 70 queries, 26 query PoW bits, and 24 interaction PoW bits.

## Reproduce the balanced policy

Set these on the existing CUDA prover process; `STWO_CAIRO_CUDA_ARTIFACT_DIR` and `STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS` must point to the authenticated canonical assets. Launch from the repository root because this CLI revision also resolves an AOT artifact relative to its working directory.

```sh
export STWO_CUDA_MANAGED_ARENA=1
export STWO_CUDA_MANAGED_PLACEMENT=capacity
export STWO_CUDA_CAPACITY_HBM_SLOT=interaction_coefficients
export STWO_CUDA_CAPACITY_MAIN_EVAL_HOST_PERCENT=50
export STWO_CUDA_CAPACITY_WRITER_SCRATCH_HOST_PERCENT=50
./zig-out/bin/stwo-cairo-cuda prove --backend cuda \
  --input /absolute/path/to/prover_input.cpi \
  --input-sha256 <SHA256_OF_CPI> \
  --output /absolute/path/to/proof.json \
  --report-out /absolute/path/to/report.json
```

This is a **qualified experimental profile for the two listed geometries**, not an automatic default for arbitrary PIEs. Before using it for a new geometry, measure whole-device peak and exact proof verification. The result identifies the next code target: make hot trace-commitment and writer buffers resident within an explicit HBM budget, rather than relying on the aggressive throughput policy's implicit near-full-device occupancy.

## Rejected sparse-opening hypothesis

A parallel per-column trace-opening gather compiled for `sm_89` and produced a byte-identical, Rust-verified proof. It reduced the decommit CUDA interval from 0.027 to 0.023 seconds on the larger PIE. The approximately 0.75-second full-command difference is below the noise floor of one cold run. Trace commitment, at 51.56 seconds in the control, was the actual dominant stage. The gather kernel and its intrusive timing hook were therefore **not retained** in production source. The hook caused a strict-residency failure by adding synchronizations, so its per-tree timings are diagnostic only; the valid baseline and candidate runs had it disabled.

The `receipts/` directory contains the unmodified per-run summaries, prover reports, GPU/RSS samples, process logs, and available Rust-verifier verdicts. Proof JSON files are omitted; their exact digests are retained in each successful report. `cuda-preflight.json` records the device feature check.
