# V7 CUDA numerical DEEP integration

Status: actual H200 numerical gates, real 32K/512K source proof parity and a complete 32K recursive root are qualified. Batched GPU LDE and the separate framework composition executor now also pass the complete-root byte oracle. This is an explicitly heterogeneous proof: CPU execution, witness, Blake3 commitments/transcript and subsequent FRI remain. It is not a resident GPU prover. ReleaseSafe is qualified; the new ReleaseFast CPU control fails native constraints and is explicitly not a qualified reference.

## Problem and selected mechanism

The retained mixed421 run spends 24.895 seconds in DEEP/FRI after the second CPU optimization (whole request 70.629 seconds at four workers). A full resident backend switch is not available: `CudaBackend` deliberately has no host column interface; `riscv_cuda.requireExecution` rejects execution. Existing resident commitment/transcript kernels implement Blake2s, whereas V7 uses Blake3. Existing typed secure-polynomial CUDA programs cover old word17/RAM23 interaction planes, not current RAM29/window31 or V7 native/caller equations.

The selected first vertical keeps the exact original PCS contract and uses the already implemented CUDA addressed numerator and compact-combine kernels. The PCS scheme receives an optional, proof-owned `QuotientExecutor`; null preserves the original backend. A non-null executor receives the original raw source columns, sample grouping, random-power-weighted line coefficients and lifting domain. It must fill the same four M31 planes. The unchanged generic Blake3 commitment and verifier consume those planes. Requested CUDA failures abort rather than selecting CPU arithmetic.

## Dataflow and bounds

1. Derive metadata from the original `LazyQuotientProvider`. Preserve every sample term, sign, random coefficient, sample-point grouping and original native-domain lift. Unsampled columns do not enter the numerical source roster. The initial executor rejects sampled log-zero columns, matching the existing CUDA minimum log and avoiding the host quotient path’s unsupported single-value lifting edge. Two-row constant columns are supported.
2. Check total device source, metadata, partial-numerator and result sizes before CUDA allocation. Device allocations are independently charged against the same explicit cap. Host metadata and temporary coefficient expansion have separate bounds and use the request allocator.
3. Upload each immutable source once. Compact coefficient sources are currently reconstructed on CPU, one column at a time, with explicit timing; this is host preparation, not a hidden GPU fallback. Upload exact line coefficients and topology.
4. Run original addressed numerator kernel over each group's native maximum domain, then original compact-combine kernel at the exact lifting domain. No transcript barrier is crossed or challenge rederived.
5. Synchronize, download four result planes, reject noncanonical field words, then run original CPU Blake3 commitment/FRI. Synchronize all outstanding transfers before releasing any staging lifetime, including error cleanup. Context is owned by one thread and cannot be reused after failed teardown.

No new CUDA kernel or JIT path is introduced. The archive build identity, device UUID/SM and provider identity are recorded; this identity is performance provenance, not proof authority. GPU correctness remains subject to exact numerical comparison and complete original proof verification.

## Qualification sequence

- Host metadata/differential gate: mixed column lengths, repeated samples, unused columns, compact coefficients and a two-row constant; exact output against original CPU quotient oracle. Reject insufficient device/metadata caps before CUDA allocation.
- Linux object gate: `src/riscv_cuda_numeric_codegen.zig`, `build-obj -target x86_64-linux-gnu -mcpu=baseline -OReleaseSafe -lc` through the repository module graph.
- Actual-device numeric gate: `src/riscv_cuda_numeric_device_test_root.zig`, linked to the exact native CUDA archive. Compare all output words, record transfers and actual kernel launches. GPU availability, provider/SM mismatch and budget failures are fatal.
- Complete V7 canonical proof: same input/config/statement/seed as CPU, complete proof-byte parity plus fresh independent verification after producer teardown. CPU and GPU arithmetic stage times remain separate; do not attribute CPU proof times to CUDA.
- Only then measure repeated end-to-end requests, including runtime startup, metadata/preparation, H2D/D2H, kernel time, CPU remaining stages, verification, host RSS and device peak. Stage speedup alone does not qualify a product speedup.

## Further resident work

FFT/LDE and FRI numerical kernels can reuse the same explicit execution ownership, but require their own byte/geometry gates. Full resident V7 additionally needs Blake3 commitment/transcript/PoW/decommit, exact current AIR exports/AOT, arbitrary-tree controllers, and composition split3 support or the independently qualified degree-bounded-q2 protocol. Existing Cairo/circuit GPU proof qualification does not qualify these missing pieces.

## H200 evidence and coefficient-expansion iteration

The fixed-source same-binary campaign uses source `ef0e1ff67c8d646001e145e378b86921b4abaa5dc207847b86ef3fe41a149775`, binary `0a1289c345efa37f50a04f95a17d93c6f6ca097c1415f00b2f4c24e759dda48a`, twelve CPU workers, q70/PoW26, sparse incoming-state admission, resident memory, degree-bounded-q2, 2GiB native MAIN cache and 4MiB DEEP metadata. A corrected x86 scalar M31 implementation is included; prior failed Linux controls are preserved rather than counted as GPU results.

| Declared retained window | CPU request | CUDA DEEP request | Proof contract |
|---|---:|---:|---|
| Native 32,768 cycles, one segment | 13.282s | 13.011s | All four original proofs byte-identical and independently verified |
| Native 524,288 cycles, two segments | 36.062s | 36.024s | All five original proofs byte-identical and independently verified |
| Native 32,768 cycles, complete recursive root | 175.419s | 252.836s | Exact 1,023,252-byte root; originals destroyed before independent global closure |

These are single quiet observations, not confidence intervals. The complete root SHA256 is `8ee14e8654e498f5c154dfc700a76cc8da1dbfbddb266c7cc7fd46ac9ccde400`. This proves a declared nonterminal window between externally admitted complete states; it does not prove the skipped prefix or an entire Ethereum block.

The parent CUDA callback takes 84.814s: **82.138s CPU coefficient expansion**, 2.568s upload, 57.5ms numerator/combine, 50.4ms download. It materializes 927 compact columns, uploads 19.084GB and retains 19.631GB of explicitly allocated device buffers. Host tracked peak remains 13.860GB. The underlying CPU parent DEEP/FRI stage takes 9.896s. This is a concrete preparation regression, not insufficient GPU arithmetic throughput.

The next implementation therefore preserves original source indices/term ordering while placing eligible same-height compact columns into contiguous device destinations. It uploads original compact coefficients into a reusable 128MiB scratch allocation and invokes the existing `stwo_lde_n2b_columns_on` kernel in bounded batches. One canonical twiddle tower is derived under the request allocator and reused across heights. Full output, coefficient scratch, twiddles and descriptors count toward the explicit device cap before allocation. Unsupported tiny log shapes remain declared CPU materializations; they cannot silently replace the requested numerator/combine kernels. Expansion launch count/time and GPU/CPU expanded-column counts are separate receipt fields.

Host gates cover a same-height multi-column batch, multiple heights, exact CPU-oracle quotient output, tiny CPU materialization and device/host/scratch cap rejection. Actual NVIDIA differential passes the same six-source fixture: three GPU-expanded columns, one explicitly CPU-expanded tiny column, ten expansion launches plus two quotient launches. Device binary `3153bbee6f81c7261fe02268d386e726bc64da892d3ed0bae58bc69e7f626e03` binds source `270a62b6e8d06363208524c7c17a9c1e463fd1e62b411789b71f2cca5b92a5f0`. The small log3/log5 fixture does not cover the production large-log fused transform schedule; the separate complete-root gate below supplies that qualification.

That large-log obligation subsequently passed using source `cdd1a8cff51fa0d3e947f6935174637437f656bf394ba2e003d1270758850383`, ReleaseSafe binary `3e5678d213fe1622b98837d02b80551e728afe4b593a10d7fb35745e3fa9df02`, and serial family preparation for both CPU and GPU. The CPU request takes **184.198s**, GPU DEEP plus composition **153.889s** (one quiet pair, 1.197× request speedup). Both reproduce the same `8ee14e…` root and fresh global verification after original proof destruction. The GPU parent DEEP callback takes **1.310s** instead of the first adapter's 84.814s: all 927 compact columns are expanded on GPU, none on CPU; 354 expansion launches take 92.2ms, numerator/combine take 57.4ms, and 9.750GB upload takes 1.084s. The independent composition callback covers all 25 components, takes 3.766s including 2.650s upload, and performs 919 GPU expansions with zero CPU recoveries. Request tracked host peak drops from 13.860GB to 13.463GB. These callback times are nested inside request time and must not be added again.

The corresponding ReleaseFast binary fails the CPU-only native proof before GPU execution (`ConstraintsNotSatisfied`). Its failed invocation is retained; no GPU speedup or qualification is derived from it. A separate early ReleaseSafe/preparation4 run was deliberately interrupted when the experiment was changed to preparation1; it is retained as interrupted, not included in paired results.

Durable machine-readable evidence is under `vectors/reports/riscv-cuda-numeric-deep-20261030/h200-campaign/` (`index.json`, `runs.csv`, `stages.csv`, `gpu-calls.csv`), with all saved proofs, receipts and raw NVML logs in adjacent `h200-fixed-proofs/` and `h200-paired-results/`. `scripts/v7_cuda_campaign_results.py` reads those artifacts without mutating the CPU corpus. Inclusive stage rows must not be summed with their parents. Explicit device allocation peaks differ from independently sampled NVML device usage.
