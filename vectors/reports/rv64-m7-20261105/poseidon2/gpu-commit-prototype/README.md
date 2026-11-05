# Measured native GPU commitment hash go/no-go

**NEGATIVE prototype result.** Source P2 CUDA leaf/parent kernels are46–51x slower than the production prefixed Blake CUDA APIs on this RTX5090. This is an immature kernel measurement, not an intrinsic lower bound for Poseidon.

Same canonical M31 column-major slab and row count; every Merkle layer retained. Both use a fused upper tail at1024nodes. CUDA events isolate resident slab to root, excluding allocation, data generation, H2D/D2H, FFT/LDE, statement/FS, openings and proof generation. This is not end-to-end request performance.

Independent dense Python official-parameter KAT and all retained-node CPU parity passed at widths1/12/13/47/128/479 over8rows for both suites. Production P2 backend remains unselected. Larger timings repeat deterministic GPU roots; full CPU reconstruction of million-row trees was not performed.

| columns | log rows | Blake ms | P2 ms | P2/Blake | Blake GiB/s | P2 GiB/s |
|---:|---:|---:|---:|---:|---:|---:|
| 47 | 14 | 0.039584 | 2.022400 | 51.09 | 72.47 | 1.42 |
| 128 | 14 | 0.047840 | 2.408192 | 50.34 | 163.30 | 3.24 |
| 479 | 14 | 0.079552 | 4.005216 | 50.35 | 367.51 | 7.30 |
| 47 | 17 | 0.066816 | 3.193728 | 47.80 | 343.47 | 7.19 |
| 128 | 17 | 0.095744 | 4.708192 | 49.17 | 652.78 | 13.27 |
| 304 | 17 | 0.169600 | 8.014496 | 47.26 | 875.22 | 18.52 |
| 479 | 17 | 0.234592 | 11.074976 | 47.21 | 996.99 | 21.12 |
| 128 | 20 | 0.441408 | 20.910273 | 47.37 | 1132.74 | 23.91 |
| 479 | 20 | 1.364736 | 63.108578 | 46.24 | 1371.03 | 29.65 |

Two warmups followed by five measured repetitions, alternating suite order. GPU-s equal CUDA-event seconds because this uses one physical GPU. The retained-tree storage overhead is36/32=1.125x pernode. P2 leaf uses78registers and tail80, with zero compiler spill bytes.

Build used nvcc -O3 -std=c++17 -gencode arch=compute_120,code=sm_120 -Xptxas=-v, source rv64/poseidon_commit_bench.cu, includes native/{rv64,commitment}, linked exact library hash in receipt; compiler diagnostics preserved in build.log. The negative supports no-go for this current native kernel as a fast commitment backbone. A 32-bit reduction implementation is a separate upcoming falsifier; no model speedup is assumed.

LDE is shared arithmetic and deliberately excluded. Its cost must be added using actual source width/log and native FFT measurements; no borrowed generic FFT budget is presented as measured.
