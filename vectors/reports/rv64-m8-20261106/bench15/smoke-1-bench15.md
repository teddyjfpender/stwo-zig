# RV64 M8 15-block benchmark

proving = service request wall incl. witness generation, excl. fetch/submit. Warm/cold = median over headline services [M].
M3 = one request per block (`rv64-m3-20261104`) [M]; M7 = default warm where measured [M].

| block | Minstr | seg | M3 s | M7 s | default warm / cold s | status |
|---|---:|---:|---:|---:|---:|---|
| 26235156 | 15.3 | 4 | 34.3 | 10.5 | 10.28 / 23.33 | done |
| 24647140 | 24.6 | 6 | 48.2 | - | - | not_run |
| 24628607 | 26.9 | 7 | 51.1 | 12.9 | - | not_run |
| 25229957 | 27.1 | 7 | 53.8 | - | - | not_run |
| 24628608 | 38.6 | 10 | 60.3 | - | - | not_run |
| 24626900 | 49.1 | 12 | 68.3 | - | - | not_run |
| 24697073 | 60.4 | 15 | 84.6 | - | - | not_run |
| 24697070 | 57.8 | 14 | 86.4 | 69.9 (cold) | - | not_run |
| 26235168 | 113.4 | 28 | 145.4 | - | - | not_run |
| 25229955 | 122.5 | 30 | 147.7 | - | - | not_run |
| 25229951 | 165.9 | 40 | 179.0 | - | - | not_run |
| 24628590 | 157.6 | 38 | 186.0 | - | - | not_run |
| 24628595 | 172.8 | 42 | 213.3 | - | - | not_run |
| 24628611 | 187.7 | 45 | 234.3 | - | - | not_run |
| 26235159 | 204.8 | 49 | 250.5 | - | - | not_run |

| arm | blocks | warm sum s | cold sum s | M3 sum s (same blocks) | warm / M3 [D] |
|---|---:|---:|---:|---:|---:|
| default | 1 | 10.3 | 23.3 | 34.3 | 0.300 |

## Warm critical path per arm

| block | arm | capture | setup | native window | recursion after native | tail [D] | kernel GPU-s | GPU busy [D] | per-node peak GB | launches/node | syncs/node |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 26235156 | default | 1.78 | 0.12 | 3.36 | 5.00 | 0.02 | 8.16 | 38% | - | 2789 | 121.3 |

launches/syncs per node: job receipts (`GPU_M8_OUTER_NODE launches/host_waits`) where the arm runs OuterNodeJobs [M], else Nsight `cudaLaunchKernel`/`cudaStreamSynchronize` in the profiled warm window / nodes [D]. per-node peak: job arena peak words x 4 B [D]. GPU busy: CUPTI kernel union / (2 GPUs x profiled window) [D].
