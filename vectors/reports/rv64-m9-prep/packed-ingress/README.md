# m9-packed-ingress receipts (L1a)

The design and integration plan are in `design/riscv-proving-stack/rv64-m9-packed-ingress.md`.

| file | contents |
|---|---|
| `corpus.txt` | corpus packing on the pod: ratios, block counts and single-thread host-unpack timing [M] |
| `bench.txt` | parity, negative cases and CUDA-event decode timings for the real, synthetic and edge-shape corpora [M] |
| `bench-real3.txt` | the same for the production-size node (actual CPU leaf statics ×3, 1.03 GB) [M] |
| `summary.json` | machine-readable numbers and the per-block projections [D/E] |

Corpora are not in git. The raw dumps are 327 MB and the containers up to 1 GB; they lived in `/dev/shm/m9pk` on the pod and in the session scratchpad, and both copies have been deleted. To regenerate them, follow §5 of the design doc.
| `review/review-bench.txt` | adversarial review rerun: old vs fixed decoder on shapes/synth, 2-GPU launch, table-undercount negatives, sanitizer [M]; see design doc §6 |
