# M8 poseidon-witness: Poseidon2-W24 kernel pass and recursion-backbone decision

Stream `codex/rv64-m8-poseidon-witness`. No default, profile or production
path change. Decision note: `design/riscv-proving-stack/rv64-m8-recursion-backbone.md`.

## Kernel [M]

`src/backends/cuda/native/rv64/poseidon2_m31_fused.cuh`
(sha256 `099f2b0954cb5e3df7b19073584a9552ab20d12489d2212506d7d1110e294de0`),
selected only by `-DSTWO_P2_FUSED` in the numerical smoke/bench.
479 x 2^20 retained Merkle tree, RTX 5090, CUDA events, median of 5:
**15.957 ms (M7 common-rotate) -> 11.833 ms (1.35x)**; register-packed
15.195 ms; Blake2s control 1.367 ms. All nine classes: 1.35-1.60x. Roots are
byte-identical across variants; every retained node matches the independent
CPU reference at 8 rows for widths 1/12/13/47/128/479; numerical KATs pass;
compute-sanitizer memcheck 0 errors (smoke and a 479 x 2^12 tree).

- `kernel-ab.json`: the full A/B (variants `rotate` = M7 common-rotate
  control, `register` = register-packed v1 (deleted from source; built from
  5a93c2449, header sha256 `82e9e5455a37bcb85de5691b9d31f7fe68d08d2e189708bd1c85aa15cdcdfd09`), `fused` = commit cf063e605
  intermediate, `fused2` = this header), with binary SHA-256s.
- `pipes.json`: the sm_120 integer-pipe probe that explains the result.
- `backbone-cost.json`: net GPU-s per block for all-Poseidon and mixed
  backbones (`scripts/rv64_m8_poseidon_backbone_cost.py`).
- `qm31-straightline.json`: host program-order QM31 evaluation proxy.

Raw logs and binaries stay on the pod:

| artifact | path | sha256 |
|---|---|---|
| A/B log | `/workspace/m3/runs/m8-poseidon-witness/kernel-ab-v2.log` | `6d0722c1831722e814d04d8f0fd91719503f46aec6c255819baa2df335f71c42` |
| sanitizer smoke | `/workspace/m3/runs/m8-poseidon-witness/sanitizer-fused2.log` | `971918667f1a9507326491df7ddb5f05c5fadf104fc961b2c5329e76864d8ee2` |
| sanitizer tree | `/workspace/m3/runs/m8-poseidon-witness/sanitizer-bench-fused2.log` | `9bd1d465a294889edb5941a79f455165527e9c70001df3e12674621dc59ae7a8` |
| bench binary | `/workspace/m3/build/m8-poseidon-witness/final/bench-fused2` | `0e37a6a4f17472019fa05c06ac072c84f19821a56a0b4b1899cea75ed410522b` |
| smoke binary | `/workspace/m3/build/m8-poseidon-witness/final/smoke-fused2` | `9337617ad4eb21c959b313cc2d8e1d7d49ee0dab137d14f574ed6b782a172296` |
| control header (generated) | `/workspace/m3/build/m8-poseidon-witness/base/gen/poseidon2_m31_fast.cuh` | `ce4e500faeb446eb332d4f3e6a958be04fc183072ea525f356977cab14d1c69c` |

Build recipe (pod, CUDA 12.8, any free `build.{1,2,3}.lock`; Blake control
links the frozen `m7-combined-residency` library read-only):

```sh
INC="-I src/backends/cuda/native -I src/backends/cuda/native/rv64 -I src/backends/cuda/native/commitment"
LIB=/workspace/m3/build/m7-combined-residency/cuda/native
nvcc -O3 -std=c++17 -arch=sm_120 $INC -DSTWO_P2_FUSED tests/cuda/rv64/poseidon_commit_bench.cu \
  -L$LIB -lstwo-rv64-native -Xlinker -rpath=$LIB -o bench-fused2
nvcc -O3 -std=c++17 -arch=sm_120 $INC -DSTWO_P2_FUSED tests/cuda/rv64/poseidon2_m31_smoke.cu -o smoke-fused2
python3 scripts/rv64_m8_poseidon_fused_bench.py --bins <dir> --variants rotate fused2 --out <receipt>
```

The control `rotate` uses `-DSTWO_P2_FAST_REDUCTION -I<gen>` with
`scripts/rv64_m7_poseidon_fast_reduction.py --variant common-rotate`.

## Not claimed

Retained-tree hashing only: no FFT/LDE, transfer, transcript, PoW, openings,
native S2 profile, recursive proof, receiver or request time. Backbone GPU-s
are a cell-linear model over committed censuses [D/E].
