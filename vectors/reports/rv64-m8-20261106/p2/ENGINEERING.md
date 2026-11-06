# P2 standalone compile handoff

Status: CPU formula/static checks **PASS**; CUDA smoke and benchmark compilation **PASS**; selected numerical KATs **PASS on both RTX 5090s**. Throughput, sanitizer, S2 and whole-proof qualification remain open. See `cuda-compile.json` and `cuda-numerical.json`; raw logs stay on the pod by SHA-256.
The new header and both CUDA tests are stable for the owner's snapshot.
`source-manifest.json` pins every required compile input. Raw build logs and
compiler diagnostics remain on the pod; retain their SHA in compact receipts.
These commands compile only and do not execute GPU work.

Use a new immutable directory containing the manifest files at their original
relative paths. Example concrete locations (owner may rename the snapshot):

```sh
P2_SRC=/workspace/m3/src/m8-p2-standalone-b68e02081
P2_OUT=/workspace/m3/build/m8-p2-standalone-b68e02081
mkdir -p "$P2_OUT"
```

Candidate smoke, including unchanged v1 transcript reference KATs:

```sh
flock -w 3600 /workspace/m3/locks/build.2.lock /usr/local/cuda/bin/nvcc -O3 -std=c++17 -gencode arch=compute_120,code=sm_120 -Xptxas=-v -DSTWO_P2_REGISTER_PACKED -I"$P2_SRC/src/backends/cuda/native" -I"$P2_SRC/src/backends/cuda/native/rv64" "$P2_SRC/tests/cuda/rv64/poseidon2_m31_smoke.cu" -o "$P2_OUT/smoke-register"
```

Candidate retained-tree benchmark with independently compiled frozen Blake
controls, no shared runtime dependency:

```sh
flock -w 3600 /workspace/m3/locks/build.2.lock /usr/local/cuda/bin/nvcc -O3 -std=c++17 -gencode arch=compute_120,code=sm_120 -Xptxas=-v -DSTWO_P2_REGISTER_PACKED -I"$P2_SRC/src/backends/cuda/native" -I"$P2_SRC/src/backends/cuda/native/rv64" -I"$P2_SRC/src/backends/cuda/native/commitment" "$P2_SRC/tests/cuda/rv64/poseidon_commit_bench.cu" "$P2_SRC/src/backends/cuda/native/commitment/merkle.cu" "$P2_SRC/src/backends/cuda/native/commitment/progressive.cu" -o "$P2_OUT/bench-register"
```

Original control: repeat those two commands without
`-DSTWO_P2_REGISTER_PACKED`, using output names `smoke-original` and
`bench-original`. Historical common-rotate control generation:

```sh
python3 "$P2_SRC/scripts/rv64_m7_poseidon_fast_reduction.py" --variant common-rotate --out "$P2_OUT/poseidon2_m31_fast.cuh"
```

Then repeat the two commands replacing `-DSTWO_P2_REGISTER_PACKED` with
`-DSTWO_P2_FAST_REDUCTION -I"$P2_OUT"`, using output names `smoke-common-rotate`
and `bench-common-rotate`. Do not define both selectors. The benchmark reports
`generated-fast-reduction` for generated variants; pin the generated header
SHA and generation selector to distinguish common-rotate from fast32.

Required compile inputs (all listed with hashes in the manifest):

- `tests/cuda/rv64/{poseidon2_m31_smoke,poseidon_commit_bench}.cu`
- `src/backends/cuda/native/rv64/{poseidon2_m31,poseidon2_m31_register}.cuh`
- `src/backends/cuda/native/common/m31.cuh`
- `src/backends/cuda/native/commitment/{merkle,progressive}.cu`
- `src/backends/cuda/native/commitment/{blake2s_core,blake2s_protocol,progressive_scalar,resident_layout}.cuh`
- `src/backends/cuda/native/commitment/{blake2s_domain_states,mixed_layout}.h`
- `scripts/rv64_m7_poseidon_fast_reduction.py` for the historical control only

No GPU qualification command is authorized by this handoff. Owner schedules
KATs, retained-tree parity, sanitizer, register/spill review and matched GPU
measurements after the ordered P1/P3 gates. New implementation remains off.
No native S2, fresh-CPU acceptance or end-to-end gain is claimed.
