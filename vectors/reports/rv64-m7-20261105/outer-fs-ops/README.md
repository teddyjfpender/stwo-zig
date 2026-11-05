# M7 outer Fiat–Shamir lookup-parameter kernel

Status: **206/206 GPU checks pass across both RTX 5090s; CUDA memcheck reports zero errors.** This qualifies only the additive lookup-parameter helper. It does not qualify full device Fiat–Shamir, the recursion consumer, request performance or fewer blocking calls.

`stwo_rv64_outer_fs_lookup_params_on` derives the existing 56-word `Witness.Elements` layout from two resident OM31 draws: `z`, followed by `alpha^0` through `alpha^5`. The extension tower and coordinate order match Core OM31. The API validates live context ranges and rejects writable overlaps before enqueueing one kernel on the selected lane. It allocates nothing and does not synchronize. A noncanonical coordinate sets status bit 0 without clearing existing bits or writing output. The Zig owner remains responsible for generation, scope and publication checks; native pointer validation alone does not establish those properties.

The CPU corpus is emitted by the repository's Core OM31 implementation using the checked-in independent reference program. Each GPU checks 84 zero, one, boundary, basis and deterministic random cases against all 56 output coordinates. Each also checks eight noncanonical inputs with preserved status/output sentinels and eleven invalid-pointer, size, overlap, context and lane cases. The harness joins deliberately for observation; those fixture joins are not evidence about the production callback count.

The 1,068,752-byte optional addon links to frozen selected image `a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45`. Addon SHA-256 is `2b94d8c11c157eeea61e071f5ecc8acb81f4d12a70790a1ca878d9ca8130ab7a`. This avoids copying the 1.98 GB base image on the disk-constrained pod. It is not yet a replacement production image. Build commands, post-build dependency inventory, Core corpus and artifact hashes are in `build.json`; that inventory is explicitly not a transactional before/after source attestation.

Reproduce on the pod with:

```sh
python3 scripts/rv64_m7_outer_fs_ops_fixture.py \
  --base /workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so \
  --addon /workspace/m3/build/m7-outer-fs-ops/libstwo-rv64-outer-fs-ops.so \
  --reference /workspace/m3/build/m7-outer-fs-ops/core-reference.bin \
  --out /workspace/m3/runs/m7-outer-fs-ops/fixture.json
```

For memcheck, prefix that command with `/usr/local/cuda/bin/compute-sanitizer --tool memcheck --error-exitcode 99` and use a separate receipt path. The harness owns `gpu.lock`; do not nest another lock around it. The fixture disables the device arena and uses one lane per context, so it establishes neither arena reuse nor concurrent proof admission. Raw logs and both successful receipts are retained here.
