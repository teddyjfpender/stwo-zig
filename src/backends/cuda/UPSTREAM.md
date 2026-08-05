# CUDA source authority

The CUDA product no longer carries a 1,003-file Rust/CUDA workspace snapshot.
It retains only the 28-file transitive source closure used by the Zig-owned
product, witness generator, embedded inputs, and resident derivation checks:

- repository: `https://github.com/teddyjfpender/stwo`;
- branch: `perf-optimizations`;
- commit: `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`;
- repository tree: `55cbec6c408dfc4e81c722deca9f5526d3785536`;
- kernel subtree tree: `044f995e98ba6f2fdb5a1634a99c14927d7a93c0`;
- active closure: `authority/active`, 28 files, 295,636 bytes; and
- active closure SHA-256: `99f8b738f505fe450c8ff37ec2ea389df248f56a8cc770b02fc9cf070e872065`.

`active_source_manifest.json` authenticates every retained byte. Two upstream
headers lacked a final newline; their normalization is explicit in that
manifest. Repository-owned runtime, ABI, manifests, generators, and strict-AOT
loaders remain outside the imported closure.

## External audit authority

The complete upstream projection remains reproducible without occupying the
main repository:

| Projection | Files | Bytes | Closure SHA-256 |
| :--- | ---: | ---: | :--- |
| Host workspace | 1,003 | 44,877,364 | `8592124d6ad17610e23171fa7160030f8f76e21f4deff35e76699de8ad515341` |
| CUDA kernel subtree | 458 | 33,508,731 | `63c7503f83ed467fdcf010be867b0f395ace8a4a0d1d11572112ce7405cbbe2b` |

`host_source_manifest.json` and `source_manifest.json` are the immutable file
manifests; `product_manifest.json` pins the bytes of both manifests as well as
their advertised closures. Materialization fetches the exact commit, verifies
both Git trees, copies only the manifest-listed files, and then verifies both
content closures:

```sh
zig build cuda-authority-materialize

# Or choose an explicit audit directory.
python3 scripts/cuda_external_authority.py materialize \
  --output /absolute/path/to/cuda-host-authority \
  --receipt /absolute/path/to/authority-receipt.json
```

An existing projection can be checked without network access:

```sh
python3 scripts/cuda_external_authority.py verify \
  --output /absolute/path/to/cuda-host-authority
```

The isolated Rust adapter is an explicit migration/oracle tool, not a release
or ordinary CI dependency. `zig build test-cuda-adapter` materializes the
authority and rewrites a temporary copy of the adapter to that exact workspace.
The checked `tools/stwo-cuda-adapter-rs/Cargo.toml` is therefore provenance, not
a directly runnable in-tree Cargo product.

## Generated AOT policy

The 33 recorded-witness CUDA bodies are generated into Zig's build cache from
`vectors/cairo/sn_pie_2_witness_programs.bin`. Their checked manifest binds the
program identities, semantic hashes, cache keys, kernel names, and emitted
source hashes. The 271 Cairo evaluation bodies follow the same cache-resident
policy from `vectors/cairo/sn_pie_2_composition.bin`.

The 340 AOT bodies in the external authority are reference inventory only and
never enter a Zig-owned CUDA archive. Do not copy any of these generated
populations back into source control.

## Update rule

An upstream update is one reviewed authority change. It must refresh the full
manifests, derive and authenticate a new minimal active closure, regenerate the
ABI symbol pin, pass the host-independent product gates, and obtain fresh
NVIDIA qualification before production status changes. CuMetal evidence is an
Apple-Silicon development aid and cannot replace NVIDIA acceptance.
