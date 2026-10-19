# Detached leaf Tree0 key-only checkpoint

The leaf implementation at `3e0715f4a` reconstructed the complete outer
preprocessed commitment from a serialized detached key without loading a
native or outer proof. This is evidence for the leaf portion of G-8(c), not a
claim that RISC-V recursion is soundness-qualified. The parent fixed tree and
G-8(a)'s consistently re-proven hostile native proof remain open.

The 1/2/4/8-leaf q193 setups used the pinned manifests below. Key setup
generated and freshly verified each native proof, prepared its detached leaf,
then compared **all 39** independently reconstructed fixed-row digests and
the complete commitment root against production. A separate invocation of
`recursive-segment-v2-leaf-key-rebuild` loaded only each generated key and its
independent SHA-256 pin; all 15 invocations exited 0 with
`proof_loaded=false`. The exact key pins and roots are in [receipt.tsv](receipt.tsv).

| Leaves | Manifest | SHA-256 |
| ---: | --- | --- |
| 1 | `vectors/reports/riscv-recursion-20261018/q193-native-transcript-checkpoint/setup-manifest.json` | `0ae6f1dd9821c32fe03c618c98c2abc9d24e9672b9c99f05ccaa86195d046dcf` |
| 2 | `vectors/reports/recursive-product-20260918/larger-workload-admission-v1/admission-2-seed14/setup-manifest.json` | `c80a086c99505cf1524bfaec80f7f684da7577b2810d42fe89ab979cd6a856ee` |
| 4 | `vectors/reports/recursive-product-20260918/larger-workload-admission-v1/admission-4-seed13/setup-manifest.json` | `b77c64684e697a15f415ae22d592868a9e7ebd9ee293cd06f17fcf44db2417fb` |
| 8 | `vectors/reports/recursive-product-20260918/larger-workload-admission-v1/admission-8-seed14/setup-manifest.json` | `ccd48d5fbadb25aee55325f60a24ba9a9f4f7226ebca00ffefbc502a5282beab` |

On this host, the key-setup executable SHA-256 was
`39e7b5c236c03aca1f5a6fcdc1a6bd2699f0c1cf4283ff59359b90fbc90227c0`;
the separate key-only executable SHA-256 was
`061a2a5533e73dba08a6407f8e06c800a4078c49d6669ca59b627cd19d0abdff`.
Both were ReleaseSafe builds. The first command below reproduces the
one-leaf case from the repository root; use another table row and a new
output path for the other rosters.

```sh
zig build --build-file src/integrations/riscv_cpu/build.zig build-recursive-segment-v2-leaf-key-setup build-recursive-segment-v2-leaf-key-rebuild -Doptimize=ReleaseSafe -j2
src/integrations/riscv_cpu/zig-out/bin/recursive-segment-v2-leaf-key-setup \
  vectors/reports/riscv-recursion-20261018/q193-native-transcript-checkpoint/setup-manifest.json \
  0ae6f1dd9821c32fe03c618c98c2abc9d24e9672b9c99f05ccaa86195d046dcf \
  /tmp/stwo-riscv-leaf-tree0-new-output
src/integrations/riscv_cpu/zig-out/bin/recursive-segment-v2-leaf-key-rebuild \
  /tmp/stwo-riscv-leaf-tree0-new-output/child-0-key.json \
  45d2465a37cdc24d3a84fcc494411215b3042c1ba025cd52090c48ded0a7d71d
```

The output directory must be absent before key setup. Two local negative
controls used a key copy with a changed `preprocessed_root[0]`, and a key
copy with a changed `native_sum_topology.addresses[0]`, respectively. After
recomputing each copy's SHA-256 pin, the separate key-only command rejected
both with `DetachedLeafTree0RootMismatch`. Re-pinning a malformed key cannot
make its claimed fixed root agree with the independently regenerated tree.
