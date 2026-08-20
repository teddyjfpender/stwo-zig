# Poseidon2 M31 permutation v1 guest pair

This package is the apples-to-apples software/precompile authority needed by
C-013. Both RV32IM executables consume:

```text
[call_count: u32 little endian][call_count * 16 canonical M31 words]
```

and publish all `call_count * 16` output words in order. The default arm runs
the exact `riscv.poseidon2_m31.permute.v1` function in portable RV32IM. The
`precompile` arm retains the same I/O loop and invokes the version-1
`CUSTOM-0` operation once per state. It carries the exact `.note.stwo.zkvm`
admission descriptor; the software arm carries no extension note.

The workload shape is also compile-time authority. `shape-balanced` executes
one extra portable permutation per state in both arms, while
`shape-core-only` executes fifteen. With the one compared permutation, the
candidate's permutation work is respectively 0%, 50%, and 93.75% portable for
the dominant, balanced, and historically named `core_only` cohorts. The
features are mutually exclusive. A volatile scratch write makes the extra
work proof-visible before the ordinary output overwrites it, so public outputs
remain the exact permutation outputs and are byte-identical between arms.

Build all three source-identical shape pairs with the pinned toolchain:

```sh
cargo build --release
CARGO_TARGET_DIR=target-precompile cargo build --release --features precompile
CARGO_TARGET_DIR=target-balanced cargo build --release --features shape-balanced
CARGO_TARGET_DIR=target-balanced-precompile cargo build --release \
  --features precompile,shape-balanced
CARGO_TARGET_DIR=target-core-only cargo build --release --features shape-core-only
CARGO_TARGET_DIR=target-core-only-precompile cargo build --release \
  --features precompile,shape-core-only
```

The dominant binaries are respectively:

```text
target/riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1
target-precompile/riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1
```

The other target directories follow the commands above. Cargo does not track
`linker.ld` as an input. Remove every named target directory before a
provenance capture when the linker script changes. A C-013 capture must
authenticate the source closure, both executable bytes, the generated input,
the exact shape feature set, and independently equal output before timing
either arm. These binaries alone are not a performance receipt.

From the repository root, build all six arms and run the exact semantic
preflight:

```sh
zig build check-c013-poseidon2-pair -Doptimize=ReleaseFast -j2
```
