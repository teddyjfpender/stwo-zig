# OP Stack guests

Rust RV64 guests for the OP Stack product line
(`src/products/opstack/statement`, design in
[`design/opstack/integration.md`](../../design/opstack/integration.md)). They
were ported from PR #372 (`opstack/kona`, `opstack/mantle`) without code changes
beyond path updates.

| Path | Contents |
|---|---|
| `kona/` | Kona execution crate (`stwo-kona-execution`), the RV64 guest (`guest/`) and the separate-policy "lean" guest variants (`lean/`) |
| `mantle/` | Mantle pilot: an OP-Stack chain with its own dependency family and ME43 framing |
| `abi_probe/` | Tiny `no_std` guest on the OP guest ABI. No services, 43-byte OP framing. Prebuilt as `vectors/opstack/abi-probe.elf` for hosted end-to-end proof tests |
| `runtime/exact_layout_allocator_v2.rs` | Fork of `guests/exact_layout_allocator_v2.rs` with volatile free-list stores (size-oriented LTO dropped them) |
| `vendor/` | Vendored crate deltas; each has `UPSTREAM.json` and an entry in `third_party/INVENTORY.json` |

`kona/guest/src/keccak_sponge_service.rs` and `vendor/revm-bytecode` are forks of
the Ethereum guest's copies with the PR #372 delta, so Ethereum guest bytes stay
unchanged. The guests still path-depend read-only on
`guests/ethereum/rv64/{mem,src/single_thread_atomics.rs,src/keccak_service.rs}`
and `guests/ethereum/rv64/vendor/{k256,ecdsa,revm-interpreter,sha2-rv64}`.
This is exception E-3; issue G-1 tracks a shared `guests/rv64-runtime` crate that
would retire it.

## Toolchain and builds

`rust-toolchain.toml` pins `nightly-2026-08-08` with `rust-src`. Build guests
through `tools/opstack/build.py`. It defaults to the `canonical-glv` Kona guest
with SHA-256 delegated to the service. Use `--variant` to select another guest.
The build records source and binary identities and checks pinned ones in
`vectors/opstack/kona-guest-identity.json`.

Rebuild the ABI probe and compare it with `vectors/opstack/abi-probe.json`:

```sh
cargo +nightly-2026-08-08 build --locked --release \
  --manifest-path guests/opstack/abi_probe/Cargo.toml \
  --target guests/opstack/kona/guest/riscv64i-stwo.json \
  -Z json-target-spec -Z build-std=core -Z build-std-features=compiler-builtins-mem
shasum -a 256 guests/opstack/abi_probe/target/riscv64i-stwo/release/stwo-opstack-abi-probe
```
