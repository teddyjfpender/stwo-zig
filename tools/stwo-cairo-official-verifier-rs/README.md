# Official Stwo-Cairo Verifier

This isolated Cargo package is the final correctness oracle for the active
Stwo-Cairo Zig port. It builds the official Rust `verify_cairo` implementation
from the exact revisions in [`conformance/upstream.md`](../../conformance/upstream.md).

It has its own workspace and lockfile. Do not add path dependencies, Cargo
patches, replacement sources, or repository frontend code.

## Identity

```sh
cargo run --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml \
  -- identity
```

The JSON response binds the executable, lockfile, supported channels, proof
formats, byte limit, and both official source revisions.

## Verify

```sh
cargo run --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml \
  -- verify \
  --proof /absolute/path/proof.json \
  --channel blake2s \
  --proof-format json \
  --result /absolute/path/verdict.json
```

Supported channels are `blake2s`, `blake2s_m31`, and `poseidon252`. Supported
Rust-verifier transports are `json`, `binary`, and `extended_binary`.
Cairo-serde felt arrays target the Cairo verifier and are deliberately rejected
by this Rust adapter.

The result path must not exist. Exit status `0` means the pinned official
verifier accepted the proof, `3` means it rejected the proof, and `2` means the
adapter or invocation failed.

## Gate

```sh
cargo test --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml
python3 scripts/check_upstream_pins.py
```

The tests accept the committed all-opcodes official proof, reject a mutated
copy, test immutable verdict publication, and validate source identity.
