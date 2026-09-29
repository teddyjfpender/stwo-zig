# Official Cairo VM Execution Adapter

This isolated sidecar executes legacy compiled Cairo JSON and modern Cairo
`2.20.0` executable artifacts with Cairo VM `3.2.0` under the
`all_cairo_stwo` proof layout, and genuine Cairo PIE ZIP archives through the
official simple bootloader in proof mode. It converts the resulting runner
state through the pinned official `stwo-cairo-adapter`.

It is an execution dependency, not a proof oracle. Zig owns witness generation,
proof generation, and in-process verification. The separately isolated
`stwo-cairo-official-verifier` remains the final correctness oracle for every
published proof.

```sh
cargo run --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml -- \
  run \
  --program /absolute/path/compiled.json \
  --program-type json \
  --prover-input-out /absolute/path/prover-input.json
```

Modern executable arguments are a JSON array of hexadecimal field elements:

```sh
cargo run --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml -- \
  run \
  --program /absolute/path/program.executable.json \
  --program-type executable \
  --arguments /absolute/path/arguments.json \
  --prover-input-out /absolute/path/prover-input.json
```

PIE execution uses `cairo-program-runner-lib` from StarkWare's official
`proving` repository at `5a7c5ede4299c91a61df19a07cba4f7502c14230`, with
`Task::Pie` and Blake task hashing. [Resource provenance](resources/provenance.json)
binds the bootloader and integration fixture. This execution dependency does
not replace the existing proof protocol or official verifier pins.

```sh
cargo run --release --locked --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml -- \
  run --program /absolute/path/block.pie.zip --program-type pie \
  --input-format compact --prover-input-out /absolute/path/block.cpi
```

The output path must not exist; publication uses a synced temporary file and
atomic no-replace persistence. JSON remains the standalone CLI default; the
CPU and Metal products request `compact-v1` to avoid a second in-memory JSON
copy. Both transports carry the same validated prover input. PIE archives
reject duplicate, unknown or missing members, oversized metadata/memory, and
malformed memory cells; PIE programs do not accept an arguments file. Identity
schema 2 declares both transports and the execution-runner/bootloader pins.

Public-memory addresses are sorted before
serialization so equivalent VM executions have one stable adapter document.
Legacy JSON preserves the pinned adapter's bootloader segment context.
Executable artifacts derive the public segment context from their authenticated
builtin list because the official adapter currently hardcodes the bootloader
context.
