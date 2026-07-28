# Stwo Cairo Trace Oracle

This isolated development tool turns an official Stwo-Cairo `ProverInput`
JSON document into deterministic base- and interaction-trace checkpoints. It
calls the pinned official Rust `CairoClaimGenerator::write_trace`
implementation and emits comparison evidence for the Zig port. Released Zig
products do not build, invoke, or distribute this tool.

```sh
cargo run --release --locked -- \
  ../../vectors/cairo/official/all_opcodes.prover_input.json \
  /private/tmp/all-opcodes.base-checkpoint.json
```

Columns retain the committed `CircleEvaluation` value order
(`BitReversedOrder`). Every M31 value is encoded as canonical `u32` little
endian. Column and cumulative component hashes use the domain-separated
SHA-256 contract named in `src/checkpoint.rs`.

## Diagnostic interaction checkpoints

The separate `interaction` mode runs the interaction generator returned by
the same base-trace call and emits
`stwo-cairo-interaction-trace-checkpoint-v1`:

```sh
cargo run --release --locked -- interaction \
  ../../vectors/cairo/official/all_opcodes.prover_input.json \
  /private/tmp/all-opcodes.interaction-checkpoint.json
```

This mode is a deterministic cross-backend diagnostic, not a proof. Its
`CommonLookupElements` are deliberately independent of a proof transcript:

1. SHA-256 hashes the ASCII bytes of
   `STWO_CAIRO_INTERACTION_DIAGNOSTIC_CHALLENGE_V1` followed by one NUL byte.
2. The digest is decoded as eight little-endian `u32` words.
3. Those words are mixed into `Blake2sChannel::default()`.
4. `CommonLookupElements::draw` samples `z` and `alpha` from that channel.

The receipt explicitly sets `is_proof_transcript` to `false` and serializes
`z`, `alpha`, and all 128 alpha powers as canonical four-limb M31 values, so a
Zig comparator need not reimplement the channel before checking interaction
columns. The lookup-element digest, per-component claimed sum, raw M31 column
digests, and cumulative component accumulator are all domain separated and
bound together by the contract in `src/interaction.rs`.

Interaction columns retain `CircleEvaluation`'s `BitReversedOrder`. Each raw
M31 value is hashed as a canonical little-endian `u32`. The binary hash inputs
are length-delimited and ordered as follows:

- lookup elements: domain, four `z` limbs, alpha-power count, then each
  power's ordinal and four limbs;
- column: domain, component ordinal, label length and bytes, column ordinal,
  row count, then raw M31 values;
- component accumulator: domain, previous accumulator, lookup-element digest,
  component ordinal, label, four claimed-sum limbs, column count, then each
  column's ordinal, row count, and digest.

All integer metadata is little endian. The first component starts with a
32-byte zero accumulator. Component order is the pinned Cairo claim order,
including separately labeled `memory_id_to_big[index]` segments.

Both modes publish output atomically and refuse to replace an existing path.
Omit the output path to write JSON to standard output.

The all-builtins fixture requires the same larger worker stack used by
upstream witness tests:

```sh
RUST_MIN_STACK=67108864 cargo run --release --locked -- \
  ../../vectors/cairo/official/all_builtins.prover_input.json \
  /private/tmp/all-builtins.base-checkpoint.json
```

The standalone manifest has no path dependencies, patches, or replacement
sources. `Cargo.lock` binds the exact official source tuple:

- `stwo-cairo`: `82f21252a68ec006d73e299f5bf1ce6d4db0ee78`
- `stwo`: `7b211edde786775016ef3eecb837a6240d8fe792`
