# Trace digest

The single source of the domain-separated trace checkpoint digests
(`column_digest`, `accumulator_digest`) that stwo-zig's trace oracles emit and
`src/frontends/cairo/conformance/checkpoint.zig` compares. The record layout is
documented in `src/lib.rs`.

It is compiled into two tools, each against its own Stwo pin:

| Consumer | Stwo | Domains |
|---|---|---|
| `tools/stwo-cairo-trace-oracle` | `7b211ed` (Stwo-Cairo `82f2125`) | `STWO_CAIRO_BASE_{COLUMN,ACCUMULATOR}_V1` |
| `tools/stwo-circuit-oracle-rs` | `proving@5a7c5ed` | `STWO_CIRCUIT_{PREPROCESSED,BASE,INTERACTION}_{COLUMN,ACCUMULATOR}_V1` |

Each consumer includes `src/lib.rs` with
`#[path = "../../stwo-trace-digest/src/lib.rs"] mod trace_digest;`, so `stwo`,
`sha2` and `anyhow` resolve to the consumer's own locked crates. The directory
therefore has no `Cargo.toml`, lock or dependencies. The code reads only
`BaseField`'s canonical `u32`, which both pins share. The circuit oracle's
`source_sha256` covers this tree; the Cairo trace checkpoints were regenerated
byte-identically after the extraction.
