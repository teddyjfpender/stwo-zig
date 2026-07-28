# STWZCVE/1 canonical Rust verifier adapter

This standalone package is the canonical Rust verification lane described in
Section 12.12 of `docs/sn-pie-metal-production-architecture.md`.

The adapter implements the security boundary and two canonical proof codecs:

- fixed `STWZCVE/1` framing;
- bounded file and section lengths;
- exact section order and uniqueness;
- reserved-zero and mandatory-flag checks;
- SHA-256 authentication of every section;
- pinned source identity and executable/lockfile identity reporting;
- machine-readable direct-argv, timeout, and resource-limit configuration;
- atomic, no-replacement result publication;
- exact-revision `cairo-air` and Stwo dependencies;
- typed deserialization of complete `CairoProof` JSON emitted by `gpu_bench`;
- typed deserialization of complete `CairoProofForRustVerifier` JSON;
- deterministic validation of the redundant `memory_id_to_big` aggregate
  against every transcript-bound segment claim;
- exact typed reconstruction of `CairoClaim`, `CairoInteractionClaim`, and
  `StarkProof<Blake2sMerkleHasher>` from `resident_sn2_bundle_v1`;
- authenticated protocol/statement/provenance bindings; and
- `verify_cairo::<Blake2sMerkleChannel>` with structured panic/rejection output.

The adapter enforces the envelope, section, and result-file byte limits. The
calling block service owns the configured wall timeout, process-group
termination, and address-space limit; the adapter does not claim to apply
those process controls to itself.

The JSON proof object contains its complete typed `PublicData`, `CairoClaim`,
interaction claim, and STARK proof. The adapter verifies that complete object
and exits zero only when the canonical verifier accepts it. The pinned
`stwo-cairo` revision does not absorb the redundant
`memory_id_to_big.claimed_sum`; this adapter therefore derives that value from
`big_claimed_sums` and rejects any mismatch before calling the pinned verifier.

The compact codec constructs the pinned Rust `PublicData`, `CairoClaim`,
`CairoInteractionClaim`, and complete STARK proof, derives the canonical sample
shape from `CairoComponents`, checks exact re-flattened claims, and calls
`verify_cairo`. Capability reporting exposes the JSON and compact verification
paths separately. The real 8,410,304-byte reference-free SN2 Metal proof with
SHA-256
`5c9fe8577d83aac0c9a42d3e482e471c653e3d459304cb9310c411b283aa9052`
passes this path.

The current SN2 envelope is a decoder-development diagnostic: its statement
was encoded from the reference verifier JSON and its external artifact identity
digests are placeholders. This demonstrates proof equivalence, but is not the
production compact interchange gate. Production requires the Zig service to
serialize its independently bootstrapped statement and bind real adapted-input,
manifest, runner, and backend executable digests.

## Fixed binary framing

All integers are little-endian. Byte offsets in the 32-byte envelope header:

| Offset | Width | Field | Canonical value |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `STWZCVE\0` |
| 8 | 2 | version | `1` |
| 10 | 2 | header length | `32` |
| 12 | 4 | header flags | `0` |
| 16 | 4 | section count | `4` |
| 20 | 4 | reserved | `0` |
| 24 | 8 | complete envelope length | exact file length |

Each section immediately follows the preceding section payload and begins
with this 48-byte header:

| Offset | Width | Field | Canonical value |
| ---: | ---: | --- | --- |
| 0 | 2 | section type | `1..4` |
| 2 | 2 | flags | `1` (mandatory) |
| 4 | 4 | reserved | `0` |
| 8 | 8 | payload length | nonzero and type-bounded |
| 16 | 32 | payload SHA-256 | exact payload digest |

The four sections occur exactly once in this order: `protocol=1`,
`statement=2`, `proof=3`, `provenance=4`. The decoder rejects unknown types,
permutations, duplicate/missing sections, unknown flags, nonzero reserved
fields, length overflow, truncation, digest mismatch, and trailing bytes.

Limits are 1 GiB for the complete envelope, 4 MiB for `protocol`, 256 MiB for
`statement`, 512 MiB for `proof`, and 16 MiB for `provenance`. The section
payload codec implemented below is exact; opaque authenticated payloads are
never treated as verified proofs.

## Compact Metal validation codec

`compact_codec.rs` defines version-1 little-endian protocol and statement
payloads. The 112-byte protocol header fixes Blake2s and assigns stable wire
tags `1`, `2`, and `3` to `Canonical`, `CanonicalWithoutPedersen`, and
`CanonicalSmall`. The matching trace-tree-0 widths are exactly `161`, `105`,
and `156`; unknown tags and tag/width mismatches are rejected. The header also
authenticates salt, PCS geometry, all four trace-tree widths, and the variable
interaction-sum, sampled-value, and decommit-capacity word counts used to split
the raw proof.

The statement header is followed by eleven fixed-order segment records,
complete program/output `(id,[u32;8])` entries, exactly 83 `u32` enable bits,
and one active log size per enabled bit. The decoder rejects noncanonical M31
state/pointer/id words, a missing output segment, nonzero absent segments,
non-binary enables, noncontiguous `memory_id_to_big` slots 49 through 64,
active-count drift, invalid log sizes, overflow, truncation, and trailing bytes.
It returns the exact pinned Rust `PublicData`, `PreProcessedTraceVariant`, and
claim geometry needed by the reconstruction step.

The proof section remains the existing raw `resident_sn2_bundle_v1`; no wrapper
or producer change is required. Its decoder validates exact byte length,
canonical interaction/sample/final M31 words, the versioned decommit header,
70 raw queries, bounded unique queries, four trace plus eight FRI records,
canonical kind/role order, and every strided metadata range. Recorded layouts
reconcile to 2,102,572 words for SN1/3/4 and 2,102,576 words for SN2. It then
reconstructs the four trace decommitments, eight FRI layers, final line
polynomial, nonces, and exact fold-3 PCS configuration before canonical
verification.

The optimized adapter verified the diagnostic SN2 envelope in 68,951,334 ns.
That number covers envelope decoding, typed reconstruction, and
`verify_cairo`; it excludes process launch and producer-side envelope creation.
The measured release binary SHA-256 was
`aa9684a92768c8691ef1d9506bde0d01e84bd997742b5877cd8ed20cdd58ac82`.

## Complete JSON proof codec

All metadata payloads are strict JSON objects with unknown fields rejected.
The `proof` payload is raw serde JSON in one of two exact encodings:

- `cairo_proof_extended_json_v1`: `CairoProof<Blake2sMerkleHasher>`, as emitted
  by `gpu_bench` when `STWO_DUMP_PROOF_JSON` is set;
- `cairo_proof_rust_verifier_json_v1`:
  `CairoProofForRustVerifier<Blake2sMerkleHasher>`.

The `protocol` object contains:

```json
{
  "schema_version": 1,
  "proof_encoding": "cairo_proof_extended_json_v1",
  "channel": "blake2s",
  "preprocessed_trace_variant": "canonical",
  "channel_salt": 0,
  "pow_bits": 26,
  "log_blowup_factor": 1,
  "n_queries": 70,
  "log_last_layer_degree_bound": 0,
  "fold_step": 3,
  "lifting_log_size": null,
  "interaction_pow_bits": 24,
  "stwo_cairo_revision": "dcd5834565b7a26a27a614e353c9c60109ebc1d9",
  "stwo_revision": "9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2"
}
```

The adapter accepts the three canonical preprocessed variants and compares the
selected variant, salt, and every PCS field with the deserialized proof. The
other protocol values are fixed to the current Blake2s/fold-3 SN PIE profile.

The `statement` object is
`{"schema_version":1,"encoding":"embedded_in_cairo_proof_json_v1","proof_sha256":"<lowercase hex>"}`.
It records that the independently typed statement is embedded in the complete
proof JSON and binds those exact bytes. The `provenance` object contains
`schema_version=1`, `source="gpu_bench_json_bridge_v1"`, and lowercase
`protocol_sha256`, `statement_sha256`, and `proof_sha256` values matching the
three preceding section payloads.

Malformed metadata, digest drift, unsupported configuration, proof/protocol
mismatch, JSON decoding failure, canonical rejection, and verifier panic all
produce `verified=false`, exit status 3, and a structured error code.

## Source pins

- `stwo-cairo`: `https://github.com/teddyjfpender/stwo-cairo` at
  `dcd5834565b7a26a27a614e353c9c60109ebc1d9`
- Stwo: `https://github.com/teddyjfpender/stwo` at
  `9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2`

This package declares an empty local workspace and depends on `cairo-air` and
Stwo by the exact Git revisions above. It therefore does not inherit the local
checkout's absolute dirty `[patch]`. No path dependency or patch is permitted.

## Commands

```sh
cargo test --locked --manifest-path tools/stwo-cairo-verifier-rs/Cargo.toml
cargo build --release --locked \
  --manifest-path tools/stwo-cairo-verifier-rs/Cargo.toml \
  --bin stwo-cairo-verifier-adapter

tools/stwo-cairo-verifier-rs/target/release/stwo-cairo-verifier-adapter identity
tools/stwo-cairo-verifier-rs/target/release/stwo-cairo-verifier-adapter config
tools/stwo-cairo-verifier-rs/target/release/stwo-cairo-verifier-adapter verify \
  --envelope /exclusive/input.stwzcve \
  --result /exclusive/result.json
```
