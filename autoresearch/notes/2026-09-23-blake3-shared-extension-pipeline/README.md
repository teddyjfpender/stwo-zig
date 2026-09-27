# Shared BLAKE3 extension proof pipeline

Ethereum and guest Poseidon now specialize one typed proof, prepared-key, capture,
bounded proof codec, and authenticated manifest implementation. Ethereum retains
its existing protocol domains and artifact framing. Poseidon has distinct B3P2
proof/key domains, B3P2ART1 proof framing, B3P2ADM1 manifest framing and B3PVART1
published artifacts. The guest operation retains the existing caller/provider
AIRs; its program/memory commitments use the full-width BLAKE3 providers.

The shared product transaction and CPU-only fresh verifier now route the declared
Poseidon execution profile when `--proof-suite blake3` is selected. Preparation
reconstructs fixed columns from admitted geometry. Artifact verification requires
an external statement pin and actual ELF/input bytes, reconstructs a fresh key,
and does not retain the proving witness. Poseidon main columns are borrowed from
their final witness layout; the adapter only allocates column descriptors.

## CPU and Metal qualification

The focused full-proof gate passes for both Poseidon and Ethereum at 70 queries
and 26 PoW bits. It covers proof/codec round trips, fresh key reconstruction after
witness release, wrong key/pin/source rejection, canonical field rejection,
profile framing separation and capture mutation rejection.

The real Rust Poseidon precompile guest also passes the CPU product transaction
and a separate CLI verifier: 84 retired steps, one permutation, 64 output bytes,
1,091,213 published artifact bytes. Statement identity:
`0f5904dc0d18749703cc01340239f74fc7e3f915b28692051b9cae7855d62762`.
The updated CPU CLI accepts the retained canonical ECDSA artifact from
`../2026-09-23-blake3-shared-path-ecdsa`, confirming old Ethereum framing and
transcript compatibility after the common-pipeline extraction.

The real guest also passes Metal with the authenticated AOT bundle. CPU and
Metal artifacts are byte-identical (1,091,213 bytes); both cross-verifiers pass.
The Metal verifier was invoked with a nonexistent AOT path, confirming this
verification route needs no device initialization. Metal records 348 dispatches
and 41 CPU fallbacks: this remains hybrid execution.

These are dirty ReleaseSafe qualification runs; compilation overlapped some
runs. The raw reports retain phase timings but are not clean performance
benchmarks or evidence of an end-to-end speedup.

## Remaining work

Guest Poseidon recursive circuit integration is not established by a successful
native verification capture. Default suite promotion, obsolete prover-owned
Poseidon route removal, canonical Metal-parent qualification with shared Merkle
paths, and clean ReleaseFast CSP results remain pending. The original persistent
planning, fused PCS/DEEP, direct-layout and reviewed parameter work also remains
subject to its existing evidence; a 10x recursion speedup is unproven.

## Reproduction

The retained ELF and input are `poseidon-precompile.elf` and
`blake3-guest-poseidon-one.bin`. Both backends were invoked with:

```sh
zig-out/bin/stwo-zig-riscv-<backend> --proof-suite blake3 bench \
  --elf <retained-elf> --input <retained-input> --backend <backend> \
  --protocol secure --warmups 0 --samples 1 \
  --proof-out <new-proof-path> --report-out <new-report-path>
```

Metal used `STWO_RISCV_METAL_AOT_BUNDLE=/tmp/stwo-blake3-core-aot-20260922`.
The CLI's obsolete `--experimental` flag is not accepted after frontend promotion.
Separate verification used `--proof-suite blake3 verify --artifact <proof>` with
`--elf`, `--input`, `--protocol secure`, and the external statement digest above.
The products were built together with the serialized wrapper in ReleaseSafe;
`blake3-guest-profile-products.log` retains the build result.
