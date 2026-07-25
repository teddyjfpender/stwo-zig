# Session 11: Authenticated Pedersen AOT Module Globals

## Scope

Two of the 32 directly recorded SN2 witness programs use Pedersen W18
deductions. Their generated kernels retain the common eight-argument witness
ABI, but the deduction helper reads two module-local device symbols:

- `g_stwo_wit_pedersen_cols`: exactly 56 device pointers.
- `g_stwo_wit_pedersen_n_rows`: exactly one `u32`, with value `2^23`.

This is not an additional kernel argument and cannot be inferred from a
component label. Launching either cubin without publishing those symbols would
read uninitialized module state.

## Authenticated Capability

Every product AOT manifest entry now declares one canonical capability:
`none` or `pedersen_w18_columns_rows_v1`. The generated binary-search carrier
copies that capability beside the cache key, SM, ABI schema, kernel symbol, and
cubin digest. Production bind supplies the capability expected by the Zig
product registry. The loader rejects any mismatch before loading the cubin.
The compatibility bind path explicitly expects `none`, so it cannot launch a
Pedersen-capable module accidentally.

For the Pedersen capability, the loader resolves both exact symbol names from
the authenticated cubin and rejects absent, null, or incorrectly sized
symbols. The capability is metadata authority; component labels have no role
in native authorization.

## Publication Contract

Before a function launch, the proof-owned session provides 56 ordered resident
column addresses, the exact row count, and a nonzero table content identity.
The native loader then:

1. Confirms every address belongs to the loader's current CUDA context.
2. Confirms at least `2^23 * sizeof(u32)` bytes remain in every allocation.
3. Rejects misalignment and overlap between the 56 logical columns.
4. Copies the ordered pointers and row count into the exact module symbols on
   the proof stream.
5. Copies both symbols back to host memory on the same stream.
6. Synchronizes that stream and compares every pointer and the row count.
7. Returns a receipt bound to the capability, module, stream, symbol sizes,
   geometry, and table identity.

An identical live publication is reused without rewriting module state, while
resident-range validation still runs. The Zig session validates the receipt
against the authenticated function receipt before permitting the kernel
launch.

The table identity represents the registered table content. As in the pinned
Rust reference architecture, native publication proves exact live module,
address, geometry, and ordering facts; the Cairo fixed-table authority must
separately compute and compare the canonical content digest.

## Evidence

Local gates:

- `zig build test`: pass, 415-source closure.
- `zig build source-conformance`: pass, no new violations.
- `zig build test-cuda-build-plan`: pass, 78 tests.
- `zig build test-cuda-runtime-contract`: pass.
- Focused loader authentication tests: pass, including capability mismatch,
  exact symbol-size failure, readback, fence, idempotence, and row mismatch.

The focused RTX 4090 publication smoke passed with the full 56 by `2^23`
resident geometry. It loaded the authenticated
`partial_ec_mul_window_bits_18` cubin, resolved the two exact symbols,
published and read back all 56 addresses plus the row count, fenced the stream,
and repeated the identical publication through the cached path. It
deliberately did not launch against uninitialized table values.

The focused 48-cubin archive had build identity
`0002c13f53da5600660ab7e4f3de8b060e1795081ec929c9b39da529332b1082`
and SHA-256
`d28730ce2a8dc9401297a8fa9307f55212f0d0e38925fbe0f7eaa865ffcdfff9`.
This is device evidence for publication only, not a recorded-witness value
parity result.

## Remaining Closure

- Bind the Cairo fixed-table builder's canonical content digest to
  `PedersenW18Table.identity`.
- Extend the recorded-witness differential matrix from the 30 ordinary direct
  programs to the two Pedersen-capable programs with real canonical table
  values.
- Preserve the native composite exclusion for `partial_ec_mul_generic`; it is
  not a standalone recorded-witness launch.
- Complete per-component SIMD parity, then interaction and constraint parity.

This work admits the two module-global capabilities structurally. It does not
claim a complete SN2 witness, proof, proof-byte parity, or proving latency.
