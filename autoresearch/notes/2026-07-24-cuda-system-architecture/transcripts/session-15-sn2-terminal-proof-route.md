# Session 15: SN2 CUDA terminal proof route

Date: 2026-07-25

Status: development route complete; full CUDA proof absent

## Scope

This increment defines the isolated host boundary for a future resident Cairo
CUDA proof session. It does not execute trace commitment, OODS, quotient, FRI,
PoW, decommitment, or proof assembly.

The route accepts exactly one device-produced SWPC allocation and:

1. validates its header and six gapless sections against caller-authenticated
   `CompactProtocolV1` geometry;
2. requires measured evidence for exactly one terminal D2H operation and its
   exact transport byte count;
3. rejects any measured runtime compilation or CPU fallback attempt;
4. reorders the device's grouped interaction/query PoW words into the pinned
   Rust `resident_sn2_bundle_v1` wire order;
5. validates canonical field sections, nested decommitment layout, tree
   identities, query count, and zero transport-capacity tail;
6. exposes exact little-endian canonical proof bytes and SHA-256;
7. writes those bytes into the authenticated STWZCVE/1 envelope; and
8. exposes a hook compatible with the pinned Rust Cairo oracle's
   `verifyCairo` method and rejects noncanonical oracle identity evidence.

No zero-JIT, zero-fallback, or one-D2H property has been inferred from source
layout. The route admits those properties only through explicit runtime
counters supplied after stream completion.

## Golden SN2 geometry

The terminal descriptor consumes the shared golden layout from
`compact_verifier_interchange.zig`:

- interaction claim: 232 words (58 secure-field sums);
- sampled values: 24,440 words;
- decommitment capacity: 2,077,800 words;
- canonical proof: 2,102,576 words / 8,410,304 bytes;
- SWPC transport: 2,102,610 words / 8,410,440 bytes, including its 34-word
  device header.

A smaller runtime-geometry fixture exists only to make exact nonce placement,
section ordering, malformed-header, nonzero-tail, and evidence-rejection tests
cheap. It is not presented as an SN2 proof.

## Files

- `src/integrations/cairo_cuda/executor/terminal_decode.zig`
- `src/integrations/cairo_cuda/executor/proof_route.zig`
- `src/integrations/cairo_cuda/executor/terminal_route_test.zig`
- `src/integrations/cairo_cuda/executor/mod.zig`

The three new implementation/test files contain 254, 79, and 333 lines,
respectively, all below the 850-line source ceiling.

## Gates

Focused ReleaseSafe command:

```text
zig test -OReleaseSafe --dep stwo_core \
  -Mroot=src/cairo_cuda_terminal_test_root.zig \
  -Mstwo_core=src/core/mod.zig
```

The temporary root imported only the terminal descriptor, decoder, route, and
their transitive dependencies; it was deleted after the run.

Result:

```text
All 51 tests passed.
```

The focused tests include:

- exact canonical proof section and PoW nonce ordering;
- golden SN2 proof/transport cardinalities;
- missing measurement rejection;
- runtime compilation and CPU fallback rejection;
- poisoned header and nonzero decommitment tail rejection;
- exact proof payload bytes and digest inside STWZCVE/1; and
- the pinned Rust oracle-compatible verifier hook.

`zig fmt` completed for every touched terminal file and `git diff --check`
passed. Repository-wide source conformance was temporarily blocked by the
concurrent PCS lane's 1,002-line `executor/pcs_hooks.zig`; no terminal file
violated the ceiling.

## Explicit non-result and remaining dependencies

There is no full SN2 CUDA proof, pinned Rust acceptance receipt, proof-byte
parity result, wall time, or MHz result in this session.

Those results require:

1. the resident mixed-height commitment/OODS/quotient/FRI/decommitment stages
   to execute and populate every SWPC section;
2. an authenticated AOT terminal finalizer that clears the poison degree
   verdict only after successful proof assembly;
3. production runtime telemetry wired into `MeasuredTerminalRead`;
4. exact canonical byte comparison with the Zig SIMD proof;
5. STWZCVE/1 publication with immutable CUDA product identities; and
6. acceptance by the pinned Rust stwo-cairo verifier on the full GPU-produced
   envelope.

Only after those boundaries pass on the H100 can the SN2 proving time and MHz
be reported.
