# Warm family12 program stage

`prover/block_v5_program_extension_stage_v1.zig` exposes the bounded production
`ForBackend.hooks()` callback and `firstRoundEntry` census helper. The helper
checks the standalone family11 admission, canonical caller key and instance,
extension-only zero offsets, and exact typed caller count before proposing a
family12 entry. It does not issue authority.

The proof callback checks the replay record, independent B5SS roster, security
configuration, witness identity, and every shared fixed/main column lease. It
uses `block_v5_shared_first_round_v1.copy`; no first-round LDE or Merkle tree is
rebuilt. `block_v5_program_extension_columns_v1` recovers only the selected
caller trace columns and fixed selectors from immutable committed storage.
`block_v5_committed_trace_column_v1` uses the existing canonical circle FFT and
checks the recovered polynomial degree against the independently admitted
trace geometry. Arithmetic provider matrices are not reconstructed.

The callback transfers owned proof storage to a typed sink and retains no
witness or scheme. The original family11 scheme stays live for its arithmetic
proof. Fresh family11 and family12 verification, followed by global ROM
closure, remain mandatory receiver steps.

The existing SHA/Keccak and signer/Keccak warm fixtures now compose table and
program callbacks in their single `collect` / `proveWithHooks` replay. They
check two witness loads, fresh arithmetic verification after both borrowed
prefix proofs, fresh family12 verification, changed claims, swapped roots,
and a changed first-pass key. The focused ReleaseFast/native q8/PoW0 gate
passed all 10 tests with clean `std.testing.allocator` teardown. Both scenarios
fresh-verified family11 and family12 proofs after the shared callback replay;
the authenticated 52-event SHA address-unit regression also passed.

Exact invocation and output are recorded in
`block-v5-warm-program-extension-q8.json`. Time and peak memory were not
separately instrumented. This fixture supplies scoped execution roster pins;
it does not qualify actual native-v3 admission, whole-caller global accounting,
canonical q70 security, detached transport, or a mainnet block. The remaining
whole-caller final accounting investigation is separate from this stage gate.
