# Bulk BLAKE3 leaf encoding and packed commitment integration

2026-09-22. The canonical leaf framing owner now streams canonical M31 bytes in
bulk on little-endian hosts and bounded packed chunks on big-endian hosts. Typed
witness sinks retain their per-word role callbacks. BLAKE3's lifted hasher now
exposes the packed-byte interface already used by the shared tiled leaf builder;
there is no alternate commitment implementation or protocol byte change.

A live-source stwo-prof probe hashes 256 M31 fields per leaf, 32 leaves per call,
1000 calls per round, 5 rounds. This is a diagnostic width, not a claim about the
CSP distribution. Runtime-dependent inputs and returned digest prevent dead-code
elimination. Baseline and candidate counters plus source/harness are retained.

Median ns/leaf: 1688.388 -> 925.125; instructions/leaf: 46438.871 -> 21713.410.

The canonical 70-query/26-PoW-bit ECDSA precompile proof and independent verifier
pass: proving 0.994175542 s, execution 0.001713417 s, verification 0.188771667 s,
PoW 0.123395 s, 1,828 cycles, 3,748,258 inner proof bytes. Previous pooled-PoW
qualification was 1.000019083 s proving. Treat this end-to-end difference as
neutral: no statistical verdict or demonstrated CSP improvement. CPU default
and Metal migration remain unfinished.

The initial combined run's protocol compilation failed because a test variable
used Zig's reserved word `packed`; the separately compiled CSP test passed.
After renaming that variable, the focused ReleaseSafe protocol gate passes 8/8
tests (4/4 steps). New parity cases cover empty leaves, compression/chunk edges,
large field values, mixed typed/packed streaming, and the canonical per-word
encoding oracle. Existing independent vectors and PCS verification also pass.

Commands: stwo-prof zig run blake3-leaf-bulk-20260922 --iters 1000 --rounds 5 --json;
serialized ReleaseFast test-blake3-protocol/test-blake3-csp-ecdsa with
STWO_CSP_PROFILE=1 and canonical fixture root; then serialized ReleaseSafe
test-blake3-protocol. Logs retain the initial failure instead of claiming an
entirely green combined run.
