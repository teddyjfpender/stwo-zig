# BLAKE3 segmented artifact v7 diagnostic qualification

2026-09-22. Shared segment artifact implementation is parameterized by canonical
core suite: immutable BLAKE2s v3 facade, explicit BLAKE3 v7. Proof hasher/shape,
outer admission and inner identity version follow the selected suite. The new
identity hash domain rejects inner-version relabeling; v3's domain/bytes remain
unchanged. No production routing/default changes.

ReleaseSafe artifact gate passes 14/14 tests, including synthetic v3/v7 identity
round trips, cross-version rejection, relabeling rejection, and independently
computed Python SHA256 zero-metadata vectors. This is codec-level evidence.

The full segment proof gates initially exposed two stale test assumptions:
V1 context validation with a typed V2 context, and invented memory digests instead
of native snapshot digests. Both are corrected in the shared harness. A new
fixture-only gate passes in 528 ms after a 7 s build, validating runner execution,
snapshot-bound global source, leaf-local projection and authenticated public wire
without compiling/proving the entire guest. Earlier BLAKE3 and legacy executables
both failed with MemorySnapshotMismatch before proof generation.

Full corrected BLAKE3 and legacy signer-segment proof/serialization/independent
capture-verification gates pass: 8/8 build steps and 2/2 tests. BLAKE3 test runtime
10 s, legacy 6 s, each approximately 1 GiB MaxRSS; both ReleaseSafe compilations
were approximately 3 minutes/6 GiB. These are gate runtimes including verification
and mutation checks, not isolated proving benchmarks. Corrected log is retained.

The fixture uses diagnostic q3/PoW0. Production security, larger jobs, reusable
recursive keys, product routing and Metal remain unqualified. Furthermore the
existing SegmentV2/V3 public boundary still uses Poseidon snapshot/span/lineage
identities: v7 migrates the STARK suite, not all boundary hashing. See
../20260922-blake3-segment-boundary-audit.md. Full 256-bit BLAKE3 boundary identities
require versioned injective field encoding and corresponding AIR/key admission.

Commands: serialized ReleaseSafe test-guest-proof-artifact in frontend (14 tests),
test-ethereum-segment-artifact-fixture in CPU integration (1 test), and corrected
CPU test-blake3-ethereum-segment-artifact plus test-ethereum-segment-v2-signer-proof.
