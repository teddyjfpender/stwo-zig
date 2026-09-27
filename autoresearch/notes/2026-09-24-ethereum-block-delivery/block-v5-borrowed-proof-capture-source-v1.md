# Immutable producer proof capture

The core STARK and PCS verifier now expose borrowed proof-capture entry points using the same verifier implementation as the owned path. Borrowed inputs remain producer-owned; generated sample points and verifier scratch are still consumed, and published capture allocations are independently owned.

The native recursive leaf callback is wired to fresh verification of the immutable producer proof rather than encoding and decoding it solely to obtain another owner. Native claims are copied into capture-owned storage. Independent detached receiver decoding, resource admission and final verification remain in place. Actual native borrowed-capture verifier and native recursive leaf callback bodies now compile in a four-check focused gate (one named body check). The addresses are retained without calling them. Successful full-STARK capture and complete bundle acceptance remain unqualified.

The isolated nonproving core gate passed3/3 (two named behavior checks plus the import root): early invalid-tree rejection, late PCS proof-of-work rejection, unchanged original vectors and transactional publication, including every temporary allocation failure. These malformed fixtures do not establish successful capture independence or owned-verifier regression coverage. No STARK, segment, recursive proof or driver was invoked, and no performance result is claimed.

Exact core source hashes and the passed log are retained in `cpu-performance-gates-v1/borrowed-proof-capture-ownership-qualified-source-v1.json`. Native and leaf files remain outside that qualified snapshot while the concurrent base-AIR migration is active.

## Successful ownership qualification

The subsequent isolated gate passed6/6 (five named behavior checks plus import root). A literal constant-seven column with zero DEEP quotient and literal zero FRI evaluations uses real four-leaf BLAKE3 commitments, seven raw transcript queries and genuine PCS/Merkle/FRI verification. It invokes no STARK or FRI prover. Borrowed and owned verification produce identical complete captures and transcript states. Captures remain unchanged after all original proof payloads are poisoned and freed. Every temporary verifier allocation failure leaves both input and publication unchanged.

This exposed existing FRI allocation-error handling defects: out-of-memory was mapped to invalid-proof errors; sparse reconstruction could double-free after publishing only one of two descriptors, and folding output/workspace buffers leaked on failed allocation. FRI now preserves OutOfMemory, publishes completed owners transactionally and frees intermediate folds/workspace/output on failure. Expected out-of-memory is propagated without being logged as invalid PCS/FRI proof data. Multi-step circle and line scratch ownership is separately exercised through every allocation failure. The verification equations, commitments and transcript remain unchanged.

Evidence: `cpu-performance-gates-v1/borrowed-proof-capture-success-ownership-v2.log` and `borrowed-proof-capture-success-qualified-source-v2.json`. This qualifies successful PCS ownership and the existing owned PCS path, not successful full-STARK capture, the native/leaf callback bodies or complete independent bundle acceptance. No timing improvement is claimed.

Actual native/leaf CPU body evidence: `cpu-performance-gates-v1/borrowed-native-capture-production-body-v1.log` and `borrowed-native-capture-production-body-qualified-v1.json`. This supplements the six-check literal successful PCS gate; it does not qualify runtime STARK capture or later parent-source migrations.
