---
title: BLAKE3 protocol foundation and migration boundaries
author: Teddy Pender
created_utc: 2026-09-21T18:28:57Z
---

# BLAKE3 migration: protocol foundation

Task and required semantics: introduce a coherent BLAKE3 commitment and Fiat–Shamir suite as the CPU reference for the requested migration. Existing proof/key meanings must remain stable until a new authenticated protocol, recursive constraints and device kernels are qualified together.

Inputs/model: M31/QM31 values, unrestricted u32/u64 transcript messages, 32-byte roots, variable-length lifted Merkle leaves. Current recursive digest is eight canonical M31 words; BLAKE3's 256 output bits cannot use that representation without loss. Current recursive profile is q193/16 PCS PoW/10 interaction PoW, not the CSP profile.

Invariants: full digest preservation; explicit byte order; distinct domains for leaves, nodes, absorption types, root mixing, draws and PoW; no biased modular reduction for field challenges; bounded protocol counters; no accidental device family selection; trusted keys select the suite, never proof-supplied metadata alone.

| Candidate | Relationship | Fit / reuse | Risk |
|---|---|---|---|
| Standard BLAKE3 with framed messages | Exact primitive; new protocol construction | Existing Zig std implementation; no new dependency | New protocol must be reviewed and recursively constrained |
| Treat BLAKE3 as a Poseidon permutation | Analogy only | Incompatible chaining, flags and unrestricted words | Incorrect construction; rejected |
| Copy Proofman's Goldilocks transcript | Different field/protocol | Architectural reference | Goldilocks reduction does not transfer to M31; rejected |

Chosen mapping: streaming byte hashing for commitments; hash-chain transcript state with typed framed absorption and counter-indexed draws. Reject u32 values >= 2*(2^31-1), then reduce the accepted values modulo M31. Every field element has exactly two preimages. Keep full 32-byte roots. Merkle hashing is O(message bytes), streaming constant storage apart from BLAKE3's bounded internal tree stack.

Sources: BLAKE3 specification https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf and official vectors https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json. Existing Zig std.crypto.hash.Blake3 supplies the primitive; no upstream implementation code copied. ZisK release https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha resolves on this inspection to 02d2ae7b711454ce4574d852f8bfbddbfcbb1d67 (the earlier local tag pointed at 5c5f81c96929abed88894473ec6060b1b545b5c5). Release Cargo.lock pins proofman-fields 1.3.0-alpha checksum eb8d460b2e0e01f448eb78bd5486877239130674572be8f5c334bc86948cd65b. Inspected Proofman source d485fac207679076958b502554fb595568c2f954 fields/src/blake3_{core,transcript}.rs; this source is not asserted identical to the released crate.

Selected transfer: full BLAKE3 construction, separate transcript type, eventual dedicated seven-round compression constraints with initialization/feedforward/flags constrained separately. New native substrate remains experimental until recursive proof/key/AOT migration. Guest-required Poseidon and Ethereum Keccak semantics are independent from prover hash choice.

Prediction/falsifier: native hashing may improve; complete recursion may regress due to bitwise/addition constraints. No measured end-to-end prediction yet. Accept speed claims only from paired same-profile complete proofs plus standalone verification. ZisK release includes scheduling/packing changes, not a hash-only experiment.

Validation: official primitive vectors across block/chunk boundaries; independently encoded protocol vectors; field rejection boundaries; operation-domain and mutation tests; real CPU commitment opening and verifier rejection. Later: complete CPU/Metal proof parity, recursive parent-of-parent and mixed-family/key rejection; regenerate authenticated artifacts. Keep focused test target.

Uncertainty: recursive AIR layout and lookup traffic, Metal occupancy, end-to-end hash fraction, and security qualification. This foundation does not qualify a BLAKE3 recursive prover.
