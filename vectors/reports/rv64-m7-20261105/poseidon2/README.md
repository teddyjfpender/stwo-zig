# Experimental M7 Poseidon2 substrate

Status: scoped primitive/PCS/FRI gates PASS. No Ethereum activation or cell, memory, proof-size or speed improvement claim.

Named suites `M7-P2M31-W24-R12-C12-D9-{QM31,OM31}-v1` bind the pinned Plonky3 width24 permutation, rate12/capacity12, nine canonical M31 digest limbs (36 bytes), additive sponge, mandatory end marker and separate operation domains. Arbitrary u32s use two16-bit limbs; field inputs and digests remain canonical. Secure-field degree enters the channel IV. Parameter identity and framing enter the suite identity. The width16/eight-limb alternative has only248 digest bits, so this new profile does not silently inherit a128-bit collision claim from that shorter digest. Parameter choice is not a whole-system security certificate.

Eight focused native tests cover official and independent dense-matrix vectors, framing against an independent Python sponge, rate boundaries, transcript replay, raw-u32 injectivity, canonical serialization, field-domain separation and low-bit grinding. Small boolean AIR proofs complete real composition/PCS/FRI in QM31 and OM31 with fold1/4. Eight JSON/binary files are produced, producer processes exit, and eight independent receiver processes accept. Six malformed/root/foreign-profile cases reject. Tests with allocator checking additionally exercise real roots and openings. These are synthetic log4 fixtures, not RV64 proofs.

CUDA sm120 permutation, column-major Merkle leaves, parents and ordered transcript kernels match independent Python vectors, including raw maximum-u32 input and64-bit draw-counter boundaries. Compute Sanitizer reports zero errors. This is a new numerical substrate; the production CUDA PCS still has its old32-byte ABI and does not select these kernels. No GPU proof or device PoW qualification is implied.

Legacy `ForField` proof bytes retain their existing contract. New `ForHasher` uses separate magic/JSON protocol names,36-byte hash bounds and canonical root/path checks. The generic CPU Merkle path now avoids analyzing a Blake-only seeded worker branch; externally adopted32-byte device roots fail closed for a different hash representation.

Remaining gates: dedicated Poseidon recursion AIR/roster, exact full-leaf padded-cell census, new CUDA PCS/FS/PoW ABI, RV64 native and outer profile selection, semantic-summary/canonical digest migration, security review, full tamper corpus and both development blocks through cache-disabled fresh receivers. The final on-chain wrapper remains a separately named Blake/Keccak layer.
