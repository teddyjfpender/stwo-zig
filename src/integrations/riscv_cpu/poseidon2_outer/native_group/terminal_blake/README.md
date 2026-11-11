# Terminal-only Blake experiment

This closed prototype proves the unchanged R6 six-component circuit AIR with a
plain BLAKE2s-256 Merkle commitment and the existing raw-modulo-M31 OM31 Blake
channel. The public circuit still verifies the original native Poseidon2 proofs
and hashes complete frames with Poseidon2. It is terminal only: there is no
recursive parent, runtime selector, execution receiver or settlement admission.
Existing P2 paths, protocol identities and defaults stay unchanged.

`authority.Key.init` first builds the REAL P2 R6 source key using b2/q144. It then
commits the exact same FIXED columns under Blake, retaining the full original
P2 root and identity. Both setup times are reported. The P2 FIXED tree is freed
only after deriving that authority; raw FIXED/usage remain for the unchanged
witness generator. No P2 root is truncated, cast or used as a Blake root. Avoiding
this double cold setup is a later materialization change, not an assumed gain.

The new suite has its own domain, hash/channel identity and `STB26G01` wire magic.
Its key identity binds the complete P2 R6 source identity and the independent
32-byte Blake FIXED root. That source identity already binds all ordered native
column geometry, source AIR, multiplicities and output count. Native and P2-root
formats reject each other's valid proofs. Verification reuses the same six
component emitters, lookup closure and core STARK verifier; no AIR is redefined.
Captured-child recursion is deliberately absent. Proof buffers are capped at2MiB.

The tiny physical gate covers arithmetic, a native OM31 multiplication and a P2
permutation, with independently rebuilt trace-only source authority. It checks
all six physical components, retired-key verification, output/claim/proof/key
mutations, noncanonical claims, and valid P2/Blake cross-format rejection. This
is neither a real execution root nor a performance benchmark. No production
runtime may select the suite before its complete source/admission/terminal and
adversarial gates are qualified.

The security label remains **128-bit security target under documented
assumptions**, `security_qualified=false`. FRI uses the existing nominal144-bit
b2/q144/P0/fold4 configuration; that query product is not a composed bound.
OM31 tuple/rational/pole, finite-characteristic and multiplicity bounds are
unchanged. Raw modulo draws retain their existing nonuniformity accounting.
Blake256 has generic128-bit collision work, versus the P2 D9 output's larger
nominal birthday margin. A complete budget must explicitly include
`Q_H(Q_H-1)/2^257`, transcript/Fiat-Shamir query terms, every Merkle tree and all
native/recursive proof unions. This experiment provides no certified bound.
A future on-chain receiver would need this exact new commitment/channel/wire
suite; the existing P2 Solidity verifier cannot accept it unchanged.
