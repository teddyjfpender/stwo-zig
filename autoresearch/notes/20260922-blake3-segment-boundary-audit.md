# Remaining Poseidon ownership in segmented proof boundaries

The v7 envelope selects BLAKE3 for the STARK commitment/transcript suite. It
retains the existing SegmentV2/V3 public statement; it is not evidence that the
entire segmented proving system has stopped using Poseidon.

Authoritative sources:
- recursion/segment_statement_v2_contract.zig imports poseidon2_channel and
  air/memory_commitment/poseidon2. IdentityHasher wraps CanonicalWordHasher.
- recursion/segment_statement_v2_canonical_wire_view_v2.zig snapshotDigest hashes
  version, nonzero-word count and address/value pairs through that owner;
  snapshotIdentity adds the existing continuationRoot.
- recursion/span_statement_executed_span.zig stores Digest as eight u32 words
  but validateDigest requires each word below the M31 modulus. Its canonical
  layouts assume eight field words per digest.

Therefore raw BLAKE3 digest words cannot replace this representation unchanged:
full 256-bit digests require an injective field encoding (for example sixteen
16-bit limbs) and explicit new statement/layout admission. Masking high bits or
reducing each word would silently change the security/identity contract.

Completion requires migrating prover-owned snapshot/job/lineage/span identity
hashing, continuation tree commitments, public wire encodings and corresponding
recursive AIR/capture/key admission together, in addition to core PCS and Metal.
Guest-requested Poseidon operations remain supported. Legacy statement/artifact
verification remains explicitly versioned. This is a source audit, not a measured
claim about how much end-to-end time these identities consume. Reusable keys and
parent-of-parent proofs must qualify the resulting new boundary protocol.
