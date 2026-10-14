# Candidate line-tree descriptor binding

`line_descriptor_v2.zig` binds each experimental `S31NAT9F` line root to a
versioned Merkle shape and a named framed transcript event. It has no selected
proof dispatch. Four Gate source roots continue to use the production plain
BLAKE2s Merkle profile; this schema is only for the new original and own
quotient FRI line tracks.

Every integer below is unsigned little-endian. A tree descriptor is:

```text
"S31LTDV2" [8]
|| track [u8: original=1, own_quotient=2]
|| fold_height [u32]
|| tree_log_size [u32; 0..63]
|| root_event [u64]
|| sealed_key_digest [32]
|| line_hash_profile_digest [32]
|| column_count [u32; 1..256]
|| ordered unique column_identity_digests [column_count × 32]
```

The fixed profile digest is the framed role-9 hash of the exact bytes
`S31LINE2S31P2LEFS31P2PARM31LE32|P64`. Those bytes identify the leaf and
parent personalization and canonical M31 row/64-byte parent encodings. They
do not contain a truncated tree descriptor.

A manifest is:

```text
"S31LTMV2" [8]
|| sealed_key_digest [32]
|| fixed line_hash_profile_digest [32]
|| fold_count [u32; 1..64]
|| strictly descending fold_heights [fold_count × u32]
|| tree_count [u32; exactly 2 × (fold_count - 1)]
|| repeated (tree_byte_length [u32] || complete tree descriptor bytes)
```

The final fold height has terminal coefficients and no line tree. For each
earlier fold index `i`, descriptors must occur in original, own quotient
order, with that fold height and root event ordinals `17 + 3i` and `18 + 3i`.
The manifest digest is `BLAKE2s-256(S31BCS2 || role=9 || len:u64le ||
event=0:u64le || manifest_bytes)`. It fills the existing statement's
`line_profile_digest` slot; the statement's `key_digest` must match.
The whole manifest is capped at 512 KiB before allocation. Column digests
identify distinct key-owned columns; two columns may hold equal values while
their identity digests remain different. The `tree_log_size` and fold height
are both committed, but their arithmetic relation is not yet frozen by the
candidate Gate proof geometry. The selected key derivation must check it.

`verifyBoundOpening` checks that statement digest, exact root event, path
depth and canonical row before comparing a Merkle path. Its root argument
must be the root already absorbed at that named event. The selected verifier
must derive all descriptor bytes and ordered column identities from a sealed
key and checked geometry, retain the wrapper privately, and establish that
the root passed to the opening checker is precisely the absorbed root. These
custody and root-identity claims are **not** established by this module.

Exact Python/Zig vectors cover the bytes and digest. Invalid order, duplicate
track, wrong event, noncanonical shape, mismatched statement and path failures
are tested. This is byte-binding evidence, not a BCS/ROM or Circle FRI theorem.
In particular, consistent projection of one raw query through every fold
remains an explicit selected-verifier and LDR-theorem obligation.

The candidate `verifyBoundOpening` recomputes and hashes the complete
manifest for **each** opening. If there are `q` openings and `B` manifest
bytes, its statement check costs `q × B` hashed bytes; this has not been
benchmarked as a whole verifier. A selected verifier should admit the
statement once, copy or otherwise privately own the validated descriptor
roster, retain its digest in an internal cache, and then check each opening
against that cached binding and its authenticated root event. Exposing a
mutable cached roster would invalidate that reasoning. No such admission
cache or selected verifier exists in this candidate.
