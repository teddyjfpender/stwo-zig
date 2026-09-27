# Caller-pinned full-width base execution manifest

Status: implemented and syntax checked; runtime qualification pending in
/tmp/blake3-owned-base-run-proof-v2.log. The earlier live aggregate compatibility
binary predates this manifest and cannot qualify it.

B3EXADM1 carries source ELF/input SHA-256 labels, exact PCS configuration, the
full-width public execution statement, bounded commitment schedules, plan identity
and the typed execution transcript authority. Its BLAKE3 identity covers the whole
versioned encoding. The decoder checks that independently supplied expected
identity before allocating decoded statement/schedule storage. Caller source
labels and exact PCS configuration must also match. The decoder recomputes the
typed transcript authority after reconstruction, protecting against semantic drift.

The source labels are not a replacement for product-level validation of actual
ELF/input bytes against the public program and I/O claims. CLI integration still
needs that check and artifact/report routing. This module does not activate a
production default or admit a received key by its own embedded ID.

The real base proof fixture constructs the prepared verifier from the admitted
manifest, then destroys the decoded manifest owner before proof verification.
Negative checks cover wrong source, wrong policy, tampering rejected with an
allocator that fails on its first allocation, a newly pinned but inconsistent
transcript authority, and all manifest decoder allocation failures.

Expanded Ethereum/block proving remains deferred. This is base transport and
admission work needed to replace the remaining production commitment path.
