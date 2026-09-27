# Native BLAKE3 PoW in transcript sequencing

Exact predicate: trailing zeros of the first little-endian u32 of Frame.pow hash
must be at least bits, for bits 0..32. Equivalent to word AND low_bits_mask == 0.
Reuse the existing typed bytewise AND component and bind its output bytes to zero;
all other hash words have zero consumers. A full-width mask is required for 32
bits. Keep query-domain entry points restricted to 0..31; expose an explicit
low-bit-mask constructor for PoW without changing AIR semantics.

PoW verification does not modify digest or draw counter. Native PCS separately
mixes the nonce via mixU64 after checking it (core/pcs/verifier.zig). Represent
that absorption as its own existing operation, preserving domain separation.
Use the shared private-state frame router and producer counts. No new AIR/table.

Validate mask width 32 and existing query boundaries, native valid/invalid PoW,
zero difficulty, rejection above 32 bits, and full transcript proof with PoW,
a following draw, nonce absorption and another draw. A modest 8-bit nonce is a
fixture, not a change to production security. No production speed claim.
