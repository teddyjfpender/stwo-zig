# BLAKE3 Span and job identities

Added versioned native identity hashing through the BLAKE3 Span facade. One
sourceAt mapping owns a 32-byte zero-padded domain, u32 version/purpose/payload
count and little-endian canonical statement words. Statement preimages are 2144
bytes; job preimages are 1128 bytes and select the canonical job portion. Full
256-bit output is retained. Serialization validates before writing and allocates
no heap memory. This introduces no changes to legacy identity values.

The focused ReleaseSafe test-riscv-statement-codecs gate passed (16 seconds,
951 MB reported peak RSS). Three new checks cover shared job identity across
children/parent, distinct statement identities, framing, high-bit sensitivity,
invalid input/buffer rejection before writes, native/std hashing agreement and
recursive full-hash witness agreement. The existing exact hash-wire ledger checks
that claimed digest substitution leaves an unmatched wire; this is not a full
STARK proof. The ledger helper is shared with the original hash tests.

Remaining: constrain sourceAt mappings against authenticated production statement
wires; migrate snapshot/lineage/continuation identities and memory commitments;
update source projections, artifact/key admission and production recursion.
Defaults remain unchanged. Full Poseidon removal and recursion qualification are
not complete.
