# Raw query batches in the native transcript sequence

Exact state-machine integration: add raw query operations to the existing
absorption/secure-draw sequence. Reuse the query batch builder, preserving state,
advancing counters by ceil(count/8), and consuming no counters for zero queries.
Operation order alone supplies query start counters. Producer copy counts sum
both field draws and raw-query consumers. No alternate serialization or masking.

Extend the test-only roster to six AIRs (hash G/XOR, boundary, challenge, byte
routing, query masking); production rosters and identities remain unchanged.
Validate a mixed sequence with a partial query block, a following field draw,
absorption reset, empty queries and another draw. Compare native outputs and
trusted columns; prove the entire sequence with real tables and core verifier.
No new algorithm or security parameter. Path sorting/deduplication/folding and
PoW remain separate integration obligations.
