# OP execution improvement loop

Keep the native reference on the pinned upstream Kona/Revm/MPT semantics. Build
each guest candidate explicitly and retain ELF/input hashes. Compare the four
consecutive fixtures and their shared range, then the other four larger fixtures.
Every measured result must match the external fixture hashes, native eager/lazy
execution and the independent machine oracle. Guest validation must still reject
the malformed header, corrupted used preimage and wrong computed block claim.

Track instructions/gas, service calls/permutations/bytes, service RAM word
transitions, input size and whole-range reuse. Fewer CPU instructions may move
work into a more expensive service. Keep bulk memory optional until complete
physical proofs settle that tradeoff. Do not compare our instruction count with
another prover's cycles without accounting for service work and workload scope.
Do not substitute historical Sepolia fixtures for current Mainnet/Base coverage.

Capture comparisons use identical geometry and identical captured-value digests.
Record per-child RSS and capture settings. Prefixes cannot qualify a full block;
input preparation and native geometry plans cannot qualify a proof.

On a qualified GPU host, first produce one complete native/recursive OP execution
proof and receive it independently with caches disabled. Then measure cold and
warm resident requests for both frontier and memory variants under the same
device/host limits and explicit security/format selectors. Preserve failures,
peak memory, proof bytes, queue time and whole-request wall time. A source change
gets new proof/receiver receipts before its timing is promoted.

The next architectural gate is authenticated Kona L1 derivation and blob/KZG
validation binding the exact payload commitment in `metadata.rs`. Join that with
execution in recursion, then anchored L1/reorg handling and a running accumulator.
The settlement route is STARK compression and direct STARK verification; no
SNARK wrapping. Never replace a missing bind or verifier with a success flag.
