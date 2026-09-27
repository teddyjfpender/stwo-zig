# Real native V2 RISC-V proofs with BLAKE3

The normal typed RISC-V proving and verification pipeline now has an explicit
experimental BLAKE3 engine selection. A verifier-safe blake3_engine_protocol module
owns the coherent channel/Merkle/proof aliases, and recursion.engine exposes
Blake3ProverEngineForBackend using the existing generic engine. Standalone BLAKE3
fixtures share these same protocol aliases. No production default was changed.

The existing native V2 nonfinal/final test is now one engine-parameterized helper,
used by both the default Blake2s engine and BLAKE3. Serialization/deserialization
uses the selected engine's Hasher. The BLAKE3 test additionally decodes its proof
under the default suite and checks that verification fails with
InvalidPreprocessedCommitment. The new test name avoids substring overlap with
the existing default-suite test filters.

Both suites execute the same ELF and prove the same one-cycle nonfinal and
two-cycle final segments. The logs show identical statement wire/authority IDs
across suites, with different relation-context/native-sum IDs as expected from
different Fiat-Shamir challenges. Native verification publishes an owned capture
only on success. Existing statement mutation, unchanged capture sentinel,
receipt/native-sum mutation, adjacency and final completion checks remain active.
The default-suite rebased leaf-local V3 test also passes.

Initial execution exposed a pre-existing fixture failure under current admission:
the native tests supplied label-derived placeholder memory digests. Both suites
failed before proving with MemorySnapshotMismatch. The tests now derive entry,
shared and exit memory identities from the runner's actual retained snapshots.
The same stale placeholders in the rebased default test were corrected too.
No source validation or AIR constraint was weakened or changed.

Final serial ReleaseSafe gate: 4/4 build steps, 3/3 tests passed. Total test runtime
20 s / 1 GiB; compile 53 s / 4 GiB. The test uses one query, zero PoW, blowup one
and fold step one for qualification only. It is not a canonical CSP benchmark,
production security profile, Ethereum workload or matched performance campaign.

| Suite / segment | Prove ms | Verify ms | Serialized bytes |
| --- | ---: | ---: | ---: |
| Default Blake2s, nonfinal | 2379.145 | 482.725 (with capture) | 26494 |
| Default Blake2s, final | 2399.547 | 385.310 | not serialized in this gate |
| BLAKE3, nonfinal | 4050.468 | 900.487 (with capture) | 26539 |
| BLAKE3, final | 4223.471 | 801.530 | not serialized in this gate |

BLAKE3 was slower than Blake2s in this sequential diagnostic. These numbers do
not demonstrate a speedup over Poseidon, and no cause has been established by
profiling. The comparison is recorded rather than omitted. Optimization remains
subsequent to complete implementation and qualification.

Scope: proof PCS/Merkle and Fiat-Shamir use BLAKE3. Existing V2 program/state and
sparse-memory commitments still follow their current Poseidon-based statement
semantics; guest-visible precompile behavior is unchanged. This is not removal
of all Poseidon or activation of a new production key family. Captures are now
available from a real BLAKE3 RISC-V proof, but adapting their native V2 transcript,
relation inventory and public-boundary authority into the joined BLAKE3 parent
remains unfinished. The fixture-only parent prefix cannot be reused as if those
protocols were identical. Full-key/artifact admission, Metal and parent-of-parent
qualification also remain.

Formatting and git diff --check passed. The final guard and initial failure both
reached terminal exit; no live build was left running and no broad suite ran.
