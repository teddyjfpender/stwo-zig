# Remaining outer-wrapper ownership audit

The shared tracked allocator removes a non-semantic Ethereum runtime dependency
from both the legacy outer engine and the actual detached native-leaf producer.
The implementation body is identical after the type rename; diagnostics and the
legacy alias remain stable. This does not complete the legacy wrapper migration.

The legacy `recursive_segment_v2_outer_engine.zig` is still used by real
`recursive_temporal_parent_real_proof_test.zig` and concrete leaf wrapper callers.
Its private mint commits a verified capture, pointer-free publication and fixed
recursive witness together. The detached q193 producer does not execute this mint.
Consequently the detached complete-tree gate cannot qualify moving that code alone.

A cohesive future move has these owners:

- `recursive_segment_v2_verified_publication.zig`: core/frontend-only identities
  and validation; preserve its no-public-mint test and all identity domains.
- `recursive_segment_v2_verified_artifact.zig`: core/frontend plus publication;
  preserve its no-detached-mint test and transcript/witness receipt validation.
- `recursive_binary_verified_publication.zig`: canonical proof identity shared
  with other callers; review its whole public surface before moving it.
- `recursive_segment_v2_outer_engine_support.zig`: alias rejection, field encoding,
  verifier-tree assembly; replace concrete CPU engine only with an explicit type
  input while preserving channel/verifier types.
- `recursive_segment_v2_outer_engine.zig`: transaction, serialization/destruction,
  fresh decode/verify, private mint, explicit cohort contract. Bind backend and
  composition diagnostic capabilities at integration rather than importing CPU.

Use thin aliases at existing import paths, preserve nominal type identity, and
retain named test wrappers across module boundaries (Zig does not discover tests
across named imports automatically). Validate legacy publication and witness
fixtures plus its real concrete proof transaction. Then use the detached gate
for shared dependencies and confirm canonical bytes remain unchanged. Do not
remove the legacy route until its temporal-parent callers are migrated.
