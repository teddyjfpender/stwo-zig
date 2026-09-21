# Shared native-leaf preparation qualification

`src/frontends/riscv/recursion/detached_native_leaf_preparation_v2.zig` owns the complete native-leaf preparation bundle: capture custody, cloned verifier plans, captured FRI and VM composition witnesses, transcript execution and challenge checks, boundary trace storage, Poseidon schedule, prepared authority, validation, and identity construction. The CPU integration file now selects the existing capture type, supplies an explicit seven-declaration core-preflight interface, and aliases the shared public API.

The transferred 736-line implementation is byte-identical after removing the factory indentation and normalizing the two dependency aliases. `transfer-audit.json` records equal normalized SHA-256 digests. The integration retains no alternate preparation implementation. Capture ownership still transfers only after every derived artifact validates; all error unwinding, authority checks, identity domains, and hash field order are preserved.

Validation passed: 12 focused ReleaseSafe tests and 14 ownership checks. The shared source import closure excludes concrete backends and CPU integration. The supplied capture and core-preflight types are explicit caller dependencies; this source-closure check does not claim that the remaining concrete core authority has moved.

Complete CPU and Metal commands rebuilt matching artifacts from the same source snapshot, generated the four-segment tree, exited producer processes, and verified serialized artifacts in fresh processes. Each backend passed 192 checks including malformed proofs and same-geometry statement substitution. All 21 serialized key/claim/proof artifacts remain identical across CPU/Metal and the canonical baseline. Metal retains the required native-table and parent typed GPU dispatch checks.

The next ownership move is the noncore owner plus its private contract, support, and runtime files. The concrete core authority and preflight implementation also remain in CPU integration. Typed GPU dispatch for all 37 leaf components remains a separate implementation task; this move does not activate it or claim production-security qualification. No speedup claim is made for an ownership-only change.

`source.patch.gz` and `source-snapshot.json` freeze the qualified code before this report and the subsequent goal-document update. The CPU/Metal summaries and `cross-backend.json` pin results and local evidence paths; focused and ownership logs retain the bounded checks.
