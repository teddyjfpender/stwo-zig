# Recursive artifact pipeline V1

Status: implementation contract; production activation remains unavailable until every gate in
this document is green.

## Implementation checkpoint (2026-09-01)

The shared substrate is implemented and gated: the immutable sharded CAS, exact `BlobRefV1`,
Zig-owned semantic/execution keys and `StageManifestV1`, append-only attempts, bounded CPU/RSS
scheduling, process-local lease transfer, selective invalidation, and the persistent framed worker
all pass cross-process acceptance. A second worker process resumes the committed output without
re-executing its producer.

The production leaf migration is in progress. The role-aware V3 boundary contract, changed-only
transition transport, cold reconstruction, split memory/Merkle evaluator, complete base witness,
and appended bridge component are implemented and gated independently. The remaining leaf work is
the q193 profile-owned prove/cold-verify transaction and one fresh canonical 210-segment capture.
The historical 210-leaf corpus contains no complete STWEMT01 set; the only retained compact runs
stop at 65 and 60 segments. They are diagnostics and must not be treated as resumable production
inputs. The next capture therefore executes the block exactly once and publishes STWEMT01,
STWIMT03, local source/journal authority, and a seal-last manifest in the same transaction.

## Objective

Make the canonical Ethereum 210-to-256 recursive block proof independently resumable at every
expensive stage without weakening verifier-owned admission. A completed proof stage is paid for
once. A later process may reuse its canonical bytes only after the current typed Zig validator
cold-opens them and remints a process-local capability.

The control plane may schedule, store, and report. It may not interpret a proof digest as proof
authority, construct verifier captures, or decide cryptographic admission.

## Non-negotiable invariants

1. A content digest identifies bytes; it never proves that those bytes are valid.
2. Fresh verifier capabilities and borrowed capture views are process-local and are never encoded.
3. A cache hit calls the artifact kind's typed `coldOpen` validator before a dependent stage runs.
4. Canonical proof bytes survive validator and producer upgrades. Validator drift invalidates the
   validation receipt first and triggers revalidation, not automatic reproving.
5. Publication is create-only and seal-last: temporary write, file sync, content measurement,
   immutable object publication, cold reopen, typed validation, then committed stage reference.
6. Dependency order is semantic. Child or shard reordering changes the semantic key.
7. Filesystem paths, timestamps, host power, wall limits, and worker counts do not enter semantic
   identity. They may enter execution identity and profiling evidence.
8. Production root publication requires a fresh-process transitive cold verification of the final
   root artifact and its campaign authority.

## Identities

### `BlobRefV1`

An immutable object reference contains exactly:

- artifact kind;
- artifact format version;
- native artifact schema version;
- byte count;
- SHA-256 of the exact bytes.

The store resolves a `BlobRefV1` only when all five fields match. A path is a local implementation
detail and is never part of the reference.

Large proof transports never round-trip through Python byte arrays. A Zig worker publishes or
stream-ingests the attempt output into the shared CAS, returns its measured `BlobRefV1`, and then
cold-opens that ref. Crash recovery may clone/link/stream-ingest a complete attempt file, but the
control plane does not read and rewrite a proof-sized buffer.

V1 reserves kinds 1 through 14 for raw bytes, semantic keys, execution keys, the canonical Zig
stage manifest, validation receipts, profile receipts, execution artifacts, proof artifacts,
capture transport, recursive nodes, journals, statements, programs, and sources respectively.
Kind 9 is transport only and never denotes a fresh verifier capability. Kind 10/schema 1 is the
recursive-node envelope. Controller JSON indexes must use an explicitly registered raw/application
codec; they may not alias kind 4, which is exclusively the canonical Zig `StageManifestV1` wire.

### `SemanticKeyV1`

The semantic derivation key is a domain-separated canonical hash of:

- stage kind and stage schema version;
- local task identity: a stable campaign namespace, height, index, and global ordinal where
  applicable;
- protocol, program, AIR/profile, PCS, security, statement, and provider-policy identities;
- ordered role-tagged input `BlobRefV1` values;
- options that can change the witnessed statement, transcript, or proof semantics.

The semantic key does not assume deterministic proof bytes. More than one valid output blob may be
associated with a semantic key. Each candidate must cold-validate before selection.

Candidate sets are append-only. A profiling run may add a second valid blob for the same semantic
key without replacing the run's selected output, so `--reprofile` does not invalidate descendants
by accident. Promotion of a different candidate is an explicit ref-generation transaction; its
exact-byte dependency change then invalidates only the affected ancestor path.

The campaign namespace is not the digest of the campaign's complete leaf inventory. A node key
binds only the topology/profile authorities that govern that node and its ordered direct input
references. Consequently an input mutation invalidates that node and its ancestor path, not
unrelated branches. Legacy whole-plan authorities live in remintable validation envelopes until a
versioned local-node authority replaces them; they do not poison the reusable proof-blob key.

### `ExecutionKeyV1`

The execution key binds the semantic key plus:

- producer and verifier executable identities;
- source/build/toolchain and optimization identities;
- backend and retention policy;
- worker, memory, timeout, and other resource policy.

Execution-key changes are useful for profiling and provenance. They do not invalidate a
semantically reusable proof that the current verifier accepts.

Canonical production key derivation is Zig-owned. The control plane consumes sealed key manifests
emitted by a typed Zig adapter and does not maintain a second cryptographic-key implementation.
Python-only mock stages may derive fixture keys, but cross-language golden vectors must prove byte
parity before those helpers can be used for production artifacts.

## Durable and live states

Durable artifact state is limited to:

- `canonical_transport`: canonical bytes and dependencies are present;
- `validated`: a typed validator receipt exists for a particular validator identity;
- `committed`: the stage output reference was atomically published into a run.

`fresh_verified` is deliberately absent. `coldOpen` produces an owned in-process lease whose
destructor invalidates all borrowed views. A live runner may ownership-transfer a child lease to
its unique parent to avoid repeated verification. After a crash, the lease is reconstructed by
cold verification.

A durable validation receipt records that a named validator accepted a specific blob and authority
set. It is evidence and a revalidation index, not a transferable verifier capability. A new process
still calls the current typed `coldOpen` before using the artifact as a proof input. Within one
process, the runner keeps or ownership-transfers the resulting lease along the ready frontier so
the same artifact is not verified repeatedly.

## Stage contract

Every stage adapter provides:

1. `deriveSemanticKey(inputs, semantic_options)`;
2. `deriveExecutionKey(semantic_key, execution_options)`;
3. `coldOpen(store, artifact_ref, authorities) -> Lease`;
4. `build(context, input_leases) -> OwnedArtifact`;
5. `encodeCanonical(OwnedArtifact) -> bytes`;
6. `validateFresh(Lease, expected_task)`;
7. `profileProjection(attempt) -> StageProfileReceiptV1`.

The generic runner implements lookup, locking, attempts, atomic publication, retry, and dependency
scheduling. Cryptographic stage adapters remain Zig-owned.

Ready-node scheduling is parent-completion-aware. When two sibling leases are live, their parent is
preferred subject to CPU/RSS tokens; the runner ownership-transfers those leases, commits the
parent, and drops the children. The lease frontier is bounded and evictable. This avoids holding a
breadth-wide set of verifier captures or reopening a child that can immediately be consumed,
without coupling durable restart points to one traversal order.

Token admission is not a per-node preflight check: the scheduler accounts for all concurrently
running stages and never lets their declared CPU or RSS reservations exceed the configured totals.
Lease-bearing siblings are affinity-scheduled to the same persistent worker session. Work may move
to another session only through durable artifact refs followed by that session's own `coldOpen`.

## Attempt journal

Each numbered attempt is append-only and follows:

`intent -> running -> outputs_published -> validated -> committed`

Terminal `failed` and `indeterminate` records retain logs and inventories. An output object without
a committed reference is an orphan, not authority. A subsequent attempt may reuse it only through
ordinary lookup and cold validation.

Recovery never assumes that an interrupted producer failed. It first inventories the immutable
attempt directory, reconstructs candidate `BlobRefV1` values from any complete outputs, ingests
them into CAS, and asks the typed Zig adapter to cold-validate them against the pending semantic
task. A valid candidate proceeds through `outputs_published -> validated -> committed` without
proving again. Only an absent, partial, or rejected candidate causes a new proving attempt.

## Artifact DAG

The canonical campaign contains:

- one compact execution capture and 210 independently reusable incremental-memory transition
  authorities;
- 210 independently reusable real-leaf proof artifacts whose memory cost is proportional to the
  touched transition rather than the cumulative block state;
- 46 proof-bearing canonical-empty leaf artifacts;
- 128 height-one recursive folds: 105 real/real and 23 empty/empty;
- 64, 32, 16, 8, 4, 2, and 1 upper folds;
- one root publication referencing global parent ordinal 254.

The 127 upper artifacts include the root. The matched 840-segment A/B corpus is a separate
diagnostic namespace and cannot be relabeled as the canonical 210-leaf campaign.

The 511-node DAG contains one recursive wrapper proof per node. Native real-leaf proof artifacts
are durable inputs to the 210 real leaf-wrapper nodes, not additional tree nodes. Likewise,
the common fold is the parent proof itself: it reuses the typed H1/upper verifier logic inside one
fixed padded circuit and must not first produce a heterogeneous native parent proof and then wrap
that proof in a second recursion layer.

### Incremental memory boundary

The legacy omitted-provider bundle is a useful cold-verification and migration artifact, but it is
not the production 210-leaf execution plan. Rebuilding the complete cumulative sparse-memory tree
and its provider call list for every segment repeats unchanged state and makes block cost grow with
the sum of all prefix states. The production leaf path instead uses a role-aware successor to the
existing changed-only incremental-memory protocol. The current V1/V2 transition code is
diagnostic: it emits both boundary sides for every touched word and therefore does not implement
the canonical first-leaf public-input or final-leaf public-output/completion policy.

1. one authenticated execution streams compact STWEMT01 tapes and, while the full session tree is
   live, publishes one canonical transition frontier for each ordered segment;
2. a leaf worker cold-opens its tape, source/journal authority, and transition frontier, then
   independently replays only that leaf's typed CPU and precompile rows;
3. continuation roots always authenticate the complete sparse state so adjacent leaves compose;
   Merkle membership is not role-filtered or replaced by a caller-provided zero;
4. the leaf AIR separately derives memory-bus row inclusion from the authenticated
   `WordState.role`, segment role, public I/O layout, and completion authority. Public boundary
   words are added to the opened inventory and their suppressed side is supplied only by the typed
   public-data relation—callers never supply acceptance booleans;
5. the leaf AIR binds the replayed memory-access inventory to those exact role-derived rows, proves
   the full entry root with the canonical multiproof, hashes only changed exit paths, and constrains
   the bridge rows for unchanged leaves and reused subtrees;
6. entry/exit roots, CPU boundaries, and transition-authority lineage compose in exact segment
   order, while every native leaf remains an independently cacheable proof artifact.

The transition frontier is transport authority, not proof authority. Its SHA-256 seal cannot
replace the field-level memory, Merkle, Poseidon, root, and bridge relations. The first segment
initializes the session tree from the admitted program/input state; every later frontier must bind
the previous transition identity and previous exit root. A crash after capture resumes from the
canonical tapes/frontiers without reexecuting the block. A crash during proving rebuilds only the
missing leaf from its compact artifacts.

Production activation requires a versioned role-aware transition authority and a derived admission
from the complete typed component/profile/PCS/statement contract. Neither
`incremental_transition_v2.PRODUCTION_ACTIVE` nor a successor availability bit may be flipped as a
raw flag. Until that gate is green, omitted-provider bundles may be retained for differential
evidence and wrapper development but may not be scheduled as the final 210-leaf campaign merely
because they cold-verify.

A leaf change invalidates that leaf and one ancestor per height. It does not invalidate unrelated
leaves or siblings. Until legacy plan-wide identities are replaced by versioned local-node
authorities, expensive local proof blobs may be retained while their task-bound envelopes are
reminted and cold-validated.

## Recursive node ABI

`RecursiveNodeArtifactV1` is the common durable envelope for proof-bearing leaves and internal
nodes. It binds:

- node kind, height, index, and global ordinal;
- a fixed `NodePublicV1` output ABI;
- circuit, program, AIR/profile, PCS, and statement identities;
- ordered child artifact references;
- proof blob reference and preprocessed root;
- canonical content identity.

`RecursiveCircuitRegistryV1` is the trust list for supported circuit hashes and configurations.
Different circuit semantics may share one recursive proof geometry only when `PaddingParityV1`
proves equality of padded preprocessed-column log sizes, trace log size, PCS configuration, and
output ABI. Padding is authenticated and constrained. A parity mismatch is a planning error, not
permission to relabel or fabricate inactive rows.

The typed RISC-V frontend boundary remains kind-specific. A leaf adapter cold-opens its native
proof artifact and verifier-owned capture, then projects the frozen 412-word `NodePublicV1` and an
authenticated recursive-layout authority. The registry maps that authority to an allowed circuit
hash and padded geometry. SHA-256 custody fields are never reinterpreted as field elements, native
provider omissions are never relabeled as full-provider captures, and empty rows are never treated
as proved unless the empty circuit constrains them. Above this boundary, one registry-aware binary
fold ABI handles every height; below it, native leaf validators retain their exact AIR-specific
types.

For the Ethereum block campaign, "native leaf" always means one joined proof of the complete
segment semantics: authenticated RISC-V execution, role-aware incremental memory, Keccak-f, and
secp256k1 recovery. A proof of the RISC-V core plus incremental bridge is useful substrate but is
not an Ethereum leaf, cannot enter the production campaign DAG, and cannot mint a wrapper lease.
The canonical native artifact and its fresh verifier capture must retain the base statement, the
Ethereum extension statement, base and extension interaction claims, the incremental bridge
claim, and their single transcript/PCS transaction. Its positive gate must execute genuine
Ethereum precompile activity; a core-only execution session is insufficient even if all four PCS
commitments verify.

## Store and control plane

The first implementation reuses:

- the Metal artifact store's immutable content-addressed publication;
- the Ethereum block controller's no-follow reads, fsynced hard-link publication, attempts, and
  crash recovery;
- Zig proof-wire codecs and product-specific canonical validators;
- prover stage, task, and exact-work profiling.

The persistent store adds direct digest-addressed reopen, keyed locking or equivalent concurrent
publication, typed artifact kind/schema admission, validator receipt indexing, and a separate
explicit deep audit/index-rebuild operation. Normal reopen must not scan or rehash unrelated CAS
objects.

The Python control plane exposes:

- `plan`: derive and validate the DAG and show resources/cache decisions without proving;
- `run`: execute ready stages under CPU and RSS token admission;
- `resume`: reopen committed refs and continue missing or invalid stages;
- `verify`: shallow, cold, fresh, or transitive-root verification;
- `status`: non-authoritative progress projection;
- `explain-cache`: first differing key field and transitive invalidation set;
- `publish-root`: deep cold verification followed by seal-last publication.

All semantic operations are delegated to typed Zig subcommands.

The stable subprocess surface is one versioned `recursive-pipeline-worker-v1` request/result
protocol backed by a compile-time Zig stage registry. Its operations derive sealed keys, describe
resources, cold-open an artifact, or build one task. The stage kind selects a typed adapter inside
Zig; Python does not switch on AIR layouts or proof fields. Existing bespoke product commands may
remain as compatibility entrypoints, but pipeline integration is added behind this worker rather
than multiplying controller-specific CLIs.

The worker supports a long-lived framed session as well as a one-shot compatibility mode. Only the
long-lived Zig process may retain live verifier leases; the scheduler assigns sibling/subtree work
to that process when practical and refers to leases by process-local opaque handles. Handles never
enter manifests or CAS. If the worker exits, all handles vanish and the next worker reconstructs
them from durable refs with ordinary `coldOpen`. A one-shot `build` cold-opens and consumes all of
its inputs internally; Python can never receive or forward a serialized capture.

Lease consumption is explicit in the framed response. A successful parent `build` returns the
exact ordered handle IDs it consumed; the controller marks those handles released without issuing
`closeLease` again. A failed request must report an all-or-none consumption outcome before the
session accepts another request. Silent handle disappearance and double-close are protocol errors.

## Profiling receipt

Every attempt emits a correctness-independent profile receipt binding semantic, execution, and
output identities and recording, when available:

- wall, user, and system time;
- maximum RSS, peak footprint, swaps, faults, and I/O;
- object bytes read, hashed, written, and reused;
- worker/backend/retention policy and cache decision;
- phase timings for authority reopen, child cold admission, materialization, Tree0/1/2,
  interaction/PoW, prove, encode, destroy/decode, cold verify, and publication;
- observed host and power state as nonblocking diagnostics.

`--reprofile` bypasses semantic output reuse for the requested stage while preserving correctness
artifacts from other stages.

## Required gates before the real campaign

1. Store roundtrip, persistent reopen, corruption, truncation, collision, concurrent publication,
   wrong kind/schema, and allocation-failure tests.
2. Semantic/execution key sensitivity and validator-version revalidation tests.
3. Cross-language golden vectors for `BlobRefV1`, semantic/execution keys, and stage manifests.
4. Mock 256-node DAG with crash injection at every attempt transition, including adoption of a
   complete uncommitted output without rebuilding it.
5. Selective invalidation: changing leaf 17 invalidates leaf 17 and exactly its eight ancestors.
6. Explicit candidate promotion, stale/rejected-promotion denial, validator-version revalidation,
   same-run writer exclusion, and execution-only reprofile tests.
7. Concurrent token admission and worker-affinity tests, including success/error lease consumption,
   bounded frontier, worker death, and no double-close.
8. Large-artifact streaming/CAS adoption test proving the controller never materializes proof bytes.
9. Recursive padding-parity and registry mutation tests.
10. Canonical codec and cold-open tests for every stage adapter.
11. An eight-leaf real mini-tree with process teardown between selected stages.
12. One retained compact/incremental native leaf and one recursive fold with full profiling; the
    legacy omitted-provider leaf remains a differential migration gate only.
13. Fresh-process transitive verification of the mini-tree root.

Only after these gates may the 210-to-256 campaign begin. Every committed campaign artifact must
then be reusable by `resume`; no failure may require deleting the workspace or restarting an
unrelated completed stage.
