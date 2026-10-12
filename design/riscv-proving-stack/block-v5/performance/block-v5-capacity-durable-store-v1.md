# Capacity proof-file transport

`block_v5_native_capacity_store_v1.Store` publishes and loads genuine B5CT
artifacts under independently admitted source policy. It does not register them
as NativeV3 proofs or switch the canonical block driver. Catalog, template,
exact counts, configuration and first-round roots come from the receiver's
actual common seal. The file roster contains only index, length and SHA-256.

Initialization copies bounded slot metadata and borrows immutable shape,
catalog and common-roster authority for its lifetime. Ordered indices support
binary lookup. One mutex protects publication/load state. Codecs intersect
per-policy limits with the store's file cap; total bytes and metadata have
independent limits. These caps are transport accounting, not a total PCS/RSS
budget. Production callers must retain the shared proving budget and bounded
coordinator.

The store allocator must be the producer proof allocator on publication and
the consuming fresh receiver allocator on structural loading. `Native.Proof`
uses an explicit allocator for destruction; the typed loader does not change
that ownership contract. Returned captures carry their own allocator. The
store and its borrowed directory/authority must outlive all active callbacks;
shutdown joins those callbacks before `deinit` releases slot metadata.

`sink().put` checks independently admitted roots and encodes one bounded
capacity envelope. Only successful durable publication consumes the producer's
proof. Allocation, limits, identity, roots, existing file and I/O errors retain
that proof. Filenames are `block-v5-native-capacity-{index}.proof` and cannot
collide with legacy native artifacts.

`loader().take` performs length/hash checks, structural decoding and first-round
root validation, returning an independently owned proof. It does not verify a
STARK. `verifyCaptured` instead routes the actual loaded artifact to the genuine
capacity fresh verifier and returns its owned capture. A failed load burns its
attempt slot; `requireConsumed` checks attempts, never cryptographic acceptance.
The complete receiver must still accept every genuine proof and close its
relations.

The distinct `B5CTFLS1` manifest is fixed width (12-byte header, 44-byte rows),
with streaming SHA-256 verification and an independently supplied expected
hash. Count, file size and metadata caps are checked before allocating its
array. The manifest does not grant a key, instance, source or proof receipt.

Shared `block_v5_artifact_files_v1` replaces duplicated durable publication and
pinned reads in the existing canonical bundle store. On the supported POSIX
hosts, it syncs a temporary inode, links it exclusively to the final name,
syncs the directory, then cleans the temporary name. Linking fails if a final
name already exists, including a concurrent publication; no existing artifact
is replaced. Before final publication errors clean the temporary file; a sync
error after linking removes the new final name and retains proof ownership.

The focused gate passes11/11: six new transport contracts, one prior durable
roster contract and four import checks. It exercises actual source-policy
admission with structurally valid literal postcards, successful publication and
deep loading, proof retention on failures, non-overwrite, tampering, streaming
manifest caps and exhaustive allocation failures. Genuine fresh-capture loader
and legacy loader bodies compile without invocation. Source and log snapshots
are recorded in `native-capacity-store-qualified-v1.json` under the Ethereum
block delivery CPU performance gates.

A subsequent6-check gate retains actual instantiated legacy ROM producer and
loader bodies and rechecks the prior manifest regression after the legacy
manifest writer also adopts shared exclusive publication. The receipt preserves
the11-check baseline hashes separately from these two affected source snapshots.

No guest, STARK, recursive proof, segment, device or benchmark ran in this gate.
Fused capacity transport, canonical driver/global activation and independently
verified complete-proof timing remain required.

The native B5CT and fused B5CF stores now delegate to one
`block_v5_capacity_artifact_store_common_v1.ForFamily` state machine. The
small family adapters retain distinct payload/policy types, wire grammars,
file and manifest names, errors and genuine fresh verifier entrypoints.
Native loading requires its fresh captured verifier; fused loading requires
both the genuine native proof and the independently sealed fused artifact.
Calling the wrong-family verification API is rejected at compilation.

Shared publication, SHA-pinned streaming manifests, binary slot lookup,
bounded metadata, fail-retaining producer ownership and one-shot consuming
loader behavior now have one implementation. Qualified original native and
fused snapshots are retained in their separate receipts; the shared-kernel
followup is recorded separately after its focused gate completes. This
cleanup does not activate the capacity driver or establish fresh proof
acceptance, process peak memory or speed.

The shared-kernel followup passes21/21 (14 named checks+7 imports),
recorded in `native-capacity-shared-store-qualified-v1.json` and
`native-capacity-shared-store-v1.log`. Both families' real verifier bodies
and legacy ROM I/O bodies are retained without invocation. The original
independent store snapshots remain intact in their baseline receipts.
