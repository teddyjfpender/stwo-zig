# Draft RFC: explicit Native CUDA runtime policy installation

Status: proposed in [RFC #329](https://github.com/teddyjfpender/stwo-zig/issues/329),
not approved or implemented. Tracking: A1 issue #327.
Invariant owners: `cuda-backend`, `riscv-cuda-integration`; consult the Native
and Cairo product owners. This proposal does not qualify GPU execution.

## Exact decision requested

Approve one additive package/ABI transaction to remove ambient environment
reads from the Native CUDA implementation without deleting live flag paths or
weakening the existing forbidden-token check:

- Add `runtime.native_policy` under the existing `stwo_cuda_backend.runtime`
  namespace, with the schema and installation operation below.
- Add matching declarations under the existing `abi.runtime` namespace.
- Bump `stwo_cuda_backend` and its build manifest from `0.1.0` to `0.2.0`.
  Add uniquely collected signature and invariant tests to its contract suite.
  Public module names, dependencies, layers and top-level API ledger stay as
  they are; unrelated ledger drift is outside this transaction.
- Move the 36 existing native policy inputs listed below to an explicit,
  immutable installation snapshot supplied by their host gateway. Preserve
  their current value parsing, defaults, selected branches and rejection
  behavior. No new flag or default promotion is authorized.

The source audit finds 17 remaining files with direct native environment
reads, including a helper used for the two legacy DEEP/sample flags. Their
keys already exist in the registry. Several are marked
`retire-after-native-default`; deleting them before the GPU promotion gates
would violate the delivery contract. A typed installation boundary preserves
those paths while satisfying the current source policy.

## ABI and schema

Add exactly one C ABI function:

```c
int32_t stwo_exec_context_install_policy_v1(
    const struct StwoCudaNativePolicyV1 *policy);

struct StwoCudaNativePolicyEntryV1 {
    uint16_t key;
    uint16_t reserved;       // zero
    uint32_t byte_len;       // excludes terminator, at most 4095
    const char *value;       // borrowed for this call only
};
struct StwoCudaNativePolicyV1 {
    uint32_t abi_version;    // exactly 1
    uint32_t entry_count;    // at most 36, sorted unique keys
    const struct StwoCudaNativePolicyEntryV1 *entries;
};
```

On supported 64-bit hosts, both structs are 16 bytes. Entry offsets are
0/2/4/8; snapshot offsets are 0/4/8. Mirror these with Zig `extern struct`
types and compile-time layout/signature checks. The public Zig operation is
`runtime.native_policy.install(snapshot: *const SnapshotV1) runtime_error.Error!void`.
The enum values below are the complete V1 key set. Unknown keys/versions,
duplicates, unsorted entries, nonzero reserved fields, invalid null/count
combinations, embedded NUL and oversized values reject with the existing
invalid-value status before publishing any snapshot or creating device state.
The bytes may otherwise be arbitrary environment bytes; do not add a UTF-8
restriction. Missing keys retain their existing unset/default semantics.

The operation copies all entries and value bytes. Caller mutation/free after
return cannot affect native behavior. Native C++ helpers read only the owned
snapshot using private typed-key accessors; they perform no ambient reads.
Existing per-flag parsing remains in its owning code, preserving its exact
handling of unset, empty, malformed and boundary values.

## Installation, failure and lifetime

The host gateway captures the existing inputs once during process/runtime
installation, before constructing the first context. Existing CLI environment
selection stays available through that gateway; no request reads environment
or mutates policy. Update every in-repository direct native client, including
the separate admission fixture, in the same change.

The installation is process-wide, matching the current cached native policy.
An identical raw snapshot is idempotent. A different snapshot after installation
or first context construction rejects; it cannot mix arena policies across
contexts or race an active request. An existing constructor used without an
explicit snapshot freezes the all-unset policy. Direct C users therefore must
install a snapshot to select non-default modes; this migration is part of the
owner decision, not an implicit compatibility assumption. Existing constructor
signatures and the 16-byte ContextOptions ABI do not change.

Serialize installation and context creation. Validate into a separate staging
owner; publish atomically only after complete validation/copy. Failed admission
must leave the previous owner intact and release its own staging resources.
No public reset, request-time setter, environment callback or global environment
wrapper is added. Snapshot storage lives through all contexts and final process
teardown, with no device allocation. The fixed setup bound derives from 36
keys times 4096 bytes, plus two entry/header sets for transactional installation:
less than 300 KiB host storage, zero per-request policy allocation. Preserve
all existing cancellation, failure, lane-join and device teardown invariants.

## Complete V1 key set

| Key | Existing input |
| --- | --- |
| 1 | `STWO_RV64_ALLOCATION_OBSERVER` |
| 2 | `STWO_RV64_COMPACT_EAGER_STATE` |
| 3 | `STWO_RV64_DEEP_COORDINATES` |
| 4 | `STWO_RV64_DEEP_TIMING` |
| 5 | `STWO_RV64_DEVICE_ARENA` |
| 6 | `STWO_RV64_DEVICE_ARENA_CHUNK` |
| 7 | `STWO_RV64_DEVICE_ARENA_POISON` |
| 8 | `STWO_RV64_DEVICE_ARENA_PREMAP` |
| 9 | `STWO_RV64_DEVICE_ARENA_RESERVE` |
| 10 | `STWO_RV64_DEVICE_ARENA_SMALL_CHUNKS` |
| 11 | `STWO_RV64_DEVICE_ARENA_STACK` |
| 12 | `STWO_RV64_EXEC_SYNC` |
| 13 | `STWO_RV64_M8_ASSIGNMENT_DUMP` |
| 14 | `STWO_RV64_M8_ASSIGNMENT_DUMP_MIN_LEVELS` |
| 15 | `STWO_RV64_M8_ASSIGNMENT_FLOW` |
| 16 | `STWO_RV64_M8_B2N_WIDE` |
| 17 | `STWO_RV64_M8_DEEP_LEGACY` |
| 18 | `STWO_RV64_M8_FFT_SMALL` |
| 19 | `STWO_RV64_M8_GKR_BATCH_PAR` |
| 20 | `STWO_RV64_M8_LOGUP_BLOCK_INVERSE` |
| 21 | `STWO_RV64_M8_MERKLE_FUSED` |
| 22 | `STWO_RV64_M8_N2B_WIDE_MIN_LOG` |
| 23 | `STWO_RV64_M8_N2B_WIDE_ROWS` |
| 24 | `STWO_RV64_M8_SAMPLE_LEGACY` |
| 25 | `STWO_RV64_M8_WITNESS_COALESCE` |
| 26 | `STWO_RV64_N2B_WIDE` |
| 27 | `STWO_RV64_NVTX` |
| 28 | `STWO_RV64_PCS_IDLE_CACHE_BYTES` |
| 29 | `STWO_RV64_PCS_PHASE_BOUND` |
| 30 | `STWO_RV64_PCS_PHASE_TIMING` |
| 31 | `STWO_RV64_PCS_ROLLING_BETA2` |
| 32 | `STWO_RV64_PCS_STREAM` |
| 33 | `STWO_RV64_PCS_STREAM_CHUNK_WORDS` |
| 34 | `STWO_RV64_PINNED_STAGING` |
| 35 | `STWO_RV64_PINNED_STAGING_SLOT` |
| 36 | `STWO_RV64_PINNED_STAGING_THREADS` |

## Executable contract before implementation

Add provider signature/layout tests first, then host-only ownership and refusal
coverage for: every key and unset/empty boundary, unknown version/key, malformed
pointer/count combinations, duplicate/order/reserved refusal, length/NUL limits,
caller mutation/free, identical retries, conflicting retries, concurrent first
installation, first-context freeze, failure without partial publication and
zero request-time allocation. Pin both existing native parsing and host-gateway
selection with fixed inputs; do not silently choose registry prose over actual
source when they differ. Any such discrepancy stays visible for its owner.

Use the existing runtime-contract and CUDA backend package gates in Debug and
ReleaseFast, plus unchanged complete Native CPU/core/frontend byte-identity
safety nets. The forbidden native API/token check remains unchanged and must
find zero ambient reads after migration. Keep the source-completeness and
CuMetal enrollment refusals; this RFC does not reclassify unsupported sources
or claim translation/hardware evidence. GPU qualification remains deferred.

## Budget and boundaries

Conditional implementation allowance: at most +650 net code/test lines, zero
new runtime flags, scripts or top-level launchers. Positive growth owns copied
installation inputs, transactional publication, explicit lifetime and executable
refusal/concurrency invariants; measure moves without removal credit. Count
configuration, documentation and receipts separately. Drafting this proposal
has a zero-code budget and does not authorize implementation.

No proof format, golden vector, protocol revision, stack/memory ceiling,
legacy deletion, kernel arithmetic, launch schedule or release status changes.
Rollback reverts the additive policy ABI, gateway migration and version bump as
one transaction. The original source/runtime remains archived and recoverable.
