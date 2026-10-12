# Block execution transition sidecar

The block execution sidecar proves memory transition emissions against the
**same typed opcode main commitment** as a freshly verified native execution
proof. One sidecar STARK covers every access slot in one execution instance.
Its 48 byte/carry witness columns per slot, transition interaction, exact
active-event count, and universal byte-range requests are constrained in the
quotient. The execution event count is therefore a verified claim, rather than
a host replay count.

The producer derives the ordered slot roster with
`block_execution_sidecar_batch_v2.slotsFromStatement` from the native statement.
It constructs each `block_execution_sidecar_trace_v2.Trace` from the native
committed `opcode_columns.components[i]` and the public segment clock frame.
`ForBackend(Backend).commitFirstRound` commits the exact native fixed/main
column lists followed by the sidecar witness tree. Its first two roots must
equal the native proof's fixed/main roots. The witness root, native roots, and
the separate execution byte-table roots enter the bound SourceSeal first-round
roster before the 47 frozen universal draws and block-specific challenges.

For Ethereum SHA segments, `block_execution_sha_artifact_v2.ForBackend(Backend)`
packages this into two phases. `init` takes the segment witness, prepared native
key, and public leaf clock frame; it exposes `native_roots`, `witnessRoot()`,
`event_count`, and the exact execution 8x8 `counter` for a separate table
first-round commitment. After all roots and the execution shard plan have been
sealed, `proveAndSerialize` returns the native artifact and sidecar wire. Its
event count is a preseal witness census that the receiver checks against the
AIR-constrained count; it is not independent proof authority.

The serialized receiver is
`block_execution_batch_receiver_v2.ForBackend(Backend).verify` for base native
execution or `.ForEthereumShaBackend(Backend).verify` for the Ethereum SHA
extension. It accepts the existing B3EXART1 or B3SHART1 native artifact, a
postcard-encoded sidecar STARK, and its typed claims. The caller independently
pins the prepared native key, SpanStatement, SourceSeal, instance index, PCS
configuration, and sidecar witness root. The receiver decodes and freshly
verifies the native proof, derives the complete slot roster from the prepared
statement and public span, checks the sidecar's native root pair and column
logs against the fresh capture, then freshly verifies the sidecar and the v3
leaf binding. A five-tree allocation-free preflight checks sidecar proof shape
before postcard allocation.

Execution byte requests use a distinct table family. The plan in
`block_execution_range_shard_v2` hashes the exact per-instance event counts
and uses a conservative field-safe shard cap. Its family-eight table roots and
family-nine plan digest are sealed independently of the sorted-memory table
family. `block_execution_range_table_v2.closed` cancels all proved execution
range requests against freshly verified table receipts. The conservative cap
uses 35 requests per event to reuse the existing table PCS API; the sidecar
actually emits 14 requests per event.

The focused `test-block-execution-native-root-v2` suite proves and freshly
verifies a real base RISC-V fixture and a real Ethereum SHA/Keccak extension
fixture, including exact native-root parity, all-slot census, serialized
receiver roundtrip, and v3 leaf binding. These are diagnostic q8/PoW0 tests.
The receiver returns an execution receipt, not a complete-block result;
sorted-memory transition closure, both byte-table families, initial-state
authority, and an independently pinned initial-image anchor are admitted by
the complete-block batch receiver.
