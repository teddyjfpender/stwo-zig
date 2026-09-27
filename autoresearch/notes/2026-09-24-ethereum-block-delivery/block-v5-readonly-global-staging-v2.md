# Shared readonly provider staging and replay

Status: implemented source; focused qualification is in progress. No PCS,
STARK, guest, segment, forest, device or benchmark is executed by this batch.
The complete canonical driver/receiver and recursive closure remain unfinished.

The original job admits its immutable input selection once. Native and caller
live-row observers update one reused interval counter vector using owner- and
generation-bound tokens. A whole source remains in one field-safe group; source
mass is reserved before observation and partial failure poisons collection.
Physical roots and exact census are required before a source record completes.
Counter grammar is explicitly versioned and bound by the global roster/ABI.

Completed group counters are stored in exclusive files. The bounded reader
validates the original complete file once and decodes at most32,768 fragments at
a time, using16KiB buffered reads rather than a filesystem call per6-byte record.
Each complete file's canonical fragment stream produces scope-bound chunk SHA
pins for later independently scheduled replay. Those pins provide transport
integrity, never source/proof/Plan authority.

`block_v5_readonly_input_global_staging_v2.zig` implements the real next phase:

1. Preflight group scope, file bytes, exact provider count and metadata limits.
2. Read one fragment shard, derive its actual typed shape and ordinal digest,
   generate real provider columns, and tally every9-plane range request including
   padded rows.
3. Commit the original provider PCS and dedicated original range PCS. Retain
   their real roots and value metadata, then release both PCS owners, columns,
   fragments, ordinals and the range counter before the next shard.
4. Bind every source/provider/range pin into the original challenge-seal roster.
5. Later workers load only their bounded, scope-pinned chunk; rebuild the actual
   witness and range counter, validate exact admitted metadata and recommit roots
   before any interaction proving. Both genuine proof families use their original
   kernels and the common sealed range inverse table.

This removes full-file rehashing per replayed provider and keeps heavyweight
state per active worker rather than per block. Witness limits do not bound PCS
or process RSS: those allocations remain charged to the original job allocator.
Whole-block performance and simultaneous-worker peak memory are unmeasured.

The focused source root retains genuine collection, replay, proving and teardown
bodies without invoking them. Behavioral checks cover token forgery/cross-owner
reuse/generation overflow/abort, exact whole-source grouping, allocation failures,
buffer and shard boundaries, chunk mutation/scope/truncation, zero provider
absence, metadata caps and actual padded range census. Historical first-attempt
compile errors remain in `global-readonly-staging-focused-v1-result.json`; a
successful newer receipt is required before calling this source batch qualified.

## Runtime planning assumptions

The user-facing1–3-hour M1 full-block estimate is a low-confidence planning range
for block24,628,607, at70queries/26PoW bits including recursive closure. It is not
a measured result or an extrapolation proven by the new component checks. The
stopped baseline's collection/initial commitments took1,650.976s; roughly80s
sidecar and17.6–22.4s recursive-leaf observations exclude native proving. No
complete timing exists for the redesigned path.

Conditional hardware scenarios apply an assumed *effective whole-pipeline*
speedup to that already uncertain range. Strong desktop CPU2–4x gives15–90min;
many-core memory-bandwidth-rich server4–10x gives6–45min; distributed4–8CPU
servers12–30x gives2–15min; complete resident single-GPU10–30x gives2–18min;
complete overlapped4–8GPU40–100x gives36s–4.5min. These speedup factors are
unmeasured model inputs, not hardware or prover benchmark claims. Multi-GPU and
distributed dispatch are not qualified current capabilities.

Serial work limits latency even with unlimited resources. If1% of that modeled
work remains serial, its floor is36–108s. Reaching a six-second block latency
requires reducing that serial work as well as accelerating and overlapping the
parallel proofs. ZisK's published prefetch/completion slots/generated AIR kernels
and overlapped recursion are relevant architecture patterns, not performance
evidence for our prover: [v1.3.0-alpha release notes](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha).
