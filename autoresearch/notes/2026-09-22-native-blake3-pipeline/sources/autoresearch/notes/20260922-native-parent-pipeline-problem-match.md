# Admitted two-stage native BLAKE3 pipeline

Task: overlap canonical preparation of the next native child with proving the
current prepared child, under the existing execution policy and explicit budgets.

Canonical match: bounded two-stage producer/consumer pipeline with backpressure,
using the already qualified owned FIFO, preparation allocator cap and persistent
worker. Reference mechanism: https://doc.rust-lang.org/std/sync/mpsc/fn.sync_channel.html .
One preparation coordinator and one proving worker group; no optimal scheduling
claim. Existing higher-level ready-node policy remains authoritative.

Reservation: preparation cap + worker cap + two queue-byte limits (queued owner and
consumer's active owner) + explicit preparation/helper stacks + fixed control and
result metadata + caller-declared external reservation. CPU demand is proof worker
count (including its coordinator) plus one serial preparation coordinator. Check
these against a validated execution policy before allocating or spawning.

Limits: bounded jobs (64), one ready slot, one active preparation, one active
proof; returned proof allocations remain charged to the worker budget. Captures
and caller/sink allocations are external; declared external reservation is a
caller obligation, not measurement or a portable RSS ceiling. Jobs must match
the worker's exact admitted key context, not merely row shape.

Failure: cancellation closes/drains the handoff, joins the producer, releases
partial outputs and prepared owners. The worker remains caller-owned. No result
publication or messaging. Span records use monotonic elapsed time and measure
actual overlap; passing verification is required before any speed interpretation.

Validation: existing real execution policy accepts fitting budgets and rejects
insufficient CPU/memory; two real preparations/proofs overlap and independently
verify; persistent plan/workspace and returned-capture lifetime tests remain.
No security-parameter/default changes. Parent-of-parent and production admission
wire remain later qualification, not implied by this local pipeline.
