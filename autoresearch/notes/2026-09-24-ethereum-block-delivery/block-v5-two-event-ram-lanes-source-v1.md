# Two-event sorted RAM lanes: isolated source handoff

Status: root subsequently qualified the initial AIR snapshot with a focused
ReleaseFast nonproving gate: 6/6 including the root import and five behavioral
fixtures. This agent ran no builds, tests, STARK proofs, segments or benchmarks.
The subsequent proof/lifecycle source batch is separately unqualified. This is
not the canonical producer or a qualified replacement for word-v4. Canonical
word-v4, native fusion-v2, driver, collection and transport were not edited.

The protocol admits only writable RAM `space=1` with register custody mode1.
Each committed row contains two ordered events. Lane0 reads its predecessor
from the authenticated previous-row lane1 endpoint, except for the independently
pinned public shard predecessor. Lane1 reads the current-row lane0 endpoint.
An odd tail has inactive lane1. Exact u64 clocks and global event ordinals,
strict adjacency, first/last events, and all value and range equations use the
existing word-v4 algebra as the equation oracle. Padding produces no requests.

The new ABI and instance ID bind lane geometry, mode, exact event census,
ordered shard endpoints/predecessor, and both physical first-round roots. The
virtual legacy event log is only an endpoint/oracle conversion, never the
committed row domain. Sequence admission rejects missing/reordered shards and
changed public predecessors. There are no proof receipts or host scalar
substitutes for fresh verification in these modules.

## Source interfaces

- `prover/block_v5_ram_lanes_protocol_v1.zig`: `Claim.validate`, `Claim.mix`,
  `admitSequence`, `abiId`, `instanceId`, and exact padded-domain `accounting`.
- `air/block/word_memory_lanes_v1.zig`: generic scalar/packed direct algebra,
  two-lane witness and range queries, shifted opening mask, per-equation degrees.
- `air/block/word_memory_lanes_trace_v1.zig`: bounded `Trace.init/append/seal`,
  physical columns, exact fixed selectors and `fixedPoint`. Appending needs no
  event-sized staging buffer or independent predecessor witness.
- `prover/block_v5_ram_lanes_interaction_v1.zig`: typed interaction `Claim`,
  normalization, public endpoint reconstruction, generic constraints, and
  `generatePrepared`. The caller supplies one shared range16 inverse table.
- `prover/block_v5_ram_lanes_component_v1.zig`: three trace trees
  `{fixed24,main54,interaction92}`, scalar/packed preparation and quotient
  component. It delegates unchanged bounded CPU recovery/SIMD/parallel quotient
  machinery, retains expansion2 and degree4, and opens only nine shifted main
  cells, all in lane1's key/clock/after endpoint.

Generation has an explicit output-plus-scratch byte cap. Variable inverse
buffers are three arrays of `1024*8` QM31 cells, 393,216 bytes total. Batch counts
and multiplied term spans are `usize`. The shared inverse table retains
1,048,576 bytes outside this cap; its construction temporarily owns another
equally sized denominator buffer. The range counter and witness have their own
explicit lifetimes/caps. A failed generator may have mutated its caller-owned
counter; discard that local counter on failure before merging global census.

## Exact polynomial bounds

Each direct lane has the exact 46 word-v4 equations plus one strict-space
equation. Active/same and carry boolean identities are at most degree3.
Shifted/public predecessor interpolation has degree2 and is multiplied by an
active/same or active/different-key gate of degree2: those continuity and strict
ordering equations have degree4. Typed first/last bindings and strict-space
equations are degree2. The active selector identity is degree1.

| Interaction plane | Planes | Maximum degree | Reason |
| --- | ---: | ---: | --- |
| Transition | 1 | 3 | Prefix delta times two linear denominators |
| Link | 1 | 4 | Selected outgoing denominator2, incoming denominator1, delta1 |
| Initial value | 1 | 3 | Weight at most2 times opposite linear denominator |
| Final endpoint | 1 | 4 | Interior endpoint weight3 times opposite denominator1 |
| Endpoint census | 1 | 3 | Interior endpoint weight3 plus public counts |
| Range census | 1 | 2 | Exact sum of existing query weights |
| Range16 fractions | 17 | 3 | Two same-index lane queries, two linear denominators |

The intra-row link cancels on the same cells and exact ordinal. The public
first-shard incoming link is an independently reconstructed constant fraction;
it is removed from the delta before multiplying the two remaining denominators.
The endpoint public fractions use the same treatment. Strict RAM allows the
endpoint-space multiplier to be omitted because space1 is separately proved.
Lane1's first selector is the identically zero fixed polynomial. These choices
avoid a degree5 recurrence or a hidden increase to expansion3. The degree
fixture executes the actual generic algebra with a symbolic degree semiring;
it does not copy the equations into a separate implementation.

## Per-event accounting, without a speed claim

At full even occupancy, versus the existing word-v4 27-column protocol:

| Work/storage | Word-v4 per event | Two-event RAM per row | Two-event RAM per event |
| --- | ---: | ---: | ---: |
| Main M31 polynomial cells | 27 | 54 | 27 |
| Fixed M31 polynomial cells | 12 | 24 | 12 |
| Interaction M31 polynomial cells | 68 | 92 | 46 |
| Total M31 polynomial cells | 107 | 170 | 85 |
| Direct equations | 46 | 94 | 47 |
| Interaction equations | 17 | 23 | 11.5 |
| Total equations | 63 | 117 | 58.5 |
| Variable batch inverse slots | 8 | 8 | 4 |

This is 20.56% fewer total polynomial cells and 7.14% fewer equations at full
occupancy; interaction cells alone fall 32.35%. Main and fixed storage per event
do not shrink. Variable inverse *slots* include inactive/constant-one slots;
their reduction is not a measured inversion-time or proof-time improvement.
Range query count remains exact: 13 or 14 per noninitial event, and 10 for the
global first event. Seventeen range prefixes sum matching query positions from
both lanes, instead of doubling the legacy nine prefixes. One inverse table is
shared. Odd tails, small shards and padded domains cost
`170 * row_capacity / events` cells per actual event, rather than always85.

## Deferred focused qualification

Root: `src/frontends/riscv/block_v5_ram_lanes_unit_test_root.zig`.
Filter: `block-v5 ram lanes`. Five source fixtures cover:

1. Exact word-v4 row equations, all bus fractions and counters, same-key and
   address-change shards, public predecessors, u64-limit clocks and padding.
2. Before/clock changes, lane permutations, wrong space/mode/capacity, missing
   or reordered shards, predecessor changes, identity/root/geometry mutations.
3. Per-equation symbolic degree bounds, including actual degree4 link/endpoint
   planes and constant-zero lane1-first handling.
4. Exact masks, arbitrary secure scalar/packed parity, actual quotient
   point/domain parity over small polynomials, missing shifted/prefix openings,
   census rejection and concrete component API code generation.
5. A streaming2051-event odd-tail fixture crossing the1024-row inverse batch
   boundary, exact global range/endpoint census, prefix/ordinal/previous-value
   mutations and resource/padded-domain accounting.

Root's focused initial AIR gate passed these fixtures, including point/domain
parity, degree bounds and the2051-event inverse-batch boundary. That establishes
no STARK-proof or complete-receiver qualification for the subsequent lifecycle.

## Remaining production integration

A production planner must partition by **event** capacity `2 * 2^row_log`, preserve the
RAM predecessor across shards, and independently reconstruct every fixed root.
First-round/seal entries, proof transcript, proof generation, exact codec/shape
bounds, detached receiver and global closure must bind this new ABI and typed
interaction census. Range providers must consume the actual per-plane sums and
exact query counts. Recommit and fresh proof/negative tests remain required.
The subsequent lifecycle batch implements the linearly replayed common
universal47/word prefix, new lane proof domain and bounded standalone codec;
see `block-v5-two-event-ram-lanes-lifecycle-source-v1.md`. None has silently
relabeled a word-v4 proof or used virtual event logs for committed domains.
Zero RAM uses the existing independently proved absence policy, not an empty
lane STARK. No measured throughput or end-to-end proof improvement is claimed.
