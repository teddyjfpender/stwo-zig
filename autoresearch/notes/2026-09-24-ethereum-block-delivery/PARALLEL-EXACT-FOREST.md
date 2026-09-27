# Bounded parallel exact forest

The canonical 218-segment schedule has 213 dyadic parents and five exact
forest members of sizes 128, 64, 16, 8, and 2. No execution leaf is padded.
`block_v4_cpu_parallel_forest_plan.zig` reproduces the serial carry order as
stable parent indices. `block_v4_cpu_parallel_forest_queue.zig` releases a
parent only after both parent dependencies have durable staged proof files.
The lowest ready index is claimed first; completion may occur out of order.

The current serial barrier is `block_v4_cpu_incremental_forest_stage.prove`:
its one `Folder` calls `Frontier.push` and proves each parent synchronously.
The new provisional `block_v4_cpu_parallel_forest_stage.prove` assigns one
`Folder`, persistent parent worker, and preparation pool to each lane. Each
lane hash-checks and fresh-verifies child bytes, proves a parent, writes its
proof under `block-v4-parent-{first}-{height}.proof`, syncs it, and publishes
the canonical pin before waking dependent tasks. The stage returns the same
parent/root pin shape as the serial path. The outer proof and detached
receiver still verify the ordered five-root digest and every admitted parent.

Memory is bounded by a synchronized host allocator shared across lanes.
Configuration must reserve the sum of each lane's preparation and persistent
worker limits below the total cap; thread stacks and external backend memory
are outside that allocator. One lane is the safe fallback if the measured
parent peak does not permit two. A parent worker has an exclusive lease, so
lanes cannot share it. Its fixed-plan cache may rebind only after the row
layout and admission checks pass; matching tree height alone is insufficient.

This follows the scheduling principle in the official
[ZisK v1.3.0-alpha release](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha):
independent recursive work can overlap while memory-heavy jobs retain bounded
resources. It does not copy ZisK's GPU implementation. The DAG and stage
interfaces can later assign ready tasks to CPU or GPU lanes without changing
proof names, key pins, tree order, or receiver semantics.

Qualification sequence: the lightweight 218-task four-thread queue test is
passing. The three-real-leaf q8 fixture matched serial parent admissions and
forest digest; its one parent cannot overlap. The five-real-leaf q8 fixture
fresh-verified all three parallel parents and matched the serial pins/digest.
Its forest time was 54.875s serial versus 39.122s with two lanes, with a
4.369 GB scoped peak; see
`block-v4-parallel-forest-five-leaf-q8.json`. The producer now defaults to
the original serial stage. `STWO_BLOCK_V4_FOREST_LANES=2` opts in only when
the tracked host budget has at least 36 GiB headroom; the parallel stage
reserves 32 GiB and falls back to serial on a budget exhaustion. Its report
records requested/used lanes and fallback reason. Canonical q70 throughput
needs a separate run; no 218-leaf proving claim follows from q8.

The versioned local quartet parent joins the complete recursive-verifier AIR
for four ordered, equal-height real children. Its key context commits the
four child key IDs, statement IDs, span bindings, namespace IDs and ordered
roster. The q8 proof was freshly verified, and swapping two children was
rejected. Preparation used 23 AIR component slots, 2,984,762 fixed rows and
3,716,160 padded main rows; the proof was 150,835 bytes with a 3.341 GB
scoped peak. Exact per-slot counts are in
`block-v4-local-quartet-five-leaf-q8.json`.

`block_v4_cpu_mixed_forest_plan.zig` now selects aligned four-child folds and
uses binary folds for residual pairs. For 218 real leaves, its planned shape
has 70 quartet and 3 binary parents with the same five exact roots. The
provisional mixed stage and outer producer are being qualified. The existing
detached bundle and receiver encode only binary parent edges, so quartet
selection is not yet an admitted production block path.
