//! Five real execution leaves expose two independent dyadic parents at once.
//! The shared helper compares serial and two-lane staged forests and fresh
//! verifies every parent proof under its admitted key.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const runner = @import("../runner/mod.zig");
const Segment = @import("../runner/result.zig").SegmentResult;
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const quad = @import("../recursion/blake3_local_quad_aggregate.zig");
const row_storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const source_seal = @import("block_memory_source_seal_v2.zig");
const manifest = @import("block_commitment_manifest.zig");
const support = @import("block_v3_recursive_test_support.zig");
const statement_mod = @import("blake3_segment_statement.zig");

test "block-v4 five real leaves stage a two-lane exact forest" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const config = parent.protocol.PCS_CONFIG;
    const instructions = [_]u32{
        0x00500093, 0x00708093, 0x00100137, 0x00100193,
        0x00312223, 0x00312423, 0x0000006f,
    };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(
        instructions.len,
        &instructions,
        0,
        .rv32im_zkvm_v1,
    );
    var session = try runner.BaseExecutionSession.init(
        a,
        &elf,
        .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
    );
    defer session.deinit();
    var segments: [5]Segment = undefined;
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*segment| segment.deinit();
    for (&segments, 0..) |*segment, i| {
        segment.* = if (i == 0) try session.startSegment(1) else try session.resumeSegment(segments[i - 1].continuation.?, if (i == 4) 100 else 1);
        segment_count += 1;
    }
    var fixtures: [5]support.Fixture = undefined;
    var fixture_count: usize = 0;
    defer for (fixtures[0..fixture_count]) |*fixture| fixture.deinit();
    for (&fixtures, &segments, 0..) |*fixture, *segment, i| {
        fixture.* = try support.Fixture.init(a, segment, @intCast(i), config);
        fixture_count += 1;
    }
    const first = try statement_mod.captureEndpoint(a, &segments[0], &fixtures[0].owner.native.statement.public_data, .entry);
    const last = try statement_mod.captureEndpoint(a, &segments[4], &fixtures[4].owner.native.statement.public_data, .exit);
    const job = try v3.initJobFromEndpoints(config, first, last, 5, first.machine.rw_memory);
    var entries: [10]source_seal.FirstRoundEntry = undefined;
    for (&fixtures, 0..) |*fixture, i| {
        const pair = fixture.entries(@intCast(i));
        entries[2 * i] = pair[0];
        entries[2 * i + 1] = pair[1];
    }
    const seal = try source_seal.SourceSeal.initBound(
        manifest.Sealed{ .digest = @splat(31), .instance_count = 5 },
        0,
        @splat(32),
        5,
        5,
        @splat(33),
        source_seal.digestFirstRoundRoster(&entries),
    );
    var leaves: [5]parent.tree.Node = undefined;
    var leaf_count: usize = 0;
    defer for (leaves[0..leaf_count]) |*leaf| leaf.deinit();
    for (&leaves, &fixtures, &segments) |*leaf, *fixture, *segment| {
        leaf.* = try fixture.proveLeaf(segment, job, seal, config, .diagnostic_q8_pow0);
        leaf_count += 1;
    }
    const mixed_only = std.process.hasEnvVarConstant("STWO_MIXED_ONLY");
    if (mixed_only)
        try @import("block_v4_parallel_forest_fixture_test.zig").compareMixedOnly(a, job, &leaves)
    else
        try @import("block_v4_parallel_forest_fixture_test.zig").compare(a, job, &leaves);
    if (mixed_only) return;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 16 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const work = budget.allocator();
    var timer = try std.time.Timer.start();
    var folded = try quad.prepare(work, .{ &leaves[0], &leaves[1], &leaves[2], &leaves[3] }, 2, .diagnostic_q8_pow0);
    defer folded.deinit();
    const preparation_ns = timer.read();
    const Api = parent.ForBackend(Cpu);
    const key = try Api.deriveKeyWithProfile(work, &folded.prepared, .diagnostic_q8_pow0);
    const admission = try parent.protocol.Admission.init(key, try key.identity());
    var fixed_counts: [row_storage.Airs.len]usize = undefined;
    var padded_main_counts: [row_storage.Airs.len]usize = undefined;
    inline for (0..row_storage.Airs.len) |i| {
        fixed_counts[i] = folded.prepared.rows.fixed[i].len;
        padded_main_counts[i] = if (folded.prepared.rows.main[i].len == 0) 0 else folded.prepared.rows.main[i][0].values.len;
    }
    timer.reset();
    const plan = try Api.Plan.init(work, &folded.prepared.rows, admission);
    defer plan.deinit();
    var produced = try plan.prove(work, &folded.prepared.rows);
    defer produced.deinit();
    const prove_ns = timer.read();
    const bytes = try parent.codec.encode(work, &produced, &admission);
    defer work.free(bytes);
    var children: [4]quad.Child = undefined;
    for (leaves[0..4], &children) |leaf, *child| child.* = .{ .statement = leaf.statement, .admission = leaf.admission };
    var verified = try quad.verifyBytes(work, bytes, admission, admission.expected_id, children);
    defer verified.deinit();
    try std.testing.expectEqualDeep(folded.statement, verified.statement);
    var reversed = children;
    std.mem.swap(quad.Child, &reversed[1], &reversed[2]);
    try std.testing.expectError(error.SlotsNotAdjacent, quad.verifyBytes(work, bytes, admission, admission.expected_id, reversed));
    std.debug.print("BLOCK_V4_LOCAL_QUAD verified=true children=4 preparation_ns={d} prove_ns={d} proof_bytes={d} scoped_peak_bytes={d} fixed_rows={any} padded_main_rows={any}\n", .{ preparation_ns, prove_ns, bytes.len, budget.snapshot().peak_live_bytes, fixed_counts, padded_main_counts });
}
