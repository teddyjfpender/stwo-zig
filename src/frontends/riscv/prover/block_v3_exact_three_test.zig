//! Three real block-v3 segments: a verified pair plus a verified leaf become
//! one diagnostic exact-count root, with no synthetic execution slot.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Segment = @import("../runner/result.zig").SegmentResult;
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const exact = @import("../recursion/blake3_exact_root_aggregate.zig");
const forest = @import("../recursion/blake3_exact_forest_protocol.zig");
const receiver = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const source_seal = @import("block_memory_source_seal_v2.zig");
const manifest = @import("block_commitment_manifest.zig");
const support = @import("block_v3_recursive_test_support.zig");
const statement_mod = @import("blake3_segment_statement.zig");

test "block-v3 three real segments produce one linked exact root" {
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
    var segments: [3]Segment = undefined;
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*segment| segment.deinit();
    for (&segments, 0..) |*segment, i| {
        segment.* = if (i == 0) try session.startSegment(1) else try session.resumeSegment(segments[i - 1].continuation.?, if (i == 2) 100 else 1);
        segment_count += 1;
    }
    var fixtures: [3]support.Fixture = undefined;
    var fixture_count: usize = 0;
    defer for (fixtures[0..fixture_count]) |*fixture| fixture.deinit();
    for (&fixtures, &segments, 0..) |*fixture, *segment, i| {
        fixture.* = try support.Fixture.init(a, segment, @intCast(i), config);
        fixture_count += 1;
    }
    const first = try statement_mod.captureEndpoint(
        a,
        &segments[0],
        &fixtures[0].owner.native.statement.public_data,
        .entry,
    );
    const last = try statement_mod.captureEndpoint(
        a,
        &segments[2],
        &fixtures[2].owner.native.statement.public_data,
        .exit,
    );
    const job = try v3.initJobFromEndpoints(config, first, last, 3, first.machine.rw_memory);
    var entries: [6]source_seal.FirstRoundEntry = undefined;
    for (&fixtures, 0..) |*fixture, i| {
        const pair = fixture.entries(@intCast(i));
        entries[2 * i] = pair[0];
        entries[2 * i + 1] = pair[1];
    }
    const seal = try source_seal.SourceSeal.initBound(
        manifest.Sealed{ .digest = @splat(31), .instance_count = 3 },
        0,
        @splat(32),
        3,
        3,
        @splat(33),
        source_seal.digestFirstRoundRoster(&entries),
    );
    var leaves: [3]parent.tree.Node = undefined;
    var leaf_count: usize = 0;
    defer for (leaves[0..leaf_count]) |*leaf| leaf.deinit();
    var linked: [3]receiver.Descriptor = undefined;
    for (&leaves, &fixtures, &segments, 0..) |*leaf, *fixture, *segment, i| {
        leaf.* = try fixture.proveLeaf(segment, job, seal, config, .diagnostic_q8_pow0);
        leaf_count += 1;
        linked[i] = try receiver.verifyLeafBytes(
            a,
            leaf.transport_bytes.?,
            leaf.admission,
            leaf.admission.expected_id,
            leaf.statement,
            &fixture.owner.native.statement.public_data,
            config,
            seal,
            fixture.native_key_id,
            fixture.first.roots[0..2].*,
            fixture.first.roots[2],
            &fixture.receipt.?,
        );
    }
    try @import("block_v4_parallel_forest_fixture_test.zig").compare(a, job, &leaves);
    var pair = try parent.tree.preparePair(a, &leaves[0], &leaves[1], 2);
    defer pair.deinit();
    const Api = parent.ForBackend(Cpu);
    const pair_key = try Api.deriveKey(a, &pair.prepared);
    const pair_admission = try parent.protocol.Admission.init(pair_key, try pair_key.identity());
    const pair_plan = try Api.Plan.init(a, &pair.prepared.rows, pair_admission);
    defer pair_plan.deinit();
    var pair_proof = try pair_plan.prove(a, &pair.prepared.rows);
    const pair_bytes = try parent.codec.encode(a, &pair_proof, &pair_admission);
    defer a.free(pair_bytes);
    var pair_node = try parent.tree.Node.verifyOwned(
        &pair_proof,
        pair_admission,
        pair_admission.expected_id,
        pair.statement,
    );
    defer pair_node.deinit();
    const pair_link = try receiver.verifyDyadicBytes(
        a,
        pair_bytes,
        pair_admission,
        pair_admission.expected_id,
        linked[0],
        linked[1],
    );
    const linked_roots = [_]receiver.Descriptor{ pair_link, linked[2] };
    const roster = try receiver.verifiedForestDigest(job, &linked_roots);
    const entries_expected = [_]forest.Entry{
        .{ .statement = pair_node.statement, .expected_key_id = pair_node.admission.expected_id },
        .{ .statement = leaves[2].statement, .expected_key_id = leaves[2].admission.expected_id },
    };
    try std.testing.expectEqualDeep(try forest.digest(job, &entries_expected), roster);
    const roots = [_]*const parent.tree.Node{ &pair_node, &leaves[2] };
    var fold = try exact.prepareDiagnostic(a, job, &roots, roster, 2);
    defer fold.deinit();
    const outer_key = try Api.deriveKey(a, &fold.prepared);
    const outer_admission = try parent.protocol.Admission.init(
        outer_key,
        try outer_key.identity(),
    );
    const outer_plan = try Api.Plan.init(a, &fold.prepared.rows, outer_admission);
    defer outer_plan.deinit();
    var outer_proof = try outer_plan.prove(a, &fold.prepared.rows);
    defer outer_proof.deinit();
    const outer_bytes = try parent.codec.encode(a, &outer_proof, &outer_admission);
    defer a.free(outer_bytes);
    var verified = try receiver.verifyDiagnosticExactBytes(
        a,
        outer_bytes,
        outer_admission,
        outer_admission.expected_id,
        job,
        &linked_roots,
    );
    defer verified.deinit();
    try std.testing.expectEqual(@as(u32, 3), verified.statement.body.executed.segment_count);
    var wrong_key = outer_admission.expected_id;
    wrong_key[0] ^= 1;
    try std.testing.expectError(
        error.UntrustedBlake3ParentKey,
        receiver.verifyDiagnosticExactBytes(
            a,
            outer_bytes,
            outer_admission,
            wrong_key,
            job,
            &linked_roots,
        ),
    );
    std.debug.print("BLOCK_V3_EXACT verified=true segments=3 forest=2+1 sidecars=3 profile=q8_pow0 outer_bytes={d}\n", .{outer_bytes.len});
}
