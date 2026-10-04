//! The block-v3 no-custody leaf path composes two same-anchor segments.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const Segment = @import("../../runner/result.zig").SegmentResult;
const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const v3 = @import("../../recursion/blake3_block_execution_span_v3.zig");
const receiver = @import("../../recursion/blake3_exact_root_receiver_v3.zig");
const source_seal = @import("../block_memory_source_seal_v2.zig");
const manifest = @import("../block_commitment_manifest.zig");
const support = @import("../block_v3_recursive_test_support.zig");
const statement_mod = @import("../blake3_segment_statement.zig");

test "block-v3 two verified sidecar leaves compose one diagnostic root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const config = parent.protocol.PCS_CONFIG;
    const instructions = [_]u32{
        0x00500093, 0x00708093, 0x00100137, 0x00100193,
        0x00312223, 0x00312423, 0x0000006f,
    };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(
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
    var segments: [2]Segment = undefined;
    segments[0] = try session.startSegment(1);
    defer segments[0].deinit();
    segments[1] = try session.resumeSegment(segments[0].continuation.?, 100);
    defer segments[1].deinit();
    var fixtures: [2]support.Fixture = undefined;
    var count: usize = 0;
    defer for (fixtures[0..count]) |*fixture| fixture.deinit();
    for (&fixtures, &segments, 0..) |*fixture, *segment, index| {
        fixture.* = try support.Fixture.init(a, segment, @intCast(index), config);
        count += 1;
    }
    const first = try statement_mod.captureEndpoint(a, &segments[0], &fixtures[0].owner.native.statement.public_data, .entry);
    const last = try statement_mod.captureEndpoint(a, &segments[1], &fixtures[1].owner.native.statement.public_data, .exit);
    const pin = first.machine.rw_memory;
    try std.testing.expect(!std.meta.eql(pin, last.machine.rw_memory));
    var wrong_pin = pin;
    wrong_pin.bytes[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockInitialImageRoot, v3.initJobFromEndpoints(config, first, last, 2, wrong_pin));
    const job = try v3.initJobFromEndpoints(config, first, last, 2, pin);
    try std.testing.expectEqualDeep(pin, job.complete.final_state.rw_memory);
    const first_entries = fixtures[0].entries(0);
    const second_entries = fixtures[1].entries(1);
    const entries = [_]source_seal.FirstRoundEntry{
        first_entries[0], first_entries[1], second_entries[0], second_entries[1],
    };
    const seal = try source_seal.SourceSeal.initBound(
        manifest.Sealed{ .digest = @splat(31), .instance_count = 2 },
        0,
        @splat(32),
        2,
        2,
        @splat(33),
        source_seal.digestFirstRoundRoster(&entries),
    );
    var left = try fixtures[0].proveLeaf(&segments[0], job, seal, config, .diagnostic_q8_pow0);
    defer left.deinit();
    var right = try fixtures[1].proveLeaf(&segments[1], job, seal, config, .diagnostic_q8_pow0);
    defer right.deinit();
    const left_link = try receiver.verifyLeafBytes(
        a,
        left.transport_bytes.?,
        left.admission,
        left.admission.expected_id,
        left.statement,
        &fixtures[0].owner.native.statement.public_data,
        config,
        seal,
        fixtures[0].native_key_id,
        fixtures[0].first.roots[0..2].*,
        fixtures[0].first.roots[2],
        &fixtures[0].receipt.?,
    );
    const right_link = try receiver.verifyLeafBytes(
        a,
        right.transport_bytes.?,
        right.admission,
        right.admission.expected_id,
        right.statement,
        &fixtures[1].owner.native.statement.public_data,
        config,
        seal,
        fixtures[1].native_key_id,
        fixtures[1].first.roots[0..2].*,
        fixtures[1].first.roots[2],
        &fixtures[1].receipt.?,
    );
    try std.testing.expectEqualDeep(pin, left.statement.body.executed.exit.rw_memory);
    try std.testing.expectEqualDeep(pin, right.statement.body.executed.entry.rw_memory);
    var folded = try parent.tree.preparePair(a, &left, &right, 2);
    defer folded.deinit();
    const Api = parent.ForBackend(Cpu);
    const key = try Api.deriveKey(a, &folded.prepared);
    const admission = try parent.protocol.Admission.init(key, try key.identity());
    const plan = try Api.Plan.init(a, &folded.prepared.rows, admission);
    defer plan.deinit();
    var proof = try plan.prove(a, &folded.prepared.rows);
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    var root = try parent.tree.Node.verifyOwned(
        &proof,
        admission,
        admission.expected_id,
        folded.statement,
    );
    defer root.deinit();
    const linked = try receiver.verifyDyadicBytes(
        a,
        bytes,
        admission,
        admission.expected_id,
        left_link,
        right_link,
    );
    try std.testing.expectEqualDeep(linked.statement, root.statement);
    _ = try root.root();
    try std.testing.expectEqual(@as(u32, 2), root.statement.body.executed.segment_count);
    std.debug.print("BLOCK_V3_RECURSION verified=true segments=2 sidecars=2 profile=q8_pow0\n", .{});
}
