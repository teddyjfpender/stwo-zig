//! Four actual segments, two intermediate aggregates and one aggregate root.
const std = @import("std");
const runner = @import("../runner/mod.zig");
const segment = @import("blake3_segment_execution.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const execution = @import("blake3_execution_proof.zig").ForBackend(Cpu);
const pipeline = @import("blake3_segment_parent.zig").ForBackend(Cpu);
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const tree = parent.tree;
const spans = @import("../recursion/span_statement_blake3.zig");
const source = @import("../recursion/air/blake3_memory_snapshot.zig");
const config = parent.protocol.PCS_CONFIG;
const Segment = @import("../runner/result.zig").SegmentResult;
test "BLAKE3 adjacent segments form a four-leaf tree" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segments: [4]Segment = undefined;
    var count: usize = 0;
    defer for (segments[0..count]) |*item| item.deinit();
    for (&segments, 0..) |*item, i| {
        item.* = if (i == 0) try session.startSegment(1) else try session.resumeSegment(segments[i - 1].continuation.?, if (i == 3) 100 else 1);
        count += 1;
    }
    const zero = spans.Digest{ .bytes = @splat(0) };
    var states: [5]spans.MachineState = undefined;
    for (&segments, 0..) |*item, i| {
        var entry = try source.fromSnapshot(a, &item.rw_memory, .entry, .continuation);
        defer entry.deinit();
        const state = try spans.MachineState.init(item.entry_cpu.pc, item.entry_cpu.regs, entry.root, zero);
        if (i != 0) try std.testing.expectEqualDeep(states[i], state);
        states[i] = state;
        var exit = try source.fromSnapshot(a, &item.rw_memory, .exit, .continuation);
        defer exit.deinit();
        states[i + 1] = try spans.MachineState.init(item.exit_cpu.pc, item.exit_cpu.regs, exit.root, zero);
    }
    // Only endpoint owners are needed to derive admitted job I/O and program.
    // Release them before materializing proof witnesses for each pair.
    const job = blk: {
        var first = try segment.Owner.init(a, &segments[0]);
        defer first.deinit();
        var last = try segment.Owner.init(a, &segments[3]);
        defer last.deinit();
        const io = @import("../recursion/blake3_public_io.zig");
        break :blk try spans.JobContext.init(try spans.CompleteExecution.init(parent.spans.protocolIdentity(config), first.memory.program.root, states[0], states[4], try io.input(&first.native.statement.public_data), try io.output(&last.native.statement.public_data), 6), 4);
    };
    var statements: [4]spans.SpanStatement = undefined;
    for (&statements, &segments, 0..) |*statement, *item, i| {
        statement.* = try spans.SpanStatement.segmentLeaf(job, @intCast(i), try spans.ExecutedSpan.init(@intCast(i), 1, item.global_first_cycle - 1, item.cycle_count, states[i], states[i + 1], .{ .digest = if (i == 0) job.complete.public_input else null }, .{ .digest = if (i == 3) job.complete.public_output else null }));
    }
    var left = try provePair(a, .{ &segments[0], &segments[1] }, .{ statements[0], statements[1] });
    defer left.deinit();
    var right = try provePair(a, .{ &segments[2], &segments[3] }, .{ statements[2], statements[3] });
    defer right.deinit();
    try std.testing.expect(left.admission.key.context.aggregation != null);
    try std.testing.expect(right.admission.key.context.aggregation != null);
    try std.testing.expectError(error.AliasedAggregateChildren, tree.preparePair(a, &left, &left, 2));
    try std.testing.expectError(error.SlotsNotAdjacent, tree.preparePair(a, &right, &left, 2));
    var folded = try tree.preparePair(a, &left, &right, 2);
    defer folded.deinit();
    try std.testing.expectEqual(@as(u8, 2), folded.statement.slots.height);
    try std.testing.expectEqualSlices(u8, &left.admission.expected_id, &folded.prepared.context.child_key_id);
    try std.testing.expectEqualSlices(u8, &right.admission.expected_id, &folded.prepared.context.aggregation.?.right_child_key_id);
    var root = try @import("blake3_tree_pipeline_test_support.zig").check(a, &left, &right, &folded);
    defer root.deinit();
    _ = try root.root();
    try std.testing.expectEqualDeep(job, root.statement.job);
    try std.testing.expectEqual(@as(u64, 6), root.statement.body.executed.cycle_count);
    try std.testing.expectEqual(@as(u32, 4), root.statement.body.executed.segment_count);
    // Nodes remain valid after another level consumes their verifier witnesses.
    try left.validate();
    try right.validate();
    std.debug.print("BLAKE3_TREE verified=true leaves=4 aggregate_levels=2 cycles=6 retained_root_rows={d}\n", .{try folded.prepared.rows.retainedBytes()});
}
fn provePair(a: std.mem.Allocator, segments: [2]*const Segment, statements: [2]spans.SpanStatement) !tree.Node {
    var left = try segment.Owner.init(a, segments[0]);
    defer left.deinit();
    var right = try segment.Owner.init(a, segments[1]);
    defer right.deinit();
    const lv = try execution.PreparedVerifier.init(a, &left.native.statement, try left.admission(), config);
    defer lv.deinit();
    const rv = try execution.PreparedVerifier.init(a, &right.native.statement, try right.admission(), config);
    defer rv.deinit();
    var wrong = rv.id;
    wrong[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, pipeline.preparePair(a, .{ &left, &right }, .{ lv, rv }, .{ lv.id, wrong }, statements, 2));
    try std.testing.expect(!left.native.interaction_ready and !right.native.interaction_ready);
    try std.testing.expectError(error.AliasedAggregateChildren, pipeline.preparePair(a, .{ &left, &left }, .{ lv, lv }, .{ lv.id, lv.id }, statements, 2));
    var folded = try pipeline.preparePair(a, .{ &left, &right }, .{ lv, rv }, .{ lv.id, rv.id }, statements, 2);
    defer folded.deinit();
    return proveFold(a, &folded);
}
fn proveFold(a: std.mem.Allocator, folded: *const parent.aggregation.Fold) !tree.Node {
    const Api = parent.ForBackend(Cpu);
    const key = try Api.deriveKey(a, &folded.prepared);
    const expected = try key.identity();
    const admission = try parent.protocol.Admission.init(key, expected);
    const plan = try Api.Plan.init(a, &folded.prepared.rows, admission);
    var plan_alive = true;
    defer if (plan_alive) plan.deinit();
    var proof = try plan.prove(a, &folded.prepared.rows);
    defer proof.deinit();
    plan.deinit();
    plan_alive = false;
    const bytes = try parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    proof.deinit();
    var wrong = expected;
    wrong[0] ^= 1;
    var rejected = try parent.codec.decode(a, bytes, &admission);
    defer rejected.deinit();
    try std.testing.expectError(error.UntrustedBlake3ParentKey, tree.Node.verifyOwned(&rejected, admission, wrong, folded.statement));
    try std.testing.expect(rejected.proof == null);
    var decoded = try parent.codec.decode(a, bytes, &admission);
    defer decoded.deinit();
    const result = try tree.Node.verifyOwned(&decoded, admission, expected, folded.statement);
    try std.testing.expect(decoded.proof == null);
    std.debug.print("BLAKE3_TREE_NODE verified=true height={d} artifact_bytes={d}\n", .{ folded.statement.slots.height, bytes.len });
    return result;
}
