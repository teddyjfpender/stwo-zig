//! Real adjacent local-clock segments, independently verified and folded.
const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../runner/mod.zig");
const segment = @import("blake3_segment_execution.zig");
const api = @import("blake3_execution_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");
const aggregate = @import("../recursion/blake3_execution_aggregate.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const segment_statement = @import("blake3_segment_statement.zig");
const config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
test "BLAKE3 adjacent segments aggregate and recursively verify [compact providers]" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var first = try session.startSegment(3);
    defer first.deinit();
    var second = try session.resumeSegment(first.continuation.?, 100);
    defer second.deinit();
    try std.testing.expectEqual(@as(u64, 4), second.global_first_cycle);
    var left = try segment.Owner.initCompact(a, &first);
    defer left.deinit();
    var right = try segment.Owner.initCompact(a, &second);
    defer right.deinit();
    try std.testing.expectEqualDeep(left.memory.program.root, right.memory.program.root);
    const first_boundary = try segment_statement.boundary(a, &first);
    const second_boundary = try segment_statement.boundary(a, &second);
    try std.testing.expectEqualDeep(first_boundary.exit, second_boundary.entry);
    const job = try segment_statement.initJob(a, config, &first, &second, &left.native.statement.public_data, &right.native.statement.public_data);
    const statements = [2]span.SpanStatement{
        try segment_statement.leaf(a, job, &first),
        try segment_statement.leaf(a, job, &second),
    };
    var l = try prepare(a, &left, statements[0]);
    var l_alive = true;
    defer if (l_alive) l.deinit();
    var r = try prepare(a, &right, statements[1]);
    var r_alive = true;
    defer if (r_alive) r.deinit();
    try std.testing.expect(!std.mem.eql(u8, &l.context.child_key_id, &r.context.child_key_id));
    const expected = try aggregate.admit(&l.context, &r.context, statements);
    var substituted = r.context;
    substituted.statement_identity.?[31] ^= 1;
    try std.testing.expectError(error.UntrustedAggregateSpan, aggregate.admit(&l.context, &substituted, statements));
    try std.testing.expectError(error.SlotsNotAdjacent, aggregate.admit(&r.context, &l.context, .{ statements[1], statements[0] }));
    l_alive = false;
    r_alive = false;
    var folded = try aggregate.prepareOwned(a, &l, &r, statements);
    defer folded.deinit();
    try std.testing.expectEqualDeep(expected, folded.statement);
    _ = try span.RootStatement.init(folded.statement);
    std.debug.print("BLAKE3_AGGREGATE distinct_children=true segments=2 cycles={d} inputs={d} retained_bytes={d}\n", .{ folded.statement.body.executed.cycle_count, folded.prepared.rows.input_count, try folded.prepared.rows.retainedBytes() });
    try @import("blake3_execution_parent_proof_test_support.zig").check(a, &folded.prepared);
}
fn prepare(a: std.mem.Allocator, owner: *segment.Owner, statement: span.SpanStatement) !parent.Prepared {
    const admission = try owner.admission();
    const verifier = try api.PreparedVerifier.initCompact(a, &owner.native.statement, admission, config, owner.native.compact_ranges.?.plan);
    defer verifier.deinit();
    const pipeline = @import("blake3_segment_parent.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    var wrong = verifier.id;
    wrong[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, pipeline.prepare(a, owner, verifier, wrong, statement, 2));
    try std.testing.expect(!owner.native.interaction_ready);
    var changed = statement;
    changed.body.executed.entry.registers[1] ^= 1;
    // Span validation may reject the changed job endpoint before execution binding.
    if (pipeline.prepare(a, owner, verifier, verifier.id, changed, 2)) |unexpected| {
        var owned = unexpected;
        owned.deinit();
        return error.ExpectedSpanRejection;
    } else |_| {}
    try std.testing.expect(!owner.native.interaction_ready);
    return pipeline.prepare(a, owner, verifier, verifier.id, statement, 2);
}
