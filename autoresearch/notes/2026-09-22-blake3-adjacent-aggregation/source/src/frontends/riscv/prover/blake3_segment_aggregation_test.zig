//! Real adjacent local-clock segments, independently verified and folded.
const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../runner/mod.zig");
const segment = @import("blake3_segment_execution.zig");
const api = @import("blake3_execution_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");
const aggregate = @import("../recursion/blake3_execution_aggregate.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const source = @import("../recursion/air/blake3_memory_snapshot.zig");
const config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
test "BLAKE3 adjacent segments aggregate and recursively verify" {
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
    var left = try segment.Owner.init(a, &first);
    defer left.deinit();
    var right = try segment.Owner.init(a, &second);
    defer right.deinit();
    try std.testing.expectEqualDeep(left.memory.program.root, right.memory.program.root);
    var entry = try source.fromSnapshot(a, &first.rw_memory, .entry, .continuation);
    defer entry.deinit();
    var middle = try source.fromSnapshot(a, &first.rw_memory, .exit, .continuation);
    defer middle.deinit();
    var resumed = try source.fromSnapshot(a, &second.rw_memory, .entry, .continuation);
    defer resumed.deinit();
    var final = try source.fromSnapshot(a, &second.rw_memory, .exit, .continuation);
    defer final.deinit();
    try std.testing.expectEqualDeep(middle.root, resumed.root);
    const zero = span.Digest{ .bytes = @splat(0) };
    const initial = try span.MachineState.init(first.entry_cpu.pc, first.entry_cpu.regs, entry.root, zero);
    const shared = try span.MachineState.init(first.exit_cpu.pc, first.exit_cpu.regs, middle.root, zero);
    const ended = try span.MachineState.init(second.exit_cpu.pc, second.exit_cpu.regs, final.root, zero);
    const io = @import("../recursion/blake3_public_io.zig");
    const input = try io.input(&left.native.statement.public_data);
    const output = try io.output(&right.native.statement.public_data);
    const job = try span.JobContext.init(try span.CompleteExecution.init(@import("../recursion/blake3_execution_span.zig").protocolIdentity(config), left.memory.program.root, initial, ended, input, output, first.cycle_count + second.cycle_count), 2);
    const statements = [2]span.SpanStatement{
        try span.SpanStatement.segmentLeaf(job, 0, try span.ExecutedSpan.init(0, 1, 0, first.cycle_count, initial, shared, .{ .digest = input }, .{ .digest = null })),
        try span.SpanStatement.segmentLeaf(job, 1, try span.ExecutedSpan.init(1, 1, first.cycle_count, second.cycle_count, shared, ended, .{ .digest = null }, .{ .digest = output })),
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
    const verifier = try api.PreparedVerifier.init(a, &owner.native.statement, admission, config);
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
