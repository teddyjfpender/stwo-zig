const std = @import("std");
const custody = @import("blake3_memory_custody.zig");
const chain = @import("blake3_memory_update_chain.zig");
const commitment = @import("../../prover/blake3_commitment_plan.zig");
const public = @import("../../air/public_data.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
test "BLAKE3 memory update proves public custody determines the exact conversion" {
    const a = std.testing.allocator;
    const root = try tree.TreeHasher.init(.memory).root(&.{});
    const program_root = try tree.TreeHasher.init(.program).root(&.{});
    const rom = [_]tree.Leaf{ .{ .index = 0x1000, .value = 0 }, .{ .index = 0x1001, .value = 0 }, .{ .index = 0x1002, .value = 0 }, .{ .index = 0x1003, .value = 0 } };
    var plan = try commitment.Plan.init(a, .{ program_root, root, root }, &.{.{ .address = 0x2004, .clock = 1, .direction = .final, .source_circuit = 1, .path_namespace = 2, .root = root }}, &.{.{ .namespace = 1000, .address = 0x1000, .multiplicity = 1, .root = program_root }}, &rom);
    defer plan.deinit();
    const admission = try commitment.Admission.init(&plan, try plan.identity());
    var data = public.Blake3PublicData{
        .initial_pc = 0x1000,
        .final_pc = 0x1010,
        .clock = 10,
        .initial_regs = @splat(0),
        .final_regs = @splat(0),
        .reg_last_clock = @splat(0),
        .program_root = program_root,
        .initial_rw_root = root,
        .final_rw_root = root,
        .completion = public.Completion.canonicalSelfLoop(0x1010),
        .io_entries = .{ .input_start = 0x2000, .input_len = 8, .input_words = &.{ 0xff, 0x12345678 }, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{.{ .addr = 0x3004, .value = 0, .clock = 1 }} },
    };
    const io = @import("../blake3_public_io.zig");
    const input_id = try io.input(&data);
    const output_id = try io.output(&data);
    var clock_only = data;
    clock_only.io_entries.output_words = &.{.{ .addr = 0x3004, .value = 0, .clock = 2 }};
    try std.testing.expectEqualDeep(output_id, try io.output(&clock_only));
    var changed_input = data;
    changed_input.io_entries.input_words = &.{ 0xff, 0x92345678 };
    try std.testing.expect(!std.meta.eql(input_id, try io.input(&changed_input)));
    try std.testing.expect(!std.meta.eql(input_id, output_id));
    var moved_output = data;
    moved_output.io_entries.output_len_addr = 0x3010;
    moved_output.io_entries.output_words = &.{.{ .addr = 0x3010, .value = 0, .clock = 1 }};
    try std.testing.expect(!std.meta.eql(output_id, try io.output(&moved_output)));
    const entry = try custody.edits(a, .entry, &data, admission);
    defer a.free(entry);
    try std.testing.expectEqual(@as(usize, 2), entry.len);
    try std.testing.expectEqual(@as(u32, 255), entry[0].after);
    try std.testing.expectEqual(@as(u32, 0x12345678), entry[1].after);
    const exit = try custody.edits(a, .exit, &data, admission);
    defer a.free(exit);
    // Untouched input is restored; touched input is already in the ordinary
    // final commitment. All four zero bytes of the public output stay checked.
    try std.testing.expectEqual(@as(usize, 2), exit.len);
    try std.testing.expectEqual(@as(u32, 0x3004 / 4), exit[1].address);
    var conversion = try chain.planWitness(a, 2000, 1999, entry, &.{});
    defer conversion.deinit();
    try custody.admit(&conversion, .entry, &data, admission, a);
    const full = [_]tree.Leaf{ .{ .index = 0x2000 / 4, .value = 255 }, .{ .index = 0x2004 / 4, .value = 0x12345678 } };
    try std.testing.expectEqualDeep(try tree.TreeHasher.init(.memory).root(&full), conversion.roots[2]);
    var prepared = try custody.prepare(a, .entry, &data, admission, &.{}, conversion.roots[2], 2000, 1999);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 2), prepared.rows.updates.len);
    try std.testing.expectEqualSlices(u8, &try conversion.identity(), &try prepared.plan.identity());
    try std.testing.expectError(error.UntrustedMemoryUpdateChain, custody.prepare(a, .entry, &data, admission, &.{}, root, 2000, 1999));
    // Metadata admission has its own focused tests; a binding is not a proof.
    const span = @import("../span_statement_blake3.zig");
    const binding = @import("../blake3_execution_span.zig");
    const config = @import("../blake3_execution_parent_protocol.zig").PCS_CONFIG;
    var exit_plan = try chain.planWitness(a, 4000, 3999, exit, &.{});
    defer exit_plan.deinit();
    const zero = span.Digest{ .bytes = @splat(0) };
    const entry_state = try span.MachineState.init(data.initial_pc, data.initial_regs, conversion.roots[2], zero);
    const exit_state = try span.MachineState.init(data.final_pc, data.final_regs, exit_plan.roots[2], zero);
    const job = try span.JobContext.init(try span.CompleteExecution.init(binding.protocolIdentity(config), program_root, entry_state, exit_state, input_id, output_id, data.clock), 1);
    const statement = try span.SpanStatement.segmentLeaf(job, 0, try span.ExecutedSpan.init(0, 1, 0, data.clock, entry_state, exit_state, .{ .digest = input_id }, .{ .digest = output_id }));
    try binding.validate(a, statement, &data, admission, config, &conversion, &exit_plan);
    var unfinished = data;
    unfinished.completion = .{ .kind = .unretired_program_fetch, .address = data.final_pc, .value = 0x13, .clock = 0 };
    try std.testing.expectError(error.IncompleteExecutionSpan, binding.validate(a, statement, &unfinished, admission, config, &conversion, &exit_plan));
    var invalid_io = statement;
    invalid_io.body.executed.entry.public_io_state.bytes[0] = 1;
    invalid_io.job.complete.initial_state = invalid_io.body.executed.entry;
    try std.testing.expectError(error.InvalidExecutionIoState, binding.validate(a, invalid_io, &data, admission, config, &conversion, &exit_plan));
    conversion.edits[1].after = 1;
    try std.testing.expectError(error.UntrustedMemoryCustody, custody.admit(&conversion, .entry, &data, admission, a));
    conversion.edits[1].after = 0;
    data.io_entries.input_words = &.{ 0xfe, 0x12345678 };
    try std.testing.expectError(error.UntrustedMemoryCustody, custody.admit(&conversion, .entry, &data, admission, a));
    data.io_entries.input_words = &.{ 0xff, 0x12345678 };
    // Rejected even if a caller pins the conflicting schedule anew.
    plan.memories[0].direction = .initial;
    plan.memories[0].clock = 0;
    const conflict = try commitment.Admission.init(&plan, try plan.identity());
    try std.testing.expectError(error.ConflictingPublicMemoryCustody, custody.edits(a, .entry, &data, conflict));
    try std.testing.expectError(error.UntrustedCommitmentPlan, custody.edits(a, .entry, &data, admission));
}
