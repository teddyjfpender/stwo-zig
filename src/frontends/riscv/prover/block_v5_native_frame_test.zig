//! Pure frame constraints and independent public admission, not proof reuse.
const std = @import("std");
const core = @import("stwo_core");
const Frame = @import("block_v5_native_frame_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Public = @import("block_v5_native_public_admission_v1.zig");
const Q = core.fields.qm31.QM31;

test "block-v5 native physical frame pins immutable geometry and rejects changed rows" {
    var first = shape(0x1000);
    var second = shape(0x2000);
    const one = try Frame.expected(&first, 3);
    const two = try Frame.expected(&second, 3);
    try std.testing.expectEqualDeep(one, two);
    const context = Public.Context{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = 3 };
    const first_admission = try Public.Admission.init(context, &first.public_data);
    const second_admission = try Public.Admission.init(context, &second.public_data);
    try std.testing.expect(!std.meta.eql(first_admission.expected_id, second_admission.expected_id));
    const pinned = Frame.symbols(Q, one);
    for (Frame.evaluateGeneric(Q, Q.one(), pinned, Q.zero(), pinned)) |check| try std.testing.expect(check.isZero());
    const bad_selector = Frame.evaluateGeneric(Q, Q.zero(), pinned, Q.zero(), pinned);
    try std.testing.expect(!bad_selector[0].isZero());
    var changed = pinned;
    changed[0] = changed[0].add(Q.one());
    try std.testing.expect(!Frame.evaluateGeneric(Q, Q.one(), changed, Q.zero(), pinned)[1].isZero());
    changed = pinned;
    changed[2] = changed[2].add(Q.one());
    try std.testing.expect(!Frame.evaluateGeneric(Q, Q.one(), changed, Q.zero(), pinned)[3].isZero());
    const bad_pad = Frame.evaluateGeneric(Q, Q.one(), pinned, Q.one(), pinned);
    try std.testing.expect(!bad_pad[Frame.N_CONSTRAINTS - 1].isZero());
    try std.testing.expectError(error.InvalidStatement, Frame.expected(&first, 2));
    var clock = first;
    clock.n_infra = 1;
    clock.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../infra_trace.zig").CLOCK_UPDATE_COLS };
    try std.testing.expectError(error.InvalidV5NativeFrameShape, Frame.expected(&clock, 3));
    const a = std.testing.allocator;
    const fixed = try Frame.fixedColumns(a);
    defer Frame.freeColumns(a, fixed);
    const interaction = try Frame.interactionColumns(a);
    defer Frame.freeColumns(a, interaction);
    for (interaction[0].values) |value| try std.testing.expect(value.isZero());
    const main = try Frame.mainColumns(a, one);
    defer Frame.freeColumns(a, main);
    try std.testing.expectEqual(@as(usize, Frame.FIXED_COLUMNS), fixed.len);
    try std.testing.expectEqual(@as(usize, Frame.MAIN_COLUMNS), main.len);
    for (main, one.values) |column, expected| for (column.values) |value|
        try std.testing.expectEqualDeep(expected, value);
}

fn shape(pc: u32) Shape {
    var result: Shape = undefined;
    result.initializeDescriptorStorage();
    result.n_components = 0;
    result.n_infra = 0;
    result.initial_pc = pc;
    result.final_pc = pc + 12;
    result.total_steps = 3;
    result.public_data = .{ .initial_pc = result.initial_pc, .final_pc = result.final_pc, .clock = result.total_steps, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(result.final_pc), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}
