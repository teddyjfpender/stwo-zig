const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Opcode = @import("../../runner/trace.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Layout = @import("../block_v7_native_relation_layout_v1.zig");
const Bounded = @import("../block_v7_degree_bounded_relation_layout_v1.zig");
const Batch = @import("../block_v7_native_projection_batch_v1.zig");
const Old = @import("../block_v5_native_projection_fused_proof_v2.zig");
const Universal = @import("../../recursion/air/universal_challenges.zig").UniversalRelations;
fn shapeFor(family: Opcode.OpcodeFamily, log: u32) Shape {
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    const rows = @as(u32, 1) << @intCast(log);
    shape.component_descs[0] = .{ .family = family, .log_size = log, .n_rows = rows, .n_columns = @intCast(Opcode.nColumnsForFamily(family)) };
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = log, .n_rows = rows, .n_columns = @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    shape.total_steps = rows;
    shape.public_data.clock = rows;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    return shape;
}
test "row-fused projections preserve every physical prefix for seventeen families and q2 q3" {
    const a = std.testing.allocator;
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const relations = Universal.dummy();
    for (0..Opcode.N_FAMILIES) |index| for ([_]u32{ 1, 4, 9 }) |log| {
        var shape = shapeFor(@enumFromInt(index), log);
        var canonical = try Layout.Layout.init(a, &shape, 0, 1);
        defer canonical.deinit();
        var bounded = try Bounded.Layout.init(a, &shape, 0, 1);
        defer bounded.deinit();
        const size = @as(usize, 1) << @intCast(log);
        const columns = try a.alloc(Engine.pcs.ColumnEvaluation, shape.component_descs[0].n_columns + 10);
        defer a.free(columns);
        for (columns, 0..) |*column, i| {
            const values = try a.alloc(M, size);
            for (values, 0..) |*value, row| value.* = M.fromU64(if (row % 5 == 0) 0 else (i * 17 + row * 13 + 1) % 257);
            column.* = .{ .log_size = log, .values = values };
        }
        defer for (columns) |column| a.free(column.values);
        for ([_][]const @import("../block_v5_native_projection_fused_source_v1.zig").Slot{ canonical.slots, bounded.slots }) |slots| {
            var actual = try Batch.generate(a, columns, slots, &relations);
            defer actual.deinit();
            for (slots, actual.values) |slot, value| {
                const expected = try Old.generateProjection(a, columns, slot, &relations);
                defer for (expected.columns) |column| a.free(column);
                try std.testing.expectEqualDeep(expected.sum, value.sum);
                for (expected.columns, value.columns) |left, right| try std.testing.expectEqualSlices(M, left, right);
            }
            const invalid = try a.dupe(Engine.pcs.ColumnEvaluation, columns);
            defer a.free(invalid);
            invalid[0].log_size += 1;
            try std.testing.expectError(error.InvalidProjectionBatchGeometry, Batch.generate(a, invalid, slots, &relations));
            if (log == 1) {
                var zero = relations;
                for (&zero.elements) |*element| element.* = @TypeOf(element.*).init(element.arity, core.fields.qm31.QM31.zero(), core.fields.qm31.QM31.zero());
                // Physical row zero is entirely inactive. A zero numerator
                // still must not excuse a zero denominator in any stream.
                try std.testing.expectError(error.DivisionByZero, Batch.generate(a, columns, slots, &zero));
            }
        }
    };
}
