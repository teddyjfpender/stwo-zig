const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Opcode = @import("../../runner/trace.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Projection = @import("../block_v5_native_projection_fused_component_v1.zig").Component;
const Batch = @import("../block_v8_native_projection_domain_batch_v1.zig");
const Fused = @import("../block_v5_native_projection_fused_proof_v2.zig");
const CP = E.air.component_prover;

fn shapeFor(family: Opcode.OpcodeFamily, log: u32) Shape {
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    const rows = @as(u32, 1) << @intCast(log);
    shape.n_components = 1;
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

test "batched domain quotients equal every original slot for seventeen families q2 q3 and parallel rows" {
    const a = std.testing.allocator;
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const relations = @import("../../recursion/air/universal_challenges.zig").UniversalRelations.dummy();
    for (0..Opcode.N_FAMILIES) |family| for ([_]u32{ 1, 7 }) |log| {
        var shape = shapeFor(@enumFromInt(family), log);
        var canonical = try @import("../block_v7_native_relation_layout_v1.zig").Layout.init(a, &shape, 0, 1);
        defer canonical.deinit();
        var bounded = try @import("../block_v7_degree_bounded_relation_layout_v1.zig").Layout.init(a, &shape, 0, 1);
        defer bounded.deinit();
        for ([_][]const Source.Slot{ canonical.slots, bounded.slots }) |slots| {
            const split = Fused.compositionSplit(slots);
            const main_count = Opcode.nColumnsForFamily(@enumFromInt(family)) + 10;
            const main_logs = try a.alloc(u32, main_count);
            defer a.free(main_logs);
            @memset(main_logs, log);
            const interaction_logs = try a.alloc(u32, 4 * slots.len);
            defer a.free(interaction_logs);
            @memset(interaction_logs, log);
            const polys = try a.alloc(CP.Poly, main_count + interaction_logs.len);
            defer a.free(polys);
            var initialized: usize = 0;
            defer for (polys[0..initialized]) |poly| a.free(poly.values);
            for (polys, 0..) |*poly, column| {
                const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
                for (values, 0..) |*value, row| value.* = M.fromU64((column * 31 + row * 17 + 11) % 257);
                poly.* = .{ .log_size = log, .values = values };
                initialized += 1;
            }
            var trees = [_][]const CP.Poly{ &.{}, polys[0..main_count], polys[main_count..] };
            const trace = CP.Trace{ .polys = .initOwned(&trees) };
            const items = try a.alloc(Projection, slots.len);
            defer a.free(items);
            const originals = try a.alloc(core.air.components.Component, slots.len);
            defer a.free(originals);
            for (items, slots, originals, 0..) |*item, slot, *original, i| {
                item.* = try (Projection{ .slot = slot, .fixed_logs = &.{}, .main_logs = main_logs, .interaction_logs = interaction_logs, .root_owner = i == 0, .interaction_offset = 4 * i, .claim = Q.fromM31Array(.{ M.fromU64(i + 1), M.fromU64(i + 3), M.fromU64(i + 7), M.fromU64(i + 11) }), .relations = &relations, .composition_split = split }).init();
                original.* = item.asVerifierComponent();
            }
            const alpha = Q.fromM31Array(.{ M.fromU64(3), M.fromU64(5), M.fromU64(7), M.fromU64(11) });
            var reference = try E.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + split, items.len);
            defer reference.deinit();
            for (items) |*item| try item.evaluateConstraintQuotientsOnDomain(&trace, &reference);
            var expected = try reference.finalize();
            defer expected.deinit(a);
            for ([_]usize{ 1, 4, 32 }) |batch_slots| {
                const batch = try Batch.Owned.init(a, items, originals, .{ .max_batch_slots = batch_slots, .max_interaction_workspace_bytes = if (batch_slots == 1) 1 else 1 << 20 });
                defer batch.deinit();
                var actual = try E.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + split, items.len);
                defer actual.deinit();
                try batch.evaluateConstraintQuotientsOnDomain(&trace, &actual);
                var result = try actual.finalize();
                defer result.deinit(a);
                try std.testing.expectEqual(expected.len(), result.len());
                for (0..expected.len()) |i| try std.testing.expectEqualDeep(expected.at(i), result.at(i));
            }
        }
    };
}
