//! Nonproving parity and code-generation gate. No STARK/FRI job is executed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Opcode = @import("../../runner/trace.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Fused = @import("../block_v5_native_projection_fused_component_v1.zig").Component;
const Program = @import("../block_v5_program_request_component_v1.zig").Component;
const Lookup = @import("../block_v5_native_lookup_request_component_v1.zig").Component;
const Template = @import("../block_v5_native_template_protocol_v3.zig");
const Accumulator = core.air.accumulation.PointEvaluationAccumulator;
const DomainAccumulator = engine.air.accumulation.DomainEvaluationAccumulator;
const Coefficients = engine.poly.circle.poly.CircleCoefficients;
fn value(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(3 + seed * 7), @intCast(5 + seed * 11), @intCast(7 + seed * 13), @intCast(11 + seed * 17));
}
fn shapeFor(family: Opcode.OpcodeFamily) Shape {
    var shape = std.mem.zeroes(Shape);
    shape.initializeDescriptorStorage();
    shape.n_components = 1;
    shape.component_descs[0] = .{ .family = family, .log_size = 1, .n_rows = 1, .n_columns = @intCast(Opcode.nColumnsForFamily(family)) };
    shape.n_infra = 1;
    shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    shape.total_steps = 1;
    shape.public_data.clock = 1;
    shape.public_data.program_root = .{ .bytes = @splat(1) };
    shape.public_data.completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0);
    shape.public_data.io_entries.input_words = &.{};
    shape.public_data.io_entries.output_words = &.{};
    return shape;
}
fn separateAtPoint(component: Fused, point: core.circle.CirclePointQM31, mask: *const core.air.components.MaskValues, accumulation: *Accumulator) !void {
    switch (component.slot.kind) {
        .program => |family| {
            const original = try (Program{ .family = family, .log_size = component.slot.log_size, .main_offset = component.slot.main_offset, .fixed_logs = component.fixed_logs, .main_logs = component.main_logs, .root_owner = component.root_owner, .main_open_mask = component.main_open_mask, .interaction_offset = component.interaction_offset, .interaction_logs = component.interaction_logs, .claim = component.claim, .relations = component.relations }).init();
            try original.evaluateConstraintQuotientsAtPoint(point, mask, accumulation, component.slot.log_size);
        },
        .lookup => |slot| {
            const original = try (Lookup{ .slot = slot, .fixed_logs = component.fixed_logs, .main_logs = component.main_logs, .root_owner = component.root_owner, .main_open_mask = component.main_open_mask, .interaction_offset = component.interaction_offset, .interaction_logs = component.interaction_logs, .claim = component.claim, .relations = component.relations, .composition_split = component.composition_split }).init();
            try original.evaluateConstraintQuotientsAtPoint(point, mask, accumulation, component.slot.log_size);
        },
    }
}

fn checkSchedule(shape: *const Shape, mode: u32) !void {
    const a = std.testing.allocator;
    const slots = try Source.slotsFromShapeForMode(a, shape, 0, mode);
    defer a.free(slots);
    const fixed_logs = try Template.columnLogs(a, shape, 0, .fixed);
    defer a.free(fixed_logs);
    const main_logs = try Template.columnLogs(a, shape, 0, .main);
    defer a.free(main_logs);
    const interaction_logs = try a.alloc(u32, slots.len * 4);
    defer a.free(interaction_logs);
    const open_mask = try a.alloc(bool, main_logs.len);
    defer a.free(open_mask);
    @memset(open_mask, false);
    var split: u32 = 2;
    for (slots, 0..) |slot, i| {
        @memset(interaction_logs[4 * i ..][0..4], slot.log_size);
        @memset(open_mask[slot.main_offset..][0..slot.width], true);
        split = @max(split, std.math.log2_int_ceil(u32, slot.degree));
    }
    var relation_channel = core.proof_suites.Blake3.Channel{};
    relation_channel.mixU32s(&.{ 1, mode, @intFromEnum(shape.component_descs[0].family) });
    const relations = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &relation_channel);
    const point = core.circle.secureFieldPoint(127);
    const main_storage = try a.alloc([1]Q, main_logs.len);
    defer a.free(main_storage);
    const main_mask = try a.alloc([]Q, main_logs.len);
    defer a.free(main_mask);
    for (main_storage, main_mask, 0..) |*cell, *column, i| {
        cell.* = .{value(100 + i)};
        column.* = cell;
    }
    const interaction_storage = try a.alloc([2]Q, interaction_logs.len);
    defer a.free(interaction_storage);
    const interaction_mask = try a.alloc([]Q, interaction_logs.len);
    defer a.free(interaction_mask);
    for (interaction_storage, interaction_mask, 0..) |*cell, *column, i| {
        cell.* = .{ value(200 + i), value(300 + i) };
        column.* = cell;
    }
    const fixed_mask = try a.alloc([]Q, fixed_logs.len);
    defer a.free(fixed_mask);
    for (fixed_mask) |*column| column.* = &.{};
    var tree_masks: [3][][]Q = .{ fixed_mask, main_mask, interaction_mask };
    const mask = core.air.components.MaskValues{ .items = &tree_masks };
    // Small degree-one source/interaction polynomials. Domain evaluation below
    // performs only transforms and quotient equations, never commitments/FRI.
    const coefficient_storage = try a.alloc([2]M, main_logs.len + interaction_logs.len);
    defer a.free(coefficient_storage);
    const main_polys = try a.alloc(engine.air.component_prover.Poly, main_logs.len);
    defer a.free(main_polys);
    const interaction_polys = try a.alloc(engine.air.component_prover.Poly, interaction_logs.len);
    defer a.free(interaction_polys);
    for (coefficient_storage, 0..) |*coeffs, i| coeffs.* = .{ M.fromCanonical(@intCast(7 + i)), M.fromCanonical(@intCast(11 + 3 * i)) };
    for (main_polys, coefficient_storage[0..main_logs.len]) |*poly, *coeffs| poly.* = .{ .log_size = 1, .values = &.{}, .coefficients = try Coefficients.initBorrowed(coeffs) };
    for (interaction_polys, coefficient_storage[main_logs.len..]) |*poly, *coeffs| poly.* = .{ .log_size = 1, .values = &.{}, .coefficients = try Coefficients.initBorrowed(coeffs) };
    var poly_trees: [3][]const engine.air.component_prover.Poly = .{ &.{}, main_polys, interaction_polys };
    const trace = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&poly_trees) };
    var actual_composite = Accumulator.init(value(9));
    var separate_composite = Accumulator.init(value(9));
    for (slots, 0..) |slot, i| {
        const fused = try (Fused{ .slot = slot, .fixed_logs = fixed_logs, .main_logs = main_logs, .root_owner = i == 0, .main_open_mask = open_mask, .interaction_offset = 4 * i, .interaction_logs = interaction_logs, .claim = value(i + 1), .relations = &relations, .composition_split = split }).init();
        var bounds = try fused.traceLogDegreeBounds(a);
        defer bounds.deinitDeep(a);
        var points = try fused.maskPoints(a, point, slot.log_size);
        defer points.deinitDeep(a);
        try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
        try std.testing.expectEqual(@as(usize, 4), bounds.items[2].len);
        try std.testing.expectEqual(@as(usize, if (i == 0) main_logs.len else 0), points.items[1].len);
        if (i == 0) for (points.items[0]) |column| try std.testing.expectEqual(@as(usize, 0), column.len);
        if (i == 0) for (points.items[1], open_mask) |column, open| try std.testing.expectEqual(@as(usize, if (open) 1 else 0), column.len);
        for (points.items[2]) |column| {
            try std.testing.expectEqual(@as(usize, 2), column.len);
            try std.testing.expect(column[0].eql(point));
            try std.testing.expect(column[1].eql(@import("../../air/logup.zig").prevRowPoint(slot.log_size, point)));
        }
        var actual = Accumulator.init(value(9));
        var expected = Accumulator.init(value(9));
        try fused.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, slot.log_size);
        try separateAtPoint(fused, point, &mask, &expected);
        try std.testing.expectEqualDeep(expected.finalize(), actual.finalize());
        const saved_main = main_mask[slot.main_offset];
        main_mask[slot.main_offset] = saved_main[0..0];
        try std.testing.expectError(error.MissingV5FusedProjectionPoint, fused.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, slot.log_size));
        main_mask[slot.main_offset] = saved_main;
        const saved_interaction = interaction_mask[4 * i];
        interaction_mask[4 * i] = saved_interaction[0..1];
        try std.testing.expectError(error.MissingV5FusedProjectionPoint, fused.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, slot.log_size));
        interaction_mask[4 * i] = saved_interaction;
        try fused.evaluateConstraintQuotientsAtPoint(point, &mask, &actual_composite, slot.log_size);
        try separateAtPoint(fused, point, &mask, &separate_composite);
        var domain_accumulator = try DomainAccumulator.init(a, value(9), slot.log_size + split, 1);
        defer domain_accumulator.deinit();
        try fused.evaluateConstraintQuotientsOnDomain(&trace, &domain_accumulator);
        const cache = (try @import("../block_v7_shared_quotient_cache_v1.zig").Owner.create(a, 256)).?;
        defer cache.destroy();
        var leased = fused;
        leased.leased_quotient_cache = &cache.cache;
        var leased_accumulator = try DomainAccumulator.init(a, value(9), slot.log_size + split, 1);
        defer leased_accumulator.deinit();
        try leased.evaluateConstraintQuotientsOnDomain(&trace, &leased_accumulator);
        const eval_log = slot.log_size + split;
        const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
        for (0..domain.size()) |row| {
            const base_point = domain.at(core.utils.bitReverseIndex(row, eval_log));
            const domain_point = core.circle.CirclePointQM31{ .x = Q.fromBase(base_point.x), .y = Q.fromBase(base_point.y) };
            const previous_point = @import("../../air/logup.zig").prevRowPoint(slot.log_size, domain_point);
            for (main_polys, main_storage) |poly, *cell| cell.* = .{poly.coefficients.?.evalAtPoint(domain_point)};
            for (interaction_polys, interaction_storage) |poly, *cell| cell.* = .{ poly.coefficients.?.evalAtPoint(domain_point), poly.coefficients.?.evalAtPoint(previous_point) };
            var reference = Accumulator.init(value(9));
            try separateAtPoint(fused, domain_point, &mask, &reference);
            try std.testing.expectEqualDeep(reference.finalize(), domain_accumulator.sub_accumulations[eval_log].?.at(row));
            try std.testing.expectEqualDeep(reference.finalize(), leased_accumulator.sub_accumulations[eval_log].?.at(row));
        }
        // Restore arbitrary secure (nonbase) OODS samples for the next slot.
        for (main_storage, 0..) |*cell, j| cell.* = .{value(100 + j)};
        for (interaction_storage, 0..) |*cell, j| cell.* = .{ value(200 + j), value(300 + j) };
    }
    try std.testing.expectEqualDeep(separate_composite.finalize(), actual_composite.finalize());
}

test "block-v5 fused native nonproving masks OODS and domain equations match separate projections" {
    for (0..Opcode.N_FAMILIES) |index| {
        const family: Opcode.OpcodeFamily = @enumFromInt(index);
        if (!@import("../../air/semantic_eval.zig").isTraceCompatible(family)) continue;
        var shape = shapeFor(family);
        for ([_]u32{ 0, 1 }) |mode| try checkSchedule(&shape, mode);
    }
}
test "block-v5 fused native nonproving producer and fresh receiver APIs compile" {
    const ProofApi = @import("../block_v5_native_projection_fused_proof_v1.zig").ForBackend(Cpu);
    const ReceiverApi = @import("../block_v5_native_projection_fused_receiver_v1.zig").ForBackend(Cpu);
    const Stage = @import("../block_v5_native_projection_fused_stage_v1.zig").ForBackend(Cpu);
    const borrowed: *const @TypeOf(ProofApi.borrowFirstRound) = &ProofApi.borrowFirstRound;
    const prove: *const @TypeOf(ProofApi.prove) = &ProofApi.prove;
    const verify: *const @TypeOf(ReceiverApi.verifyOwned) = &ReceiverApi.verifyOwned;
    const stage: *const @TypeOf(Stage.hooks) = &Stage.hooks;
    std.mem.doNotOptimizeAway(borrowed);
    std.mem.doNotOptimizeAway(prove);
    std.mem.doNotOptimizeAway(verify);
    std.mem.doNotOptimizeAway(stage);
}

fn checkGenerated(slot: Source.Slot, relations: *const @import("../../recursion/air/universal_challenges.zig").UniversalRelations) !void {
    const a = std.testing.allocator;
    const Column = engine.pcs.ColumnEvaluation;
    const Generator = @import("../block_v5_native_projection_fused_proof_v2.zig");
    const Framework = @import("../../recursion/air/framework_interaction.zig");
    const size = @as(usize, 1) << @intCast(slot.log_size);
    const columns = try a.alloc(Column, slot.main_offset + slot.width);
    defer a.free(columns);
    const storage = try a.alloc(M, columns.len * size);
    defer a.free(storage);
    for (columns, 0..) |*column, i| {
        column.* = .{ .log_size = slot.log_size, .values = storage[i * size ..][0..size] };
        for (storage[i * size ..][0..size], 0..) |*cell, j| cell.* = M.fromCanonical(@intCast((i * 17 + j * 7 + 3) % 1009));
    }
    const generated = try Generator.generateProjection(a, columns, slot, relations);
    defer for (generated.columns) |column| a.free(column);
    const terms = try a.alloc(Q, size);
    defer a.free(terms);
    var sum = Q.zero();
    // Independent old scalar algorithm: each denominator is inverted alone.
    for (terms, 0..) |*term, logical| {
        var row: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        const physical = Framework.committedRow(logical, slot.log_size);
        for (row[0..slot.width], columns[slot.main_offset..]) |*cell, column| cell.* = Q.fromBase(column.values[physical]);
        const pair = try Source.fromCommittedMain(slot, row[0..slot.width], relations);
        term.* = pair.numerator().mul(try pair.denominator().inv());
        sum = sum.add(term.*);
    }
    try std.testing.expectEqualDeep(sum, generated.sum);
    const shift = try sum.divM31(M.fromCanonical(@intCast(size)));
    var running = Q.zero();
    for (terms, 0..) |term, logical| {
        running = running.add(term).sub(shift);
        for (generated.columns, running.toM31Array()) |column, limb| try std.testing.expectEqualDeep(limb, column[Framework.committedRow(logical, slot.log_size)]);
    }
    // Geometry errors must be caught even if that column's request is inactive.
    columns[slot.main_offset].log_size += 1;
    try std.testing.expectError(error.InvalidV5FullFusedRoster, Generator.generateProjection(a, columns, slot, relations));
    columns[slot.main_offset].log_size -= 1;
    var zero_relations = relations.*;
    for (&zero_relations.elements) |*element| {
        element.z = Q.zero();
        element.alpha = Q.zero();
        @memset(&element.alpha_powers, Q.zero());
    }
    const zero_error = Q.zero().inv();
    try std.testing.expectError(if (zero_error) |_| unreachable else |err| err, Generator.generateProjection(a, columns, slot, &zero_relations));
}

test "native projection tiled inversion preserves every physical prefix across opcode families and modes" {
    const a = std.testing.allocator;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 19, 83, 101 });
    const relations = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    for (0..Opcode.N_FAMILIES) |index| {
        const family: Opcode.OpcodeFamily = @enumFromInt(index);
        if (!@import("../../air/semantic_eval.zig").isTraceCompatible(family)) continue;
        var shape = shapeFor(family);
        for ([_]u32{ 0, 1 }) |mode| {
            const slots = try Source.slotsFromShapeForMode(a, &shape, 0, mode);
            defer a.free(slots);
            for (slots) |slot| try checkGenerated(slot, &relations);
            // Cross a tile boundary without changing the original typed recipe.
            if (index == 0) {
                var large = slots[0];
                large.log_size = 13;
                large.n_rows = 8192;
                try checkGenerated(large, &relations);
            }
        }
    }
}

test "native projection parallel tiles and unavailable nested lease preserve scalar prefix" {
    const a = std.testing.allocator;
    const Pool = engine.work_pool;
    var pool: Pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 193, 181, 107 });
    const relations = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    var shape = shapeFor(.base_alu_imm);
    const slots = try Source.slotsFromShapeForMode(a, &shape, 0, 1);
    defer a.free(slots);
    var slot = slots[0];
    slot.log_size = 15;
    slot.n_rows = 32768;
    try checkGenerated(slot, &relations);
    var held = try pool.acquire(try Pool.WorkerBudget.init(3));
    defer held.deinit();
    // Must fall back without waiting for the lease held by this coordinator.
    try checkGenerated(slot, &relations);
}
