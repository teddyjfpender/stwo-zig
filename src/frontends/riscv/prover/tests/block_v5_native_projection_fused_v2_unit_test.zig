//! Nonproving four-tree remapping/census/mutation and concrete API gate.
//! No commitments, STARK, FRI, guest execution or segment job is run here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Proof = @import("../block_v5_native_projection_fused_proof_v2.zig");
const Receiver = @import("../block_v5_native_projection_fused_receiver_v2.zig");
const Components = @import("../block_v5_native_projection_fused_component_v2.zig");
const MemoryComponent = @import("../block_execution_sidecar_stark_v2.zig").Component;
const MemorySlots = @import("../block_execution_sidecar_batch_v2.zig");
const MemoryProof = @import("../block_v5_opcode_memory_sidecar_proof_v1.zig");
const Integer = @import("../block_execution_integer_bridge_v2.zig");
const Eval = @import("../block_v5_opcode_sidecar_eval_v1.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Opcode = @import("../../runner/trace.zig");
const Template = @import("../block_v5_native_template_protocol_v3.zig");
const Word = @import("../block_v5_word_memory_protocol_v1.zig");
const Bus = @import("../block_memory_relation_v2.zig");
const Frame = @import("../../air/block/memory_event.zig").Frame;
const Coefficients = engine.poly.circle.poly.CircleCoefficients;
const Accumulator = core.air.accumulation.PointEvaluationAccumulator;
const DomainAccumulator = engine.air.accumulation.DomainEvaluationAccumulator;
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
fn pointColumns(a: std.mem.Allocator, count: usize, samples: usize, seed: usize) ![][]Q {
    const columns = try a.alloc([]Q, count);
    for (columns, 0..) |*column, i| {
        column.* = try a.alloc(Q, samples);
        for (column.*, 0..) |*cell, j| cell.* = value(seed + i + j * 137);
    }
    return columns;
}
fn polys(a: std.mem.Allocator, count: usize, seed: usize) ![]const engine.air.component_prover.Poly {
    const columns = try a.alloc(engine.air.component_prover.Poly, count);
    for (columns, 0..) |*poly, i| {
        const coeffs = try a.dupe(M, &.{ M.fromCanonical(@intCast(7 + seed + i)), M.fromCanonical(@intCast(11 + 3 * i)) });
        poly.* = .{ .log_size = 1, .values = &.{}, .coefficients = try Coefficients.initBorrowed(coeffs) };
    }
    return columns;
}
fn check(family: Opcode.OpcodeFamily, mode: u32) !usize {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var shape = shapeFor(family);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 1 };
    const projections = try Source.slotsFromShapeForMode(a, &shape, 0, mode);
    const slots = try MemorySlots.slotsFromStatementForMode(a, &shape, frame, mode);
    const fixed = try Template.columnLogs(a, &shape, 0, .fixed);
    const main = try Template.columnLogs(a, &shape, 0, .main);
    try Proof.validateRoster(projections, slots, main, mode);
    const interaction = try Proof.interactionLogs(a, projections, slots);
    const witness = try Proof.witnessLogs(a, slots);
    try std.testing.expectEqual(projections.len * 4 + slots.len * Eval.INTERACTION_COUNT, interaction.len);
    try std.testing.expectEqual(slots.len * Integer.COLUMN_COUNT, witness.len);
    const mask = try Proof.mainMask(a, main.len, projections, slots);
    var universal_channel = core.proof_suites.Blake3.Channel{};
    const universal = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &universal_channel);
    var packed_channel = core.proof_suites.Blake3.Channel{};
    const word_challenges = try Word.Challenges.drawFromChannel(a, &packed_channel);
    var bus_channel = core.proof_suites.Blake3.Channel{};
    const bus = try Bus.Challenges.drawFromChannel(a, &bus_channel);
    // Both unchanged paths use the identical frozen universal prefix.
    try std.testing.expectEqualDeep(universal, word_challenges.universal_prefix);
    try std.testing.expectEqualDeep(universal, bus.universal_prefix);
    const point = core.circle.secureFieldPoint(127);
    const fixed_values = try pointColumns(a, fixed.len, 0, 10);
    const main_values = try pointColumns(a, main.len, 1, 100);
    const witness_values = try pointColumns(a, witness.len, 1, 300);
    const interaction_values = try pointColumns(a, interaction.len, 2, 500);
    var full_trees: [4][][]Q = .{ fixed_values, main_values, witness_values, interaction_values };
    var separate_trees: [3][][]Q = .{ fixed_values, main_values, interaction_values };
    const full_mask = core.air.components.MaskValues{ .items = &full_trees };
    const separate_mask = core.air.components.MaskValues{ .items = &separate_trees };
    const fixed_polys = try polys(a, 0, 0);
    const main_polys = try polys(a, main.len, 100);
    const witness_polys = try polys(a, witness.len, 300);
    const interaction_polys = try polys(a, interaction.len, 500);
    var four_polys: [4][]const engine.air.component_prover.Poly = .{ fixed_polys, main_polys, witness_polys, interaction_polys };
    var three_polys: [3][]const engine.air.component_prover.Poly = .{ fixed_polys, main_polys, interaction_polys };
    const full_trace = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&four_polys) };
    const separate_trace = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&three_polys) };
    var actual_composite = Accumulator.init(value(9));
    var expected_composite = Accumulator.init(value(9));
    const split = Proof.compositionSplit(projections);
    for (projections, 0..) |slot, i| {
        const inner = try (@import("../block_v5_native_projection_fused_component_v1.zig").Component{ .slot = slot, .fixed_logs = fixed, .main_logs = main, .root_owner = i == 0, .main_open_mask = mask, .interaction_offset = 4 * i, .interaction_logs = interaction, .claim = value(i), .relations = &universal, .composition_split = split }).init();
        const fused = try (Components.ProjectionComponent{ .inner = inner, .has_access_witness = slots.len != 0 }).init();
        var bounds = try fused.traceLogDegreeBounds(a);
        defer bounds.deinitDeep(a);
        var points = try fused.maskPoints(a, point, 1);
        defer points.deinitDeep(a);
        const tree_count: usize = if (slots.len == 0) 3 else 4;
        try std.testing.expectEqual(tree_count, bounds.items.len);
        try std.testing.expectEqual(tree_count, points.items.len);
        if (slots.len != 0) {
            try std.testing.expectEqual(@as(usize, 0), bounds.items[2].len);
            try std.testing.expectEqual(@as(usize, 0), points.items[2].len);
        }
        const interaction_tree = tree_count - 1;
        for (points.items[interaction_tree]) |samples| {
            try std.testing.expectEqual(@as(usize, 2), samples.len);
            try std.testing.expect(samples[0].eql(point));
            try std.testing.expect(samples[1].eql(@import("../../air/logup.zig").prevRowPoint(1, point)));
        }
        if (i == 0) for (points.items[1], mask) |samples, open| try std.testing.expectEqual(@as(usize, if (open) 1 else 0), samples.len);
        const view_mask = if (slots.len == 0) &separate_mask else &full_mask;
        const view_trace = if (slots.len == 0) &separate_trace else &full_trace;
        try fused.evaluateConstraintQuotientsAtPoint(point, view_mask, &actual_composite, 1);
        try inner.evaluateConstraintQuotientsAtPoint(point, &separate_mask, &expected_composite, 1);
        var actual_domain = try DomainAccumulator.init(a, value(9), 1 + split, 1);
        defer actual_domain.deinit();
        var expected_domain = try DomainAccumulator.init(a, value(9), 1 + split, 1);
        defer expected_domain.deinit();
        try fused.evaluateConstraintQuotientsOnDomain(view_trace, &actual_domain);
        try inner.evaluateConstraintQuotientsOnDomain(&separate_trace, &expected_domain);
        for (0..(@as(usize, 1) << @intCast(1 + split))) |row| try std.testing.expectEqualDeep(expected_domain.sub_accumulations[1 + split].?.at(row), actual_domain.sub_accumulations[1 + split].?.at(row));
        const saved = interaction_values[4 * i];
        interaction_values[4 * i] = saved[0..1];
        var unused = Accumulator.init(value(9));
        try std.testing.expectError(error.MissingV5FusedProjectionPoint, fused.evaluateConstraintQuotientsAtPoint(point, view_mask, &unused, 1));
        interaction_values[4 * i] = saved;
    }
    for (slots, 0..) |slot, i| {
        const inner = try (MemoryComponent{ .family = slot.family, .slot = slot.slot, .log_size = slot.log_size, .base_clock = try Integer.baseClockFromPublicFrame(frame), .fixed_logs = fixed, .main_logs = main, .witness_logs = witness, .interaction_logs = interaction, .root_owner = false, .main_offset = slot.main_offset, .witness_offset = i * Integer.COLUMN_COUNT, .interaction_offset = projections.len * 4 + i * Eval.INTERACTION_COUNT, .transition_claim = value(i), .transition_count = 1, .range_claims = @splat(value(i + 3)), .challenges = &bus, .v5_packed = .{ .elements = &word_challenges }, .v5_universal = .{ .claim = value(i + 2), .elements = universal.get(.memory_access) }, .register_custody_mode = mode }).init();
        const fused = try (Components.AccessComponent{ .inner = inner, .composition_split = split }).init();
        var points = try fused.maskPoints(a, point, 1);
        defer points.deinitDeep(a);
        try std.testing.expectEqual(@as(usize, 4), points.items.len);
        for (points.items[2]) |samples| try std.testing.expectEqual(@as(usize, 1), samples.len);
        for (points.items[3]) |samples| try std.testing.expectEqual(@as(usize, 2), samples.len);
        try fused.evaluateConstraintQuotientsAtPoint(point, &full_mask, &actual_composite, 1);
        try inner.evaluateConstraintQuotientsAtPoint(point, &full_mask, &expected_composite, 1);
        var actual_domain = try DomainAccumulator.init(a, value(9), 3, fused.nConstraints());
        defer actual_domain.deinit();
        var expected_domain = try DomainAccumulator.init(a, value(9), 3, inner.nConstraints());
        defer expected_domain.deinit();
        try fused.evaluateConstraintQuotientsOnDomain(&full_trace, &actual_domain);
        try inner.evaluateConstraintQuotientsOnDomain(&full_trace, &expected_domain);
        for (0..8) |row| try std.testing.expectEqualDeep(expected_domain.sub_accumulations[3].?.at(row), actual_domain.sub_accumulations[3].?.at(row));
        const saved = witness_values[i * Integer.COLUMN_COUNT];
        witness_values[i * Integer.COLUMN_COUNT] = saved[0..0];
        var unused = Accumulator.init(value(9));
        try std.testing.expectError(error.MissingExecutionSidecarPoint, fused.evaluateConstraintQuotientsAtPoint(point, &full_mask, &unused, 1));
        witness_values[i * Integer.COLUMN_COUNT] = saved;
    }
    try std.testing.expectEqualDeep(expected_composite.finalize(), actual_composite.finalize());
    return slots.len;
}
test "block-v5 full fused nonproving projection access OODS domain and complete masks parity" {
    var accesses: usize = 0;
    for (0..Opcode.N_FAMILIES) |i| {
        const family: Opcode.OpcodeFamily = @enumFromInt(i);
        if (!@import("../../air/semantic_eval.zig").isTraceCompatible(family)) continue;
        for ([_]u32{ 0, 1 }) |mode| accesses += try check(family, mode);
    }
    try std.testing.expect(accesses != 0);
}
test "block-v5 full fused identities bind frame mode witness both rosters and reject v1" {
    const a = std.testing.allocator;
    var shape = shapeFor(.load_store);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 11, .cycle_count = 1 };
    const projections = try Source.slotsFromShapeForMode(a, &shape, 0, 1);
    defer a.free(projections);
    const slots = try MemorySlots.slotsFromStatementForMode(a, &shape, frame, 1);
    defer a.free(slots);
    const roots: [2][32]u8 = .{ @splat(3), @splat(4) };
    const original = Proof.instanceId(@splat(1), @splat(2), roots, @splat(5), 0, frame, projections, slots);
    const old = @import("../block_v5_native_projection_fused_receiver_v1.zig").instanceId(@splat(1), @splat(2), 0, projections);
    try std.testing.expect(!std.meta.eql(original, old));
    var changed_frame = frame;
    changed_frame.global_first_cycle += 1;
    try std.testing.expect(!std.meta.eql(original, Proof.instanceId(@splat(1), @splat(2), roots, @splat(5), 0, changed_frame, projections, slots)));
    try std.testing.expect(!std.meta.eql(original, Proof.instanceId(@splat(1), @splat(2), roots, @splat(6), 0, frame, projections, slots)));
    try std.testing.expect(!std.meta.eql(original, Proof.instanceId(@splat(1), @splat(2), roots, @splat(5), 1, frame, projections, slots)));
    const changed = try a.dupe(Source.Slot, projections);
    defer a.free(changed);
    changed[0].register_custody_mode = 0;
    try std.testing.expect(!std.meta.eql(original, Proof.instanceId(@splat(1), @splat(2), roots, @splat(5), 0, frame, changed, slots)));
    try std.testing.expectError(error.InvalidV5FullFusedRoster, Proof.requireProjectionRoster(changed, projections));
    const memory_changed = try a.dupe(MemoryProof.Slot, slots);
    defer a.free(memory_changed);
    memory_changed[0].slot += 1;
    try std.testing.expect(!std.meta.eql(original, Proof.instanceId(@splat(1), @splat(2), roots, @splat(5), 0, frame, projections, memory_changed)));
    const absent = Proof.instanceId(@splat(1), @splat(2), roots, @import("../block_v5_empty_opcode_memory_v1.zig").witnessRootForMode(1), 0, frame, &.{}, &.{});
    try std.testing.expect(!std.meta.eql(absent, Proof.instanceId(@splat(1), @splat(2), roots, @import("../block_v5_empty_opcode_memory_v1.zig").witnessRootForMode(0), 0, frame, &.{}, &.{})));
}
test "block-v5 full fused typed absence never accepts dummy STARK or missing real projection" {
    try Receiver.requireProofPresence(0, 0, false);
    try std.testing.expectError(error.UntrustedV5FullFusedTypedAbsence, Receiver.requireProofPresence(0, 0, true));
    try std.testing.expectError(error.UntrustedV5FullFusedTypedAbsence, Receiver.requireProofPresence(0, 1, false));
    try std.testing.expectError(error.MissingV5FullFusedProof, Receiver.requireProofPresence(1, 0, false));
    try Receiver.requireProofPresence(1, 0, true);
    try Receiver.requireProofPresence(1, 1, true);
}
test "block-v5 full fused nonproving concrete producer receiver stage and memory hook codegen" {
    const Api = Proof.ForBackend(Cpu);
    const Receive = Receiver.ForBackend(Cpu);
    const Stage = @import("../block_v5_native_projection_fused_stage_v2.zig").ForBackend(Cpu);
    const Join = @import("../block_v5_word_memory_join_v1.zig").ForBackend(Cpu);
    const prove: *const @TypeOf(Api.proveForNativeFirstRound) = &Api.proveForNativeFirstRound;
    const verify: *const @TypeOf(Receive.verifyOwned) = &Receive.verifyOwned;
    const after: *const @TypeOf(Receive.verifyAfterFreshNative) = &Receive.verifyAfterFreshNative;
    const stage: *const @TypeOf(Stage.hooks) = &Stage.hooks;
    const join: *const @TypeOf(Join.onFusedNative) = &Join.onFusedNative;
    std.mem.doNotOptimizeAway(prove);
    std.mem.doNotOptimizeAway(verify);
    std.mem.doNotOptimizeAway(after);
    std.mem.doNotOptimizeAway(stage);
    std.mem.doNotOptimizeAway(join);
}
