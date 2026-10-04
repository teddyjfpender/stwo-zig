//! Nonproving B5CF source/mask/equation/domain/fault/body fixtures. No PCS
//! commitment, interaction generation, STARK, FRI, guest or device invocation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Source = @import("../block_v5_native_capacity_fused_source_v1.zig");
const Protocol = @import("../block_v5_native_capacity_protocol_v1.zig");
const Native = @import("../block_v5_native_capacity_proof_v1.zig");
const Proof = @import("../block_v5_native_capacity_fused_proof_v1.zig");
const Receiver = @import("../block_v5_native_capacity_fused_receiver_v1.zig");
const Stage = @import("../block_v5_native_capacity_fused_stage_v1.zig");
const Adapter = @import("../block_v5_native_capacity_fused_component_v1.zig");
const OldAdapter = @import("../block_v5_native_projection_fused_component_v2.zig");
const Original = @import("../block_v5_native_projection_fused_source_v1.zig");
const Batch = @import("../block_execution_sidecar_batch_v2.zig");
const Memory = @import("../block_v5_opcode_memory_sidecar_proof_v1.zig");
const Integer = @import("../block_execution_integer_bridge_v2.zig");
const Eval = @import("../block_v5_opcode_sidecar_eval_v1.zig");
const Word = @import("../block_v5_word_memory_protocol_v1.zig");
const Bus = @import("../block_memory_relation_v2.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Catalog = @import("../block_v5_native_capacity_catalog_v1.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
const Opcode = @import("../../runner/trace.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const Poly = engine.air.component_prover.Poly;
const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 11, .cycle_count = 3 };
fn shape(family: Opcode.OpcodeFamily) Shape {
    var result = std.mem.zeroes(Shape);
    result.initializeDescriptorStorage();
    result.n_components = 1;
    result.component_descs[0] = .{ .family = family, .log_size = 2, .n_rows = 3, .n_columns = @intCast(Opcode.nColumnsForFamily(family)) };
    result.n_infra = 1;
    result.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../../air/clock_update_interaction.zig").N_MAIN_COLUMNS };
    result.total_steps = 3;
    result.public_data = .{ .initial_pc = 0, .final_pc = 0, .clock = 3, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}
fn value(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(seed + 7), @intCast(seed + 11), @intCast(seed + 13), @intCast(seed + 17));
}
fn points(a: std.mem.Allocator, logs: []const u32, n: usize, seed: usize) ![][]Q {
    const output = try a.alloc([]Q, logs.len);
    for (output, 0..) |*column, i| {
        column.* = try a.alloc(Q, n);
        for (column.*, 0..) |*sample, j| sample.* = value(seed + 29 * i + 151 * j);
    }
    return output;
}
fn polys(a: std.mem.Allocator, logs: []const u32, seed: usize) ![]const Poly {
    const output = try a.alloc(Poly, logs.len);
    for (output, logs, 0..) |*poly, log, i| {
        const coefficients = try a.alloc(M, @as(usize, 1) << @intCast(log));
        @memset(coefficients, M.zero());
        coefficients[0] = M.fromCanonical(@intCast(seed + 3 * i + 7));
        coefficients[1] = M.fromCanonical(@intCast(seed + 7 * i + 11));
        poly.* = .{ .log_size = log, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(coefficients) };
    }
    return output;
}

test "capacity fused exact source ordinals mixed selector origins mask union and resource mutations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]Opcode.OpcodeFamily{ .base_alu_imm, .load_store }) |family| {
        var source = shape(family);
        for ([_]u32{ 0, 1 }) |mode| {
            const projections = try Source.slotsFromShapeForMode(a, &source, 0, mode);
            const old = try Original.slotsFromShapeForMode(a, &source, 0, mode);
            try Proof.requireProjectionRoster(projections, old);
            const slots = try Source.memorySlots(a, &source, 0, frame, mode);
            const original_slots = try Batch.slotsFromStatementForMode(a, &source, frame, mode);
            try std.testing.expectEqualDeep(original_slots, slots);
            const fixed = try Protocol.columnLogs(a, &source, 0, .fixed);
            const main = try Protocol.columnLogs(a, &source, 0, .main);
            const plan = try Protocol.Plan.fromShape(&source, 0);
            try Source.requireLogs(&source, 0, fixed, main);
            try (Proof.Limits{}).require(&source, 0, projections, slots);
            const mask = try Proof.mainMask(a, main.len, projections, slots, &source, 0);
            for (plan.active()) |shard| {
                try std.testing.expect(mask[shard.main_index]);
                // Only the native fresh verifier needs the running count;
                // the fused sidecar opens the original source + selector.
                try std.testing.expect(!mask[shard.main_index + 1]);
            }
            for (projections) |slot| {
                const link = try Source.binding(&source, 0, slot.main_offset, slot.log_size, slot.n_rows);
                try std.testing.expectEqual(slot.log_size, main[link.main_index]);
                try std.testing.expectEqual(plan.native_main_count, link.native_main_count);
            }
            try std.testing.expectError(error.InvalidCapacityFusedSelectorOrigin, Source.binding(&source, 0, 1, 2, 3));
            try std.testing.expectError(error.InvalidCapacityFusedSelectorOrigin, Source.binding(&source, 0, 0, 2, 4));
            try std.testing.expectError(error.InvalidCapacityFusedColumnRoster, Proof.mainMask(a, plan.native_main_count, projections, slots, &source, 0));
            const saved = main[plan.shards[0].main_index];
            main[plan.shards[0].main_index] += 1;
            try std.testing.expectError(error.InvalidCapacityFusedColumnRoster, Source.requireLogs(&source, 0, fixed, main));
            main[plan.shards[0].main_index] = saved;
            try std.testing.expectError(error.CapacityFusedResourceLimit, (Proof.Limits{ .max_projection_slots = 0 }).require(&source, 0, projections, slots));
            try std.testing.expectError(error.CapacityFusedResourceLimit, (Proof.Limits{ .max_interaction_cells = 0 }).require(&source, 0, projections, slots));
            if (slots.len != 0) try std.testing.expectError(error.CapacityFusedResourceLimit, (Proof.Limits{ .max_witness_cells = 0 }).require(&source, 0, projections, slots));
        }
    }
}

fn parity(family: Opcode.OpcodeFamily, mode: u32) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var source = shape(family);
    const projections = try Source.slotsFromShapeForMode(a, &source, 0, mode);
    const slots = try Source.memorySlots(a, &source, 0, frame, mode);
    const fixed = try Protocol.columnLogs(a, &source, 0, .fixed);
    const main = try Protocol.columnLogs(a, &source, 0, .main);
    const witness = try Proof.witnessLogs(a, slots);
    const interaction = try Proof.interactionLogs(a, projections, slots);
    const open = try Proof.mainMask(a, main.len, projections, slots, &source, 0);
    var channel = core.proof_suites.Blake3.Channel{};
    const word = try Word.Challenges.drawFromChannel(a, &channel);
    var bus_channel = core.proof_suites.Blake3.Channel{};
    const bus = try Bus.Challenges.drawFromChannel(a, &bus_channel);
    const fixed_values = try points(a, fixed, 0, 7);
    const main_values = try points(a, main, 1, 31);
    const witness_values = try points(a, witness, 1, 59);
    const interaction_values = try points(a, interaction, 2, 101);
    var full: [4][][]Q = .{ fixed_values, main_values, witness_values, interaction_values };
    var no_access: [3][][]Q = .{ fixed_values, main_values, interaction_values };
    const mask = core.air.components.MaskValues{ .items = if (slots.len == 0) &no_access else &full };
    const point = core.circle.secureFieldPoint(127);
    const split = Proof.compositionSplit(projections);
    for (projections, 0..) |slot, index| {
        const old = try (OldAdapter.ProjectionComponent{ .has_access_witness = slots.len != 0, .inner = .{ .slot = slot, .fixed_logs = fixed, .main_logs = main, .root_owner = index == 0, .main_open_mask = open, .interaction_offset = 4 * index, .interaction_logs = interaction, .claim = value(index), .relations = &word.universal_prefix, .composition_split = split } }).init();
        const link = try Source.binding(&source, 0, slot.main_offset, slot.log_size, slot.n_rows);
        const fresh = try (Adapter.ProjectionComponent{ .inner = old, .binding = link }).init();
        var declared = try fresh.maskPoints(a, point, 2);
        defer declared.deinitDeep(a);
        if (index == 0) for (declared.items[1], open) |samples, yes| try std.testing.expectEqual(@as(usize, if (yes) 1 else 0), samples.len);
        var actual = core.air.accumulation.PointEvaluationAccumulator.init(value(901));
        var expected = core.air.accumulation.PointEvaluationAccumulator.init(value(901));
        try fresh.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, 2);
        try old.evaluateConstraintQuotientsAtPoint(point, &mask, &expected, 2);
        var row: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        for (row[0..slot.width], main_values[slot.main_offset..][0..slot.width]) |*cell, column| cell.* = column[0];
        const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(slot.log_size).coset(), point.repeatedDouble(2 - slot.log_size)).inv();
        expected.accumulate((try Source.activity(slot, row[0..slot.width])).sub(main_values[link.main_index][0]).mul(inverse));
        try std.testing.expectEqualDeep(expected.accumulation, actual.accumulation);
        const prior = actual.accumulation;
        const saved = main_values[link.main_index][0];
        main_values[link.main_index][0] = saved.add(Q.one());
        var mutated = core.air.accumulation.PointEvaluationAccumulator.init(value(901));
        try fresh.evaluateConstraintQuotientsAtPoint(point, &mask, &mutated, 2);
        try std.testing.expect(!std.meta.eql(prior, mutated.accumulation));
        main_values[link.main_index][0] = saved;
        const saved_samples = main_values[link.main_index];
        main_values[link.main_index] = saved_samples[0..0];
        try std.testing.expectError(error.InvalidCapacityFusedMasks, fresh.evaluateConstraintQuotientsAtPoint(point, &mask, &mutated, 2));
        main_values[link.main_index] = saved_samples;
        try std.testing.expectEqual(@as(u8, 1), try fresh.constraintDegreeBound(old.nConstraints()));
    }
    if (slots.len != 0) for (slots, 0..) |slot, index| {
        const old = try (OldAdapter.AccessComponent{ .composition_split = split, .inner = .{ .family = slot.family, .slot = slot.slot, .log_size = slot.log_size, .base_clock = try Integer.baseClockFromPublicFrame(frame), .fixed_logs = fixed, .main_logs = main, .witness_logs = witness, .interaction_logs = interaction, .root_owner = false, .main_offset = slot.main_offset, .witness_offset = index * Integer.COLUMN_COUNT, .interaction_offset = 4 * projections.len + index * Eval.INTERACTION_COUNT, .transition_claim = value(index), .transition_count = 1, .range_claims = @splat(value(index + 17)), .challenges = &bus, .v5_packed = .{ .elements = &word }, .v5_universal = .{ .claim = value(index + 29), .elements = word.universal_prefix.get(.memory_access) }, .register_custody_mode = mode } }).init();
        const binding = try Source.binding(&source, 0, slot.main_offset, slot.log_size, null);
        const fresh = try (Adapter.AccessComponent{ .inner = old, .binding = binding }).init();
        var actual = core.air.accumulation.PointEvaluationAccumulator.init(value(701));
        var expected = core.air.accumulation.PointEvaluationAccumulator.init(value(701));
        try fresh.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, 2);
        try old.evaluateConstraintQuotientsAtPoint(point, &mask, &expected, 2);
        var row: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        const width = Opcode.nColumnsForFamily(family);
        for (row[0..width], main_values[slot.main_offset..][0..width]) |*cell, column| cell.* = column[0];
        const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(slot.log_size).coset(), point).inv();
        expected.accumulate((try Source.opcodeActivity(family, row[0..width])).sub(main_values[binding.main_index][0]).mul(inverse));
        try std.testing.expectEqualDeep(expected.accumulation, actual.accumulation);
    };
    // Mixed-domain oracles exercise full polynomial recovery and shifted
    // interaction masks. Expected activity is evaluated from coefficients at
    // the actual extension domain, independent of the adapter row recovery.
    const fixed_polys = try polys(a, fixed, 7);
    const main_polys = try polys(a, main, 19);
    const witness_polys = try polys(a, witness, 31);
    const interaction_polys = try polys(a, interaction, 43);
    var four: [4][]const Poly = .{ fixed_polys, main_polys, witness_polys, interaction_polys };
    var three: [3][]const Poly = .{ fixed_polys, main_polys, interaction_polys };
    const trace = engine.air.component_prover.Trace{ .polys = .{ .items = if (slots.len == 0) &three else &four } };
    for (projections, 0..) |slot, index| {
        const old = try (OldAdapter.ProjectionComponent{ .has_access_witness = slots.len != 0, .inner = .{ .slot = slot, .fixed_logs = fixed, .main_logs = main, .root_owner = index == 0, .main_open_mask = open, .interaction_offset = 4 * index, .interaction_logs = interaction, .claim = value(index), .relations = &word.universal_prefix, .composition_split = split } }).init();
        const binding = try Source.binding(&source, 0, slot.main_offset, slot.log_size, slot.n_rows);
        const fresh = try (Adapter.ProjectionComponent{ .inner = old, .binding = binding }).init();
        try domainParity(a, &trace, old, fresh, binding, slot.main_offset, slot.width, slot, null);
    }
    for (slots, 0..) |slot, index| {
        const old = try (OldAdapter.AccessComponent{ .composition_split = split, .inner = .{ .family = slot.family, .slot = slot.slot, .log_size = slot.log_size, .base_clock = try Integer.baseClockFromPublicFrame(frame), .fixed_logs = fixed, .main_logs = main, .witness_logs = witness, .interaction_logs = interaction, .root_owner = false, .main_offset = slot.main_offset, .witness_offset = index * Integer.COLUMN_COUNT, .interaction_offset = 4 * projections.len + index * Eval.INTERACTION_COUNT, .transition_claim = value(index), .transition_count = 1, .range_claims = @splat(value(index + 17)), .challenges = &bus, .v5_packed = .{ .elements = &word }, .v5_universal = .{ .claim = value(index + 29), .elements = word.universal_prefix.get(.memory_access) }, .register_custody_mode = mode } }).init();
        const binding = try Source.binding(&source, 0, slot.main_offset, slot.log_size, null);
        const fresh = try (Adapter.AccessComponent{ .inner = old, .binding = binding }).init();
        try domainParity(a, &trace, old, fresh, binding, slot.main_offset, Opcode.nColumnsForFamily(slot.family), null, slot.family);
    }
}
fn domainParity(a: std.mem.Allocator, trace: *const engine.air.component_prover.Trace, old: anytype, fresh: anytype, binding: Source.Binding, offset: usize, width: usize, projection: ?Source.Slot, family: ?Opcode.OpcodeFamily) !void {
    const eval_log = binding.log_size + fresh.compositionLogSplit();
    var actual = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, value(71), eval_log, fresh.nConstraints());
    defer actual.deinit();
    var expected = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, value(71), eval_log, fresh.nConstraints());
    defer expected.deinit();
    try fresh.evaluateConstraintQuotientsOnDomain(trace, &actual);
    try old.evaluateConstraintQuotientsOnDomain(trace, &expected);
    const output = try expected.columns(a, &.{.{ .log_size = eval_log, .n_cols = 1 }});
    defer a.free(output);
    var result = output[0];
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    for (0..domain.size()) |physical| {
        const base = domain.at(core.utils.bitReverseIndex(physical, eval_log));
        const evaluation = Point{ .x = Q.fromBase(base.x), .y = Q.fromBase(base.y) };
        var row: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        for (row[0..width], trace.polys.items[1][offset..][0..width]) |*cell, poly| cell.* = poly.coefficients.?.evalAtPoint(evaluation);
        const selector = trace.polys.items[1][binding.main_index].coefficients.?.evalAtPoint(evaluation);
        const active = if (projection) |slot| try Source.activity(slot, row[0..width]) else try Source.opcodeActivity(family.?, row[0..width]);
        const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(binding.log_size).coset(), evaluation).inv();
        result.accumulate(physical, result.random_coeff_powers[result.random_coeff_powers.len - 1].mul(active.sub(selector)).mul(inverse));
    }
    try std.testing.expectEqual(@as(usize, 0), actual.next_power_index);
    try std.testing.expectEqual(@as(usize, 0), expected.next_power_index);
    for (actual.sub_accumulations, expected.sub_accumulations, 0..) |have, want, log| {
        try std.testing.expectEqual(want != null, have != null);
        if (want) |wanted| for (0..@as(usize, 1) << @intCast(log)) |physical|
            try std.testing.expectEqualDeep(wanted.at(physical), have.?.at(physical));
    }
}

test "capacity fused original projection and RW point domain equations retain every selector and shifted mask" {
    try parity(.base_alu_imm, 0);
    try parity(.base_alu_imm, 1);
    try parity(.load_store, 1);
}

test "capacity fused protocol frame mode count seal and access-root identities reject exact-row relabel" {
    const a = std.testing.allocator;
    var source = shape(.load_store);
    const projections = try Source.slotsFromShapeForMode(a, &source, 0, 1);
    defer a.free(projections);
    const slots = try Source.memorySlots(a, &source, 0, frame, 1);
    defer a.free(slots);
    const roots: Seal.Roots = .{ @splat(3), @splat(5) };
    const id = Proof.instanceId(@splat(7), @splat(11), roots, @splat(13), 0, frame, projections, slots);
    const old = @import("../block_v5_native_projection_fused_proof_v2.zig").instanceId(@splat(7), @splat(11), roots, @splat(13), 0, frame, projections, slots);
    try std.testing.expect(!std.meta.eql(id, old));
    try std.testing.expect(!std.meta.eql(id, Proof.instanceId(@splat(7), @splat(11), roots, @splat(17), 0, frame, projections, slots)));
    var different_frame = frame;
    different_frame.global_first_cycle += 1;
    try std.testing.expect(!std.meta.eql(id, Proof.instanceId(@splat(7), @splat(11), roots, @splat(13), 0, different_frame, projections, slots)));
    const saved = projections[0].n_rows;
    projections[0].n_rows = 2;
    try std.testing.expect(!std.meta.eql(id, Proof.instanceId(@splat(7), @splat(11), roots, @splat(13), 0, frame, projections, slots)));
    projections[0].n_rows = saved;
    var sealed = std.mem.zeroes(Seal.Sealed);
    sealed.digest = @splat(7);
    const channel = try Proof.proofChannel(a, sealed);
    sealed.digest[0] ^= 1;
    try std.testing.expect(!std.meta.eql(channel.digestBytes(), (try Proof.proofChannel(a, sealed)).digestBytes()));
    try Proof.requireProtocol(Proof.VERSION);
    try std.testing.expectError(error.UntrustedCapacityFusedProtocol, Proof.requireProtocol(2));
    try std.testing.expectError(error.UntrustedCapacityFusedProtocol, Proof.requireProtocol(0));
}

test "capacity fused genuine zero RW typed absence binds frame roots ordinals and rejects nonempty presence" {
    const a = std.testing.allocator;
    var source = shape(.base_alu_imm);
    // No clock rows: every ordinary access in this shape is a register.
    source.n_infra = 0;
    const execution = Seal.Entry{ .family = .execution, .index = 0, .roots = .{ @splat(3), @splat(5) }, .instance_id = @splat(7) };
    const absent = try Source.emptyEntry(a, &source, 0, frame, execution, 0, 1);
    try std.testing.expectEqualDeep(try Source.emptyWitnessRoot(1), absent.roots[0]);
    try std.testing.expect(!std.meta.eql(absent.roots[0], @import("../block_v5_empty_opcode_memory_v1.zig").witnessRootForMode(1)));
    try std.testing.expectError(error.InvalidCapacityFusedAbsence, Source.emptyEntry(a, &source, 0, frame, execution, 1, 1));
    try std.testing.expectError(error.NonemptyCapacityFusedAbsence, Source.emptyEntry(a, &source, 0, frame, execution, 0, 0));
    try Receiver.requireProofPresence(0, 0, false);
    try std.testing.expectError(error.UntrustedV5FullFusedTypedAbsence, Receiver.requireProofPresence(0, 0, true));
    try std.testing.expectError(error.UntrustedV5FullFusedTypedAbsence, Receiver.requireProofPresence(0, 1, false));
    try std.testing.expectError(error.MissingV5FullFusedProof, Receiver.requireProofPresence(1, 0, false));
    var changed = execution;
    changed.index += 1;
    try std.testing.expect(!std.meta.eql(absent, try Source.emptyEntry(a, &source, 0, frame, changed, 0, 1)));
    changed = execution;
    changed.roots[1][0] ^= 1;
    try std.testing.expect(!std.meta.eql(absent, try Source.emptyEntry(a, &source, 0, frame, changed, 0, 1)));
    // A caller-only segment has a genuine mandatory native frame AIR, but
    // no ordinary projection or access proof and no invented scalar receipt.
    source.n_components = 0;
    const empty_projections = try Source.slotsFromShapeForMode(a, &source, source.total_steps, 1);
    defer a.free(empty_projections);
    const empty_memory = try Source.memorySlots(a, &source, source.total_steps, frame, 1);
    defer a.free(empty_memory);
    try std.testing.expectEqual(@as(usize, 0), empty_projections.len);
    try std.testing.expectEqual(@as(usize, 0), empty_memory.len);
    const plan = try Protocol.Plan.fromShape(&source, source.total_steps);
    try std.testing.expectEqual(@as(usize, 4), plan.mainCount());
    _ = try Source.emptyEntry(a, &source, source.total_steps, frame, execution, 0, 1);
    try Receiver.requireProofPresence(empty_projections.len, empty_memory.len, false);
}

test "capacity fused selector links remain linear across every native recipe at arbitrary extension points" {
    // Independent affine checks exercise the authentic program-access
    // numerator (including local-zero envelopes), not a copied flag index.
    for (0..Opcode.N_FAMILIES) |ordinal| {
        const family: Opcode.OpcodeFamily = @enumFromInt(ordinal);
        for ([_]bool{ false, true }) |local_zero| {
            const count = if (local_zero) try @import("../../air/x0_native_envelope_v1.zig").mainColumnCount(family) else Opcode.nColumnsForFamily(family);
            var left: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            var right: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            var sum: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            var scaled: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            const zero: [Opcode.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
            const scale = value(901 + ordinal);
            for (0..count) |i| {
                left[i] = value(71 + i + ordinal);
                right[i] = value(177 + 3 * i + ordinal);
                sum[i] = left[i].add(right[i]);
                scaled[i] = left[i].mul(scale);
            }
            const base = try Source.opcodeActivity(family, zero[0..count]);
            const l = (try Source.opcodeActivity(family, left[0..count])).sub(base);
            const r = (try Source.opcodeActivity(family, right[0..count])).sub(base);
            try std.testing.expectEqualDeep(l.add(r), (try Source.opcodeActivity(family, sum[0..count])).sub(base));
            try std.testing.expectEqualDeep(l.mul(scale), (try Source.opcodeActivity(family, scaled[0..count])).sub(base));
        }
    }
}

fn allocationFailure(a: std.mem.Allocator) !void {
    var source = shape(.base_alu_imm);
    const projections = try Source.slotsFromShapeForMode(a, &source, 0, 1);
    defer a.free(projections);
    const slots = try Source.memorySlots(a, &source, 0, frame, 1);
    defer a.free(slots);
    const fixed = try Protocol.columnLogs(a, &source, 0, .fixed);
    defer a.free(fixed);
    const main = try Protocol.columnLogs(a, &source, 0, .main);
    defer a.free(main);
    const interactions = try Proof.interactionLogs(a, projections, slots);
    defer a.free(interactions);
    const mask = try Proof.mainMask(a, main.len, projections, slots, &source, 0);
    defer a.free(mask);
    var channel = core.proof_suites.Blake3.Channel{};
    const universal = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const slot = projections[0];
    const component = try (Adapter.ProjectionComponent{ .binding = try Source.binding(&source, 0, slot.main_offset, slot.log_size, slot.n_rows), .inner = .{ .has_access_witness = false, .inner = .{ .slot = slot, .fixed_logs = fixed, .main_logs = main, .root_owner = true, .main_open_mask = mask, .interaction_offset = 0, .interaction_logs = interactions, .claim = Q.zero(), .relations = &universal, .composition_split = Proof.compositionSplit(projections) } } }).init();
    var points_owned = try component.maskPoints(a, core.circle.secureFieldPoint(127), 2);
    defer points_owned.deinitDeep(a);
    var logs = try component.traceLogDegreeBounds(a);
    defer logs.deinitDeep(a);
}
test "capacity fused owned mask and source inventories survive every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{});
}

fn proveBody(a: std.mem.Allocator, first: *Proof.ForBackend(Cpu).FirstRound, inputs: []const Memory.Input, slots: []const Memory.Slot, projections: []const Source.Slot, native: *Native.ForBackend(Cpu).FirstRound, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) anyerror!Proof.Proof {
    return Proof.ForBackend(Cpu).proveForNativeFirstRound(a, first, inputs, slots, projections, sealed, pins, entries, catalog, native, native.index, frame, @splat(7), .{});
}
fn receiveBody(a: std.mem.Allocator, native: Native.Proof, proof: ?Proof.Proof, pin: Receiver.InstancePin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) anyerror!Receiver.Open {
    return Receiver.ForBackend(Cpu).verifyOwned(a, native, proof, 0, pin, .{ .frame = frame, .expected_events = 0, .witness_root = @splat(7) }, sealed, pins, entries, catalog);
}
fn stageBody(a: std.mem.Allocator, stage: *Stage.ForBackend(Cpu), native: *Native.ForBackend(Cpu).FirstRound, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) anyerror!void {
    return stage.produce(a, native, sealed, pins, entries, catalog);
}
test "capacity fused actual capacity warm producer fresh CPU receiver and stage bodies compile only" {
    inline for (.{ &proveBody, &receiveBody, &stageBody, &Stage.ForBackend(Cpu).collect, &Stage.Proposal.memoryEntry, &Stage.Proposal.projectionEntry }) |function| std.mem.doNotOptimizeAway(function);
    // These are distinct nominal receipts, not casts or NativeV3 aliases.
    comptime {
        if (Receiver.Open == @import("../block_v5_native_projection_fused_receiver_v2.zig").Open) @compileError("capacity receiver relabeled native v3");
        if (Proof.ProjectionReceipt == @import("../block_v5_native_projection_fused_proof_v1.zig").VerifiedReceipt) @compileError("capacity projections relabeled legacy receipt");
    }
}
