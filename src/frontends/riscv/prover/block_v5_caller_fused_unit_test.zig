//! Nonproving caller fusion parity. No guest/segment execution, commitments,
//! STARK/FRI jobs or benchmarks are performed by these tests.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Receiver = @import("block_v5_caller_fused_receiver_v1.zig");
const Adapters = @import("block_v5_caller_fused_component_v1.zig");
const Program = @import("block_v5_program_extension_component_v1.zig").Component;
const Tables = @import("block_v5_precompile_lookup_component_v1.zig").Component;
const Memory = @import("block_execution_sidecar_stark_v2.zig").Component;
const Frame = @import("../air/block/memory_event.zig").Frame;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const PointAccumulator = core.air.accumulation.PointEvaluationAccumulator;
const DomainAccumulator = engine.air.accumulation.DomainEvaluationAccumulator;
fn value(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(3 + seed * 7), @intCast(5 + seed * 11), @intCast(7 + seed * 13), @intCast(11 + seed * 17));
}
fn statement(a: std.mem.Allocator) !Profile.admission.Statement {
    const Geometry = @import("../air/guest_precompile/ethereum_statement.zig");
    var shapes: Geometry.SecpShapes = undefined;
    inline for (@typeInfo(Geometry.SecpShapes).@"struct".fields) |field| @field(shapes, field.name) = .{ .log_size = 1, .n_rows = 1 };
    shapes.byte = .{ .log_size = 8, .n_rows = 256 };
    return @import("block_v5_precompile_witness_v1.zig").canonicalStatement(a, 1, 1, 2, shapes);
}
fn points(a: std.mem.Allocator, count: usize, samples: usize, seed: usize) ![][]Q {
    const out = try a.alloc([]Q, count);
    for (out, 0..) |*column, i| {
        column.* = try a.alloc(Q, samples);
        for (column.*, 0..) |*v, j| v.* = value(seed + i + j * 137);
    }
    return out;
}
fn polynomials(a: std.mem.Allocator, count: usize, seed: usize) ![]engine.air.component_prover.Poly {
    const out = try a.alloc(engine.air.component_prover.Poly, count);
    for (out, 0..) |*poly, i| {
        const coefficients = try a.dupe(M, &.{ M.fromCanonical(@intCast(7 + seed + i)), M.fromCanonical(@intCast(11 + 3 * i)) });
        poly.* = .{ .log_size = 1, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(coefficients) };
    }
    return out;
}
fn domainParity(a: std.mem.Allocator, fused: anytype, original: anytype, full: *const engine.air.component_prover.Trace, separate: *const engine.air.component_prover.Trace, eval_log: u32) !void {
    var actual = try DomainAccumulator.init(a, value(9), eval_log, fused.nConstraints());
    defer actual.deinit();
    var expected = try DomainAccumulator.init(a, value(9), eval_log, original.nConstraints());
    defer expected.deinit();
    try fused.evaluateConstraintQuotientsOnDomain(full, &actual);
    try original.evaluateConstraintQuotientsOnDomain(separate, &expected);
    for (0..(@as(usize, 1) << @intCast(eval_log))) |row| try std.testing.expectEqualDeep(expected.sub_accumulations[eval_log].?.at(row), actual.sub_accumulations[eval_log].?.at(row));
}
fn check(mode: u32) !void {
    const owner = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(owner);
    defer arena.deinit();
    const a = arena.allocator();
    const pinned = try statement(a);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 37, .cycle_count = 4 };
    var schedule = try Schedule.init(a, &pinned, 4, frame, mode);
    defer schedule.deinit();
    // Canonical offsets/kinds/entry filters are retained. Set polynomial log1
    // only for bounded equation parity, never for a statement/proof admission.
    const fixed = try a.alloc(u32, schedule.fixed.len);
    @memset(fixed, 1);
    const main = try a.alloc(u32, schedule.main.len);
    @memset(main, 1);
    const witness = try a.alloc(u32, schedule.memory.len * Integer.COLUMN_COUNT);
    @memset(witness, 1);
    const logs = try schedule.interactionLogs();
    @memset(logs, 1);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 37, mode });
    var word_channel = channel;
    var bus_channel = channel;
    const vm = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relations = try Profile.Relations.drawAfterVm(a, &channel, vm);
    const word_challenges = try Word.Challenges.drawFromChannel(a, &word_channel);
    const bus = try Bus.Challenges.drawFromChannel(a, &bus_channel);
    const fixed_values = try points(a, fixed.len, 1, 10);
    const main_values = try points(a, main.len, 2, 100);
    const witness_values = try points(a, witness.len, 1, 300);
    const interaction_values = try points(a, logs.len, 2, 500);
    var full_items: [4][][]Q = .{ fixed_values, main_values, witness_values, interaction_values };
    var old_items: [3][][]Q = .{ fixed_values, main_values, interaction_values };
    const mask = core.air.components.MaskValues{ .items = &full_items };
    const old_mask = core.air.components.MaskValues{ .items = &old_items };
    const fixed_polys = try polynomials(a, fixed.len, 10);
    const main_polys = try polynomials(a, main.len, 100);
    const witness_polys = try polynomials(a, witness.len, 300);
    const interaction_polys = try polynomials(a, logs.len, 500);
    var full_trees: [4][]const engine.air.component_prover.Poly = .{ fixed_polys, main_polys, witness_polys, interaction_polys };
    var old_trees: [3][]const engine.air.component_prover.Poly = .{ fixed_polys, main_polys, interaction_polys };
    const full = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&full_trees) };
    const old = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&old_trees) };
    const point = core.circle.secureFieldPoint(127);
    var actual_composite = PointAccumulator.init(value(9));
    var expected_composite = PointAccumulator.init(value(9));
    for (schedule.program, 0..) |canonical, i| inline for (.{ .program, .state }, 0..) |projection, part| {
        var slot = canonical;
        slot.log_size = 1;
        slot.active_calls = 1;
        const original = try (Program{ .projection = projection, .slot = slot, .fixed_logs = fixed, .main_logs = main, .root_owner = false, .interaction_offset = (part * schedule.program.len + i) * 4, .interaction_logs = logs, .claim = value(i), .relations = &relations.sha }).init();
        const fused = try (Adapters.Program{ .inner = original, .composition_split = schedule.split }).init();
        var bounds = try fused.traceLogDegreeBounds(owner);
        defer bounds.deinitDeep(owner);
        var samples = try fused.maskPoints(owner, point, 1);
        defer samples.deinitDeep(owner);
        try std.testing.expectEqual(@as(usize, 4), samples.items.len);
        try std.testing.expectEqual(@as(usize, 0), samples.items[2].len);
        try std.testing.expectEqual(@as(usize, 0), bounds.items[2].len);
        for (samples.items[3]) |cells| {
            try std.testing.expectEqual(@as(usize, 2), cells.len);
            try std.testing.expect(cells[1].eql(@import("../air/logup.zig").prevRowPoint(1, point)));
        }
        try fused.evaluateConstraintQuotientsAtPoint(point, &mask, &actual_composite, 1);
        try original.evaluateConstraintQuotientsAtPoint(point, &old_mask, &expected_composite, 1);
        try domainParity(owner, &fused, &original, &full, &old, 3);
        const offset = original.interaction_offset;
        const saved = interaction_values[offset];
        interaction_values[offset] = saved[0..1];
        var unused = PointAccumulator.init(value(9));
        if (fused.evaluateConstraintQuotientsAtPoint(point, &mask, &unused, 1)) |_| return error.AcceptedMissingCallerPreviousPoint else |_| {}
        interaction_values[offset] = saved;
    };
    for (schedule.tables, 0..) |canonical, i| {
        var slot = canonical;
        slot.log_size = 1;
        slot.n_rows = 1;
        const original = try (Tables{ .slot = slot, .fixed_logs = fixed, .main_logs = main, .root_owner = false, .interaction_offset = (schedule.program.len * 2 + i) * 4, .interaction_logs = logs, .claim = value(i), .relations = &relations, .source_owner = schedule.owner, .composition_split = schedule.split }).init();
        const fused = try (Adapters.Tables{ .inner = original, .composition_split = schedule.split }).init();
        try fused.evaluateConstraintQuotientsAtPoint(point, &mask, &actual_composite, 1);
        try original.evaluateConstraintQuotientsAtPoint(point, &old_mask, &expected_composite, 1);
        try domainParity(owner, &fused, &original, &full, &old, 1 + schedule.split);
    }
    for (schedule.memory, 0..) |canonical, i| {
        var slot = canonical;
        slot.log_size = 1;
        const original = try (Memory{ .register_custody_mode = mode, .family = .base_alu_imm, .slot = slot.slot, .external_source = slot, .log_size = 1, .base_clock = try Integer.baseClockFromPublicFrame(frame), .fixed_logs = fixed, .main_logs = main, .witness_logs = witness, .interaction_logs = logs, .root_owner = i == 0, .fixed_open_mask = schedule.masks.fixed, .main_open_mask = schedule.masks.main, .shared_keccak_state_offset = schedule.masks.state_offset, .main_offset = slot.main_offset, .witness_offset = i * Integer.COLUMN_COUNT, .interaction_offset = schedule.projectionCount() * 4 + i * Eval.INTERACTION_COUNT, .transition_claim = value(i), .transition_count = 1, .range_claims = @splat(value(i + 3)), .challenges = &bus, .v5_packed = .{ .elements = &word_challenges }, .v5_universal = .{ .claim = value(i + 2), .elements = vm.get(.memory_access) } }).init();
        const fused = try (Adapters.Memory{ .inner = original, .composition_split = schedule.split }).init();
        var samples = try fused.maskPoints(owner, point, 1);
        defer samples.deinitDeep(owner);
        try std.testing.expectEqual(@as(usize, 4), samples.items.len);
        for (samples.items[2]) |cells| try std.testing.expectEqual(@as(usize, 1), cells.len);
        for (samples.items[3]) |cells| try std.testing.expectEqual(@as(usize, 2), cells.len);
        if (i == 0) {
            for (samples.items[0], schedule.masks.fixed) |cells, open| try std.testing.expectEqual(@as(usize, if (open) 1 else 0), cells.len);
            for (samples.items[1], schedule.masks.main, 0..) |cells, open, column| {
                const shifted = if (schedule.masks.state_offset) |offset| column >= offset and column < offset + @import("../air/guest_precompile/keccakf_witness.zig").state_cell_count else false;
                try std.testing.expectEqual(@as(usize, if (shifted) 2 else if (open) 1 else 0), cells.len);
            }
        }
        try fused.evaluateConstraintQuotientsAtPoint(point, &mask, &actual_composite, 1);
        try original.evaluateConstraintQuotientsAtPoint(point, &mask, &expected_composite, 1);
        try domainParity(owner, &fused, &original, &full, &full, 3);
        const offset = i * Integer.COLUMN_COUNT;
        const saved = witness_values[offset];
        witness_values[offset] = saved[0..0];
        var unused = PointAccumulator.init(value(9));
        if (fused.evaluateConstraintQuotientsAtPoint(point, &mask, &unused, 1)) |_| return error.AcceptedMissingCallerWitnessPoint else |_| {}
        witness_values[offset] = saved;
    }
    try std.testing.expectEqualDeep(expected_composite.finalize(), actual_composite.finalize());
}
test "block-v5 caller fused nonproving exact schedules masks OODS and domains match separate families" {
    for ([_]u32{ 0, 1 }) |mode| try check(mode);
}
test "block-v5 caller fused nonproving identity binds both schedules roots frame mode and rejects old program" {
    const a = std.testing.allocator;
    const pinned = try statement(a);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 37, .cycle_count = 4 };
    var schedule = try Schedule.init(a, &pinned, 4, frame, 1);
    defer schedule.deinit();
    const binding = Protocol.CallerBinding{ .execution_index = 2, .caller_entry_index = 2, .execution_instance_id = @splat(1), .caller_instance_id = @splat(2), .caller_key_id = @splat(3), .first_roots = .{ @splat(4), @splat(5) }, .sealed_digest = @splat(6) };
    const id = Fused.instanceId(binding, @splat(7), frame, 1, &schedule);
    const old = @import("block_v5_program_extension_proof_v1.zig").instanceId(binding.caller_instance_id, binding.execution_instance_id, binding.execution_index, schedule.program);
    try std.testing.expect(!std.meta.eql(id, old));
    var changed = binding;
    changed.caller_key_id[0] ^= 1;
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(changed, @splat(7), frame, 1, &schedule)));
    changed = binding;
    changed.first_roots[1][0] ^= 1;
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(changed, @splat(7), frame, 1, &schedule)));
    changed = binding;
    changed.execution_instance_id[0] ^= 1;
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(changed, @splat(7), frame, 1, &schedule)));
    var changed_frame = frame;
    changed_frame.global_first_cycle += 1;
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(binding, @splat(7), changed_frame, 1, &schedule)));
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(binding, @splat(8), frame, 1, &schedule)));
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(binding, @splat(7), frame, 0, &schedule)));
    const saved = schedule.tables[0];
    schedule.tables[0].entries[0] += 1;
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(binding, @splat(7), frame, 1, &schedule)));
    schedule.tables[0] = saved;
    const memory_saved = schedule.memory[0];
    schedule.memory[0].slot += 1;
    try std.testing.expect(!std.meta.eql(id, Fused.instanceId(binding, @splat(7), frame, 1, &schedule)));
    schedule.memory[0] = memory_saved;
}
test "block-v5 caller fused nonproving claim census and sparse absence reject missing swapped obligations" {
    const a = std.testing.allocator;
    const pinned = try statement(a);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 4 };
    var schedule = try Schedule.init(a, &pinned, 4, frame, 1);
    defer schedule.deinit();
    const binding = std.mem.zeroes(Protocol.CallerBinding);
    const program = try a.alloc(@import("block_v5_program_extension_proof_v1.zig").Claim, schedule.program.len);
    defer a.free(program);
    for (program, schedule.program) |*claim, slot| claim.* = .{ .sum = Q.zero(), .fetch_count = slot.active_calls };
    const state = try a.dupe(@import("block_v5_program_extension_proof_v1.zig").Claim, program);
    defer a.free(state);
    const tables = try a.alloc(@import("block_v5_precompile_lookup_algebra_v1.zig").Claim, schedule.tables.len);
    defer a.free(tables);
    for (tables, schedule.tables) |*claim, slot| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
    const memory = try a.alloc(@import("block_v5_external_memory_sidecar_proof_v1.zig").Claim, schedule.memory.len);
    defer a.free(memory);
    for (memory) |*claim| claim.* = .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .range_claims = @splat(Q.zero()), .active_count = 0 };
    memory[0].active_count = 1;
    var channel = core.proof_suites.Blake3.Channel{};
    try std.testing.expectError(error.UntrustedV5CallerCompositeEventCensus, Fused.mixClaims(&channel, binding, &schedule, program, state, tables, memory));
    state[0].fetch_count += 1;
    try std.testing.expectError(error.InvalidV5CallerCompositeClaims, Fused.mixClaims(&channel, binding, &schedule, program, state, tables, memory));
    state[0].fetch_count -= 1;
    try std.testing.expectError(error.InvalidV5CallerCompositeClaims, Fused.mixClaims(&channel, binding, &schedule, program[0..0], state, tables, memory));
    tables[0].row_count += 1;
    try std.testing.expectError(error.InvalidV5CallerCompositeClaims, Fused.mixClaims(&channel, binding, &schedule, program, state, tables, memory));
    tables[0].row_count -= 1;
    for (schedule.memory, memory) |slot, *claim| claim.active_count = if (slot.kind == .sha) 2 else 1;
    var admitted_channel = core.proof_suites.Blake3.Channel{};
    try Fused.mixClaims(&admitted_channel, binding, &schedule, program, state, tables, memory);
    const admitted_digest = admitted_channel.digestBytes();
    program[0].sum = Q.one();
    var mutated_channel = core.proof_suites.Blake3.Channel{};
    try Fused.mixClaims(&mutated_channel, binding, &schedule, program, state, tables, memory);
    try std.testing.expect(!std.meta.eql(admitted_digest, mutated_channel.digestBytes()));
    const Seal = @import("block_v5_source_seal_v1.zig");
    var sealed = std.mem.zeroes(Seal.Sealed);
    sealed.execution_instance_count = 1;
    const execution = Seal.Entry{ .family = .execution, .index = 0, .instance_id = @splat(1), .roots = .{ @splat(2), @splat(3) } };
    try Receiver.requireAbsence(0, sealed, &.{execution});
    try std.testing.expectError(error.MissingV5CallerCompositePin, Receiver.requireAbsence(0, sealed, &.{ execution, .{ .family = .precompile, .index = 0, .instance_id = @splat(4), .roots = .{ @splat(5), @splat(6) } } }));
    try std.testing.expectError(error.UntrustedV5CallerCompositeAbsentIndex, Receiver.requireAbsence(1, sealed, &.{execution}));
}
test "block-v5 caller fused nonproving warm producer and fresh receiver bodies compile" {
    const ProofApi = Fused.ForBackend(Cpu);
    const Fresh = Receiver.ForBackend(Cpu);
    const Warm = @import("block_v5_caller_fused_stage_v1.zig").ForBackend(Cpu);
    const prove: *const @TypeOf(ProofApi.proveForCallerFirstRound) = &ProofApi.proveForCallerFirstRound;
    const fresh: *const @TypeOf(Fresh.verifyOwned) = &Fresh.verifyOwned;
    const absent: *const @TypeOf(Fresh.verifyOptionalOwned) = &Fresh.verifyOptionalOwned;
    const stage: *const @TypeOf(Warm.proveWarm) = &Warm.proveWarm;
    const prepared: *const @TypeOf(Warm.provePreparedWarm) = &Warm.provePreparedWarm;
    const bound: *const @TypeOf(@import("block_v5_caller_fused_stage_v1.zig").lateBind) = &@import("block_v5_caller_fused_stage_v1.zig").lateBind;
    std.mem.doNotOptimizeAway(prove);
    std.mem.doNotOptimizeAway(fresh);
    std.mem.doNotOptimizeAway(absent);
    std.mem.doNotOptimizeAway(stage);
    std.mem.doNotOptimizeAway(prepared);
    std.mem.doNotOptimizeAway(bound);
}

test "block-v5 caller fused nonproving independent seal admission rejects swapped old and missing roots" {
    const a = std.testing.allocator;
    const Seal = @import("block_v5_source_seal_v1.zig");
    const pinned = try statement(a);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 19, .cycle_count = 4 };
    var schedule = try Schedule.init(a, &pinned, 4, frame, 0);
    defer schedule.deinit();
    const config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    const roots: Seal.Roots = .{ @splat(3), @splat(4) };
    const key = try Protocol.keyId(&pinned, 4, config, roots[0]);
    const caller = Protocol.instanceId(key, @splat(2), 0, roots);
    var binding = Protocol.CallerBinding{ .execution_index = 0, .caller_entry_index = 0, .execution_instance_id = @splat(2), .caller_instance_id = caller, .caller_key_id = key, .first_roots = roots, .sealed_digest = @splat(0) };
    var counts: [Seal.family_count]u32 = @splat(0);
    inline for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .precompile, .program_extension_request, .execution_external_sidecar }) |family| counts[@intFromEnum(family) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(9), .native_template_id = @splat(10), .program_root = @splat(11), .program_plan_digest = @splat(12), .memory_plan_digest = @splat(13), .initial_source_plan_digest = @splat(14), .config = config, .counts = counts };
    var entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(15), .roots = .{ @splat(16), @splat(17) } },
        .{ .family = .execution, .index = 0, .instance_id = binding.execution_instance_id, .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(23), .roots = .{ @splat(24), @splat(25) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        .{ .family = .precompile, .index = 0, .instance_id = caller, .roots = roots },
        Fused.entry(binding, @splat(5), frame, 0, &schedule),
        @import("block_v5_external_memory_sidecar_proof_v1.zig").packedEntry(binding.execution_instance_id, caller, key, roots, @splat(5), 0, schedule.memory),
    };
    const sealed = try Seal.seal(pins, &entries);
    binding.sealed_digest = sealed.digest;
    try Fused.admit(binding, @splat(5), frame, &schedule, sealed, pins, &entries);
    const saved = entries[6];
    entries[6].instance_id = @import("block_v5_program_extension_proof_v1.zig").instanceId(caller, binding.execution_instance_id, 0, schedule.program);
    const old_seal = try Seal.seal(pins, &entries);
    binding.sealed_digest = old_seal.digest;
    try std.testing.expectError(error.UntrustedV5CallerCompositeEntry, Fused.admit(binding, @splat(5), frame, &schedule, old_seal, pins, &entries));
    entries[6] = saved;
    entries[7].roots[0][0] ^= 1;
    const swapped = try Seal.seal(pins, &entries);
    binding.sealed_digest = swapped.digest;
    try std.testing.expectError(error.UntrustedV5CallerCompositeAccess, Fused.admit(binding, @splat(5), frame, &schedule, swapped, pins, &entries));
    // Changed metadata cannot reuse the old source-seal digest either.
    binding.sealed_digest = sealed.digest;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, Fused.admit(binding, @splat(5), frame, &schedule, sealed, pins, &entries));
    try std.testing.expectError(error.InvalidBlockV5FirstRoundCensus, Seal.seal(pins, entries[0 .. entries.len - 1]));
}
