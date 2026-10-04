//! Bounded equation/admission/mask/codegen fixtures only. No STARK, guest,
//! segments, device work or benchmarks. Candidate source cells are not receipts.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Air = @import("../block_v5_caller_readonly_component_v1.zig");
const Protocol = @import("../block_v5_caller_readonly_protocol_v1.zig");
const Proof = @import("../block_v5_caller_readonly_proof_v1.zig");
const Plan = @import("../block_v5_readonly_input_plan_v1.zig");
const Selection = @import("../block_v5_readonly_input_selection_v1.zig");
const Sources = @import("../block_v5_initial_sources_v1.zig");
const Witness = @import("../block_v5_caller_readonly_witness_v1.zig");
const Source = @import("../block_execution_external_trace_v2.zig");
const Integer = @import("../block_execution_integer_bridge_v2.zig");
const Profile = @import("../blake3_ethereum_sha_profile.zig");
const Frame = @import("../../air/block/memory_event.zig").Frame;
const Schedule = @import("../block_v5_caller_fused_schedule_v1.zig").Schedule;
const sha = @import("../../air/guest_precompile/sha256_memory_caller.zig");
fn scalar(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
fn exactChallenges() Protocol.Challenges {
    const E = @import("../../air/relation_challenges.zig").RelationElements;
    var result: Protocol.Challenges = undefined;
    result.word.transition = E(11).init(Q.fromU32Unchecked(11, 7, 13, 17), Q.fromU32Unchecked(19, 23, 29, 31));
    result.classification = E(5).init(Q.fromU32Unchecked(9, 2, 3, 7), Q.fromU32Unchecked(3, 4, 5, 6));
    result.read = E(4).init(Q.fromU32Unchecked(8, 5, 7, 3), Q.fromU32Unchecked(7, 4, 8, 6));
    return result;
}
const base: u32 = 0x900000;
const input = [_]u8{ 7, 0, 0, 0, 9, 8, 7 };
const addresses = [_]u32{ base, base + 8 };
fn sources() !Sources.Pins {
    const Tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
    const leaves = [_]Tree.Leaf{ .{ .index = base / 4, .value = 7 }, .{ .index = base / 4 + 1, .value = 0x070809 } };
    var words: [16]u8 = undefined;
    inline for (0..2) |i| {
        std.mem.writeInt(u32, words[i * 8 ..][0..4], base + i * 4, .little);
        std.mem.writeInt(u32, words[i * 8 + 4 ..][0..4], leaves[i].value, .little);
    }
    // Final source file describes only the candidate mutable first touch.
    // Full initial input roster/root still include every original word.
    var touch: [9]u8 = undefined;
    touch[0] = 1;
    std.mem.writeInt(u32, touch[1..5], base + 4, .little);
    std.mem.writeInt(u32, touch[5..9], 0x070809, .little);
    return .{ .layout = .{ .program_base = 0x1000, .program_end = 0x2000, .data_base = base, .data_end = base + 4096, .stack_bottom = 0, .stack_top = 0, .io_base = 0, .io_end = 0, .input_base = base, .input_end = base + 16, .output_len_addr = base + 32, .output_data_addr = base + 36, .output_base = base + 32, .output_end = base + 128 }, .initial_rw_root = (try Tree.TreeHasher.init(.memory).root(&leaves)).bytes, .initial_registers = @splat(0), .public_input_sha256 = Sources.sha256(&input), .public_input_len = input.len, .input_words = .{ .sha256 = Sources.sha256(&words), .records = 2 }, .rw_words = .{ .sha256 = Sources.sha256(&.{}), .records = 0 }, .first_touches = .{ .sha256 = Sources.sha256(&touch), .records = 1 } };
}
fn statement(a: std.mem.Allocator) !Profile.admission.Statement {
    const Geometry = @import("../../air/guest_precompile/ethereum_statement.zig");
    var shapes: Geometry.SecpShapes = undefined;
    inline for (@typeInfo(Geometry.SecpShapes).@"struct".fields) |field| @field(shapes, field.name) = .{ .log_size = 1, .n_rows = 1 };
    shapes.byte = .{ .log_size = 8, .n_rows = 256 };
    return @import("../block_v5_precompile_witness_v1.zig").canonicalStatement(a, 1, 1, 2, shapes);
}

fn authority(selection: *const Selection.Owned, plan: Plan.Owned, source: Sources.Pins, subset: []const u32) Protocol.Authority {
    return .{ .selection = .{ .authority = selection.authority, .addresses = subset, .expected_digest = selection.digest }, .plan = .{ .source = source, .addresses = subset, .expected_digest = plan.digest }, .input = &input };
}
fn allZero(equations: anytype) bool {
    for (equations) |equation| if (!equation.isZero()) return false;
    return true;
}
fn trace(a: std.mem.Allocator, after: u32) !Source.Trace {
    const fixed = try a.alloc(Column, 1);
    fixed[0] = .{ .values = try a.dupe(M, &.{ M.one(), M.zero() }), .log_size = 1 };
    const main = try a.alloc(Column, sha.PHYSICAL_MAIN_COLUMN_COUNT);
    const matrix = try a.alloc(M, 2 * main.len);
    @memset(matrix, M.zero());
    for (main, 0..) |*column, i| column.* = .{ .values = matrix[2 * i ..][0..2], .log_size = 1 };
    // Arena-owned candidate caller cells; parsing uses the genuine SHA ABI.
    matrix[2 * sha.Layout.addresses] = M.fromCanonical(base / 4);
    matrix[2 * sha.Layout.memory_clock] = M.fromCanonical(2);
    matrix[2 * sha.Layout.before] = M.fromCanonical(7);
    for (0..4) |i| matrix[2 * (sha.Layout.output + i)] = M.fromCanonical((after >> @intCast(i * 8)) & 255);
    return Source.Trace.init(a, .{ .kind = .sha, .slot = 2, .log_size = 1, .fixed_offset = 0, .main_offset = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = (@as(u64, 1) << 40) + 1, .cycle_count = 1 } }, fixed, main);
}
test "block-v5 caller readonly authentic SHA cells reuse global clock and reject selected writes" {
    const owner = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(owner);
    defer arena.deinit();
    const a = arena.allocator();
    const pins = try sources();
    var plan = try Plan.derive(a, pins, &input, &.{base}, .{});
    defer plan.deinit();
    var source = try trace(a, 7);
    defer source.deinit();
    var metadata = try Witness.Metadata.init(owner, &source, plan, .{});
    defer metadata.deinit(owner);
    const challenges = exactChallenges();
    var interaction = try Witness.generate(owner, &source, &metadata, plan, &challenges, .{});
    defer interaction.deinit(owner);
    try std.testing.expectEqual(@as(u64, 1), metadata.events);
    try std.testing.expectEqual(@as(u64, 1), interaction.claim.readonly_count);
    try std.testing.expect(interaction.claim.mutable_sum.isZero());
    var shifts: [4]Q = undefined;
    for ([_]Q{ interaction.claim.mutable_sum, interaction.claim.classification_sum, interaction.claim.read_sum, scalar(1) }, &shifts) |sum, *out| out.* = try sum.divM31(M.fromCanonical(2));
    for (0..2) |logical| {
        const physical = @import("../../recursion/air/framework_interaction.zig").committedRow(logical, 1);
        const prev = @import("../../recursion/air/framework_interaction.zig").committedRow((logical + 1) % 2, 1);
        const pair = try source.pairAt(logical);
        const witness = (try source.witnessAt(logical)).columns();
        var row: Air.Metadata = undefined;
        for (&row, metadata.columns) |*v, column| v.* = Q.fromBase(column.values[physical]);
        var current: [Air.INTER_COUNT]Q = undefined;
        var prior: [Air.INTER_COUNT]Q = undefined;
        for (&current, &prior, interaction.columns) |*v, *w, column| {
            v.* = Q.fromBase(column[physical]);
            w.* = Q.fromBase(column[prev]);
        }
        try std.testing.expect(allZero(Air.equations(pair, witness, row, current, prior, shifts, &challenges)));
        const tuple = Air.sourceTuple(pair, witness);
        if (logical == 0) try std.testing.expectEqualDeep(@import("../block_v5_word_memory_protocol_v1.zig").fromByteTransition(Q, Integer.transitionAtPoint(pair, Integer.Witness.fromColumns(witness))), tuple);
        if (logical == 0) {
            try std.testing.expect(!tuple[5].isZero() or !tuple[6].isZero());
            var changed = pair;
            changed.after[0] = changed.after[0].add(Q.one());
            try std.testing.expect(!allZero(Air.equations(changed, witness, row, current, prior, shifts, &challenges)));
            var wrong = row;
            wrong[2] = Q.zero();
            try std.testing.expect(!allZero(Air.equations(pair, witness, wrong, current, prior, shifts, &challenges)));
            wrong = row;
            wrong[5] = Q.one().sub(wrong[5]);
            try std.testing.expect(!allZero(Air.equations(pair, witness, wrong, current, prior, shifts, &challenges)));
            var bad_clock = witness;
            bad_clock[12] = bad_clock[12].add(Q.one());
            // All-readonly mutable claim has no transition; source byte/universal
            // constraints remain required and independently catch clock forgery.
            const source_equations = Integer.constraints(pair, Integer.Witness.fromColumns(bad_clock), source.base_clock);
            try std.testing.expect(!source_equations.allZero());
        }
    }
    var bad = try trace(a, 8);
    defer bad.deinit();
    try std.testing.expectError(error.InvalidReadonlyInputClassification, Witness.Metadata.init(owner, &bad, plan, .{}));
    var count = try owner.dupe(u64, metadata.counters);
    defer owner.free(count);
    count[try plan.find(base)] += 1;
    try std.testing.expectError(error.InvalidCallerReadonlyProviderCensus, Protocol.checkProviders(plan, 1, interaction.claim, count, &challenges, .{}));
    var malformed = interaction.claim;
    malformed.mutable_sum.c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidCallerReadonlyClaim, Protocol.checkProviders(plan, 1, malformed, metadata.counters, &challenges, .{}));
}
test "block-v5 caller readonly empty subset mutable fallback and independent authority mutations" {
    const a = std.testing.allocator;
    const pins = try sources();
    var selection = try Selection.derive(a, try Selection.Authority.fromSources(pins), &input, &.{}, .{});
    defer selection.deinit();
    var plan = try Plan.derive(a, pins, &input, &.{}, .{});
    defer plan.deinit();
    const admitted = authority(&selection, plan, pins, &.{});
    var joined = try admitted.admit(a);
    defer joined.deinit();
    try std.testing.expectEqual(@as(usize, 1), joined.intervals.len);
    try std.testing.expect(!joined.intervals[0].readonly);
    var changed = admitted;
    changed.selection.expected_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedReadonlyInputSelection, changed.admit(a));
    changed = admitted;
    changed.plan.expected_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedReadonlyInputPlan, changed.admit(a));
    changed = admitted;
    changed.plan.source.initial_rw_root[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputSourceAuthority, changed.admit(a));
    changed = admitted;
    changed.plan.addresses = &.{base};
    try std.testing.expectError(error.UntrustedReadonlyInputPlan, changed.admit(a));
    var bytes = input;
    bytes[0] ^= 1;
    changed = admitted;
    changed.input = &bytes;
    try std.testing.expectError(error.UntrustedReadonlyInputBytes, changed.admit(a));
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var candidate = try trace(arena.allocator(), 8);
    defer candidate.deinit();
    var metadata = try Witness.Metadata.init(a, &candidate, plan, .{});
    defer metadata.deinit(a);
    const challenges = exactChallenges();
    var generated = try Witness.generate(a, &candidate, &metadata, plan, &challenges, .{});
    defer generated.deinit(a);
    try std.testing.expectEqual(@as(u64, 0), generated.claim.readonly_count);
    try std.testing.expect(!generated.claim.mutable_sum.isZero());
    try std.testing.expectError(error.CallerReadonlyResourceLimit, Witness.Metadata.init(a, &candidate, plan, .{ .max_metadata_bytes = 1 }));
}
test "block-v5 caller readonly versioned source identity and five-array caps reject legacy relabel" {
    const a = std.testing.allocator;
    const pins = try sources();
    var selection = try Selection.derive(a, try Selection.Authority.fromSources(pins), &input, &addresses, .{});
    defer selection.deinit();
    var plan = try Plan.derive(a, pins, &input, &addresses, .{});
    defer plan.deinit();
    const policy = authority(&selection, plan, pins, &addresses);
    const admitted = try statement(a);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 4 };
    var schedule = try Schedule.init(a, &admitted, 4, frame, 1);
    defer schedule.deinit();
    const binding = @import("../block_v5_precompile_protocol_v1.zig").CallerBinding{ .execution_index = 0, .caller_entry_index = 0, .execution_instance_id = @splat(1), .caller_instance_id = @splat(2), .caller_key_id = @splat(3), .first_roots = .{ @splat(4), @splat(5) }, .sealed_digest = @splat(6) };
    const id = Proof.instanceId(binding, @splat(7), frame, 1, &schedule, policy);
    try std.testing.expect(!std.meta.eql(id, @import("../block_v5_caller_fused_proof_v1.zig").instanceId(binding, @splat(7), frame, 1, &schedule)));
    const access = Proof.accessEntry(binding, @splat(7), frame, &schedule, policy);
    try std.testing.expect(!std.meta.eql(access, @import("../block_v5_external_memory_sidecar_proof_v1.zig").packedEntry(binding.execution_instance_id, binding.caller_instance_id, binding.caller_key_id, binding.first_roots, @splat(7), 0, schedule.memory)));
    var changed = policy;
    changed.selection.expected_digest[0] ^= 1;
    try std.testing.expect(!std.meta.eql(id, Proof.instanceId(binding, @splat(7), frame, 1, &schedule, changed)));
    changed = policy;
    changed.plan.expected_digest[0] ^= 1;
    try std.testing.expect(!std.meta.eql(id, Proof.instanceId(binding, @splat(7), frame, 1, &schedule, changed)));
    changed = policy;
    changed.limits.max_counter_bytes -= 1;
    try std.testing.expect(!std.meta.eql(id, Proof.instanceId(binding, @splat(7), frame, 1, &schedule, changed)));
    const counts = [_]usize{ schedule.program.len, schedule.program.len, schedule.tables.len, schedule.memory.len, schedule.memory.len };
    for (0..5) |i| {
        var bad = counts;
        bad[i] += 1;
        try std.testing.expectError(error.InvalidCallerReadonlyClaims, Proof.preflightCounts(&schedule, plan.intervals.len, bad, policy.limits));
    }
    try std.testing.expectError(error.CallerReadonlyResourceLimit, Proof.preflightCounts(&schedule, plan.intervals.len, counts, .{ .max_counter_bytes = 1 }));
}
test "block-v5 caller readonly actual producer fresh receiver and warm ownership bodies retained" {
    const Producer = Proof.ForBackend(Cpu);
    const Receiver = @import("../block_v5_caller_readonly_receiver_v1.zig").ForBackend(Cpu);
    const Stage = @import("../block_v5_caller_readonly_stage_v1.zig").ForBackend(Cpu);
    const produce: *const @TypeOf(Producer.proveForCallerFirstRound) = &Producer.proveForCallerFirstRound;
    const fresh: *const @TypeOf(Receiver.verifyOwned) = &Receiver.verifyOwned;
    const absence: *const @TypeOf(Receiver.verifyOptionalOwned) = &Receiver.verifyOptionalOwned;
    const prepare: *const @TypeOf(Stage.Prepared.init) = &Stage.Prepared.init;
    const warm: *const @TypeOf(Stage.proveWarm) = &Stage.proveWarm;
    const prepared: *const @TypeOf(Stage.provePreparedWarm) = &Stage.provePreparedWarm;
    const domain: *const @TypeOf(Air.Component.evaluateConstraintQuotientsOnDomain) = &Air.Component.evaluateConstraintQuotientsOnDomain;
    inline for (.{ produce, fresh, absence, prepare, warm, prepared, domain }) |body| std.mem.doNotOptimizeAway(body);
}
fn sampleValues(a: std.mem.Allocator, count: usize, n: usize) ![][]Q {
    const result = try a.alloc([]Q, count);
    for (result, 0..) |*column, c| {
        column.* = try a.alloc(Q, n);
        for (column.*, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(3 + c + i), @intCast(7 + c + i), @intCast(11 + c + i), @intCast(13 + c + i));
    }
    return result;
}
fn polys(a: std.mem.Allocator, count: usize) ![]engine.air.component_prover.Poly {
    const result = try a.alloc(engine.air.component_prover.Poly, count);
    for (result, 0..) |*poly, i| {
        const coefficients = try a.dupe(M, &.{ M.fromCanonical(@intCast(7 + i)), M.fromCanonical(@intCast(11 + 3 * i)) });
        poly.* = .{ .log_size = 1, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(coefficients) };
    }
    return result;
}
// Reference recovery evaluates every coefficient directly, independently of
// the domain evaluator's selected-column/full-LDE recovery and mask gathers.
fn domainParity(a: std.mem.Allocator, component: *const Air.Component, trees: [4][]const engine.air.component_prover.Poly) !void {
    const Domain = engine.air.accumulation.DomainEvaluationAccumulator;
    const seed = Q.fromU32Unchecked(2, 3, 5, 7);
    var actual = try Domain.init(a, seed, 3, Air.COUNT);
    defer actual.deinit();
    var source_trees = trees;
    const trace_view = engine.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&source_trees) };
    try component.evaluateConstraintQuotientsOnDomain(&trace_view, &actual);
    var expected = try Domain.init(a, seed, 3, Air.COUNT);
    defer expected.deinit();
    const output = try expected.columns(a, &.{.{ .log_size = 3, .n_cols = Air.COUNT }});
    defer a.free(output);
    var out = output[0];
    const domain = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    var values: [4][][]const M = undefined;
    for (trees, 0..) |tree, t| {
        values[t] = try a.alloc([]const M, tree.len);
        for (tree, 0..) |poly, c| {
            const evaluated = try poly.coefficients.?.evaluate(a, domain);
            values[t][c] = evaluated.values;
        }
    }
    const point = core.circle.secureFieldPoint(71);
    var shape = try component.sourceMaskPoints(a, point, 3);
    defer shape.deinitDeep(a);
    var mask_trees: [4][][]Q = undefined;
    for (shape.items, 0..) |tree, t| {
        mask_trees[t] = try a.alloc([]Q, tree.len);
        for (tree, 0..) |cells, c| mask_trees[t][c] = try a.alloc(Q, cells.len);
    }
    for (0..8) |row| {
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, 1, 3);
        const shift = core.utils.offsetBitReversedCircleDomainIndex(row, 1, 3, 27);
        for (shape.items, 0..) |tree, t| for (tree, 0..) |cells, c| {
            for (0..cells.len) |sample| mask_trees[t][c][sample] = Q.fromBase(values[t][c][if (sample == 0) row else if (t == 3) prior else shift]);
        };
        const mask = core.air.components.MaskValues{ .items = &mask_trees };
        const equations = try component.evaluateMask(&mask);
        var sum = Q.zero();
        for (equations, 0..) |equation, i| sum = sum.add(out.random_coeff_powers[Air.COUNT - 1 - i].mul(equation));
        const inverse = try core.constraints.cosetVanishing(M, core.poly.circle.canonic.CanonicCoset.new(1).coset(), domain.at(core.utils.bitReverseIndex(row, 3))).inv();
        out.accumulate(row, sum.mulM31(inverse));
        try std.testing.expectEqualDeep(expected.sub_accumulations[3].?.at(row), actual.sub_accumulations[3].?.at(row));
    }
}
test "block-v5 caller readonly all authentic slots exact masks OODS and selected domain parity" {
    const owner = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(owner);
    defer arena.deinit();
    const a = arena.allocator();
    const admitted = try statement(a);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 37, .cycle_count = 4 };
    var schedule = try Schedule.init(a, &admitted, 4, frame, 1);
    defer schedule.deinit();
    const fixed = try a.alloc(u32, schedule.fixed.len);
    @memset(fixed, 1);
    const main = try a.alloc(u32, schedule.main.len);
    @memset(main, 1);
    const witness = try a.alloc(u32, schedule.memory.len * (Integer.COLUMN_COUNT + Air.META_COUNT));
    @memset(witness, 1);
    const old_interactions = try schedule.interactionLogs();
    const interactions = try a.alloc(u32, old_interactions.len + schedule.memory.len * Air.INTER_COUNT);
    @memset(interactions, 1);
    var channel = core.proof_suites.Blake3.Channel{};
    const bus = try @import("../block_memory_relation_v2.zig").Challenges.drawFromChannel(a, &channel);
    const word = try @import("../block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    var classification = exactChallenges();
    classification.word = word;
    const fixed_samples = try sampleValues(a, fixed.len, 1);
    const main_samples = try sampleValues(a, main.len, 2);
    const witness_samples = try sampleValues(a, witness.len, 1);
    const interaction_samples = try sampleValues(a, interactions.len, 2);
    var samples: [4][][]Q = .{ fixed_samples, main_samples, witness_samples, interaction_samples };
    const mask = core.air.components.MaskValues{ .items = &samples };
    const source_polys: [4][]const engine.air.component_prover.Poly = .{ try polys(a, fixed.len), try polys(a, main.len), try polys(a, witness.len), try polys(a, interactions.len) };
    const point = core.circle.secureFieldPoint(71);
    var seen: [3]bool = @splat(false);
    for (schedule.memory, 0..) |canonical, i| {
        var slot = canonical;
        slot.log_size = 1;
        const original = try (@import("../block_execution_sidecar_stark_v2.zig").Component{ .register_custody_mode = 1, .family = .base_alu_imm, .slot = slot.slot, .external_source = slot, .log_size = 1, .base_clock = try Integer.baseClockFromPublicFrame(frame), .fixed_logs = fixed, .main_logs = main, .witness_logs = witness, .interaction_logs = interactions, .root_owner = false, .main_offset = slot.main_offset, .witness_offset = i * Integer.COLUMN_COUNT, .interaction_offset = schedule.projectionCount() * 4 + i * @import("../block_v5_opcode_sidecar_eval_v1.zig").INTERACTION_COUNT, .transition_claim = Q.zero(), .transition_count = 1, .range_claims = @splat(Q.zero()), .challenges = &bus, .v5_packed = .{ .elements = &word }, .v5_universal = .{ .claim = Q.zero(), .elements = word.universal_prefix.get(.memory_access) } }).init();
        const component = try (Air.Component{ .source = original, .metadata_offset = schedule.memory.len * Integer.COLUMN_COUNT + i * Air.META_COUNT, .prefix_offset = old_interactions.len + i * Air.INTER_COUNT, .claim = .{ .mutable_sum = Q.one(), .classification_sum = scalar(3), .read_sum = scalar(7), .readonly_count = 1 }, .challenges = &classification, .split = schedule.split }).init();
        var shape = try component.maskPoints(owner, point, 1);
        defer shape.deinitDeep(owner);
        var bounds = try component.traceLogDegreeBounds(owner);
        defer bounds.deinitDeep(owner);
        try std.testing.expectEqual(@as(usize, 0), shape.items[0].len);
        try std.testing.expectEqual(@as(usize, 0), shape.items[1].len);
        try std.testing.expectEqual(Air.META_COUNT, shape.items[2].len);
        try std.testing.expectEqual(Air.INTER_COUNT, shape.items[3].len);
        try std.testing.expectEqual(Air.META_COUNT, bounds.items[2].len);
        try std.testing.expectEqual(Air.INTER_COUNT, bounds.items[3].len);
        for (shape.items[3]) |cells| try std.testing.expect(cells[1].eql(@import("../../air/logup.zig").prevRowPoint(1, point)));
        const pair = try Air.sourcePair(slot, &mask);
        if (slot.kind == .keccak) {
            const KT = @import("../../air/guest_precompile/keccakf_trace.zig");
            const KC = @import("../../air/guest_precompile/keccakf_caller.zig");
            var caller: [KC.Layout.main_columns]Q = undefined;
            for (&caller, 0..) |*v, c| v.* = main_samples[slot.main_offset + KT.Layout.caller + c][0];
            var before: [1600]Q = undefined;
            var after: [1600]Q = undefined;
            for (&before, &after, 0..) |*v, *w, c| {
                v.* = main_samples[slot.main_offset + KT.Layout.state + c][0];
                w.* = main_samples[slot.main_offset + KT.Layout.state + c][1];
            }
            const reference = try @import("../block_execution_external_access_bridge_v2.zig").keccakPair(Q, &caller, &before, &after, slot.slot);
            try std.testing.expectEqualDeep(reference, pair);
        }
        const residuals = try component.evaluateMask(&mask);
        const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(1).coset(), point).inv();
        var actual = core.air.accumulation.PointEvaluationAccumulator.init(scalar(17));
        var expected = core.air.accumulation.PointEvaluationAccumulator.init(scalar(17));
        try component.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, 1);
        for (residuals) |residual| expected.accumulate(residual.mul(inverse));
        try std.testing.expectEqualDeep(expected.finalize(), actual.finalize());
        const saved = interaction_samples[component.prefix_offset];
        interaction_samples[component.prefix_offset] = saved[0..1];
        try std.testing.expectError(error.InvalidCallerReadonlyMask, component.evaluateMask(&mask));
        interaction_samples[component.prefix_offset] = saved;
        if (!seen[@intFromEnum(slot.kind)]) {
            seen[@intFromEnum(slot.kind)] = true;
            try domainParity(a, &component, source_polys);
        }
        for (0..Air.COUNT) |constraint| try std.testing.expectEqual(@as(u8, 3), try component.constraintDegreeBound(constraint));
    }
    for (seen) |kind| try std.testing.expect(kind);
}
fn allocationFailure(a: std.mem.Allocator, source: *const Source.Trace, plan: Plan.Owned) !void {
    var metadata = try Witness.Metadata.init(a, source, plan, .{});
    defer metadata.deinit(a);
    const challenges = exactChallenges();
    var generated = try Witness.generate(a, source, &metadata, plan, &challenges, .{});
    defer generated.deinit(a);
}
test "block-v5 caller readonly metadata and interaction all allocation failures clean" {
    const owner = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(owner);
    defer arena.deinit();
    const pins = try sources();
    var plan = try Plan.derive(owner, pins, &input, &.{base}, .{});
    defer plan.deinit();
    var candidate = try trace(arena.allocator(), 7);
    defer candidate.deinit();
    try std.testing.checkAllAllocationFailures(owner, allocationFailure, .{ &candidate, plan });
}
fn physicalBody(a: std.mem.Allocator, prefix: *@import("../block_v5_precompile_family_proof_v1.zig").ForBackend(Cpu).PhysicalFirstRound, frame: Frame, selection: Selection.Pins, bytes: []const u8, limits: Protocol.Limits) !@import("../block_v5_caller_readonly_stage_v1.zig").ForBackend(Cpu).Prepared {
    return @import("../block_v5_caller_readonly_stage_v1.zig").ForBackend(Cpu).Prepared.initPhysical(a, prefix, &prefix.witness.statement, prefix.total_steps, frame, selection, bytes, limits);
}
test "block-v5 caller readonly physical selection stage and zero RW typed absence" {
    const body: *const @TypeOf(physicalBody) = &physicalBody;
    std.mem.doNotOptimizeAway(body);
    const a = std.testing.allocator;
    const pins = try sources();
    var plan = try Plan.derive(a, pins, &input, &.{}, .{});
    defer plan.deinit();
    const counters = try a.alloc(u64, plan.intervals.len);
    defer a.free(counters);
    @memset(counters, 0);
    const challenges = exactChallenges();
    try Protocol.checkProviders(plan, 0, .{ .mutable_sum = Q.zero(), .classification_sum = Q.zero(), .read_sum = Q.zero(), .readonly_count = 0 }, counters, &challenges, .{});
    try std.testing.expectError(error.InvalidCallerReadonlyProviderCensus, Protocol.checkProviders(plan, 0, .{ .mutable_sum = Q.zero(), .classification_sum = Q.zero(), .read_sum = Q.zero(), .readonly_count = 1 }, counters, &challenges, .{}));
    // This only checks structural sparse absence. It never fabricates a proof
    // or accepts a native/caller/global receipt from these candidate IDs.
    const Seal = @import("../block_v5_source_seal_v1.zig");
    var sealed = std.mem.zeroes(Seal.Sealed);
    sealed.execution_instance_count = 1;
    const execution = Seal.Entry{ .family = .execution, .index = 0, .instance_id = @splat(1), .roots = .{ @splat(2), @splat(3) } };
    const Receiver = @import("../block_v5_caller_readonly_receiver_v1.zig");
    try Receiver.requireAbsence(0, sealed, &.{execution});
    try std.testing.expectError(error.MissingV5CallerCompositePin, Receiver.requireAbsence(0, sealed, &.{ execution, .{ .family = .precompile, .index = 0, .instance_id = @splat(4), .roots = .{ @splat(5), @splat(6) } } }));
}
