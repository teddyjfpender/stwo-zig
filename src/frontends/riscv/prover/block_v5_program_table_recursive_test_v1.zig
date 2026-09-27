//! No fixture accepts literal proof material: typed equations and policy only.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const r = @import("../recursion/air/composition_graph_recorder.zig");
const S = r.Scalar;
const Native = @import("block_v5_program_table_proof_v1.zig");
const Source = @import("block_v5_program_table_v1.zig");
const Admission = @import("block_v5_program_table_recursive_admission_v1.zig");
const Bus = @import("../recursion/block_v5_program_table_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_program_table_parent_protocol_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const leaves = [_]tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 }, .{ .index = 4, .value = 5 }, .{ .index = 5, .value = 6 }, .{ .index = 6, .value = 7 }, .{ .index = 7, .value = 8 } };
const multiplicities = [_]u64{ 3, 2 };
fn scalar(seed: u32) Q {
    return Q.fromU32Unchecked(seed + 1, seed + 2, seed + 3, seed + 4);
}
const Fixture = struct {
    plan: Source.Plan,
    entries: [6]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init() !Fixture {
        const plan = Source.Plan{ .program_root = try tree.TreeHasher.init(.program).root(&leaves), .leaves = &leaves, .multiplicities = &multiplicities, .expected_fetches = 5, .log_size = 7 };
        var self = Fixture{ .plan = plan, .entries = undefined, .pins = undefined, .sealed = undefined };
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = try plan.digest(), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
            .{ .family = .memory_range, .index = 0, .instance_id = @splat(60), .roots = .{ @splat(61), @splat(62) } },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        self.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = plan.program_root.bytes, .program_plan_digest = try plan.digest(), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = Base.PCS_CONFIG, .counts = counts };
        self.sealed = try Seal.seal(self.pins, &self.entries);
        return self;
    }
    fn prepared(self: *const Fixture, a: std.mem.Allocator) !Admission.Prepared {
        return Admission.Prepared.init(a, self.plan, 0, self.sealed, self.pins, &self.entries, .{});
    }
};
const Equation = struct {
    arena: std.heap.ArenaAllocator,
    circuit: r.Circuit,
    inputs: []Q,
    values: []Q,
    claim_input: usize,
    row_input: usize,
    previous_input: usize,
    chunk_input: usize,
    challenge_input: usize,
    fn deinit(self: *Equation) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    fn evaluate(self: *Equation) !void {
        try self.circuit.evaluateInto(self.inputs, self.values);
    }
};
fn input(builder: *r.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    return symbol.value;
}
fn equation(a: std.mem.Allocator, claim_value: Q) !Equation {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try universal.UniversalRelations.draw(temp, &channel);
    var definition = try Native.Air.build(temp);
    defer definition.deinit();
    const relation_plan = try @import("../recursion/air/universal_relation_binding.zig").Binding(Native.Air).authenticate(&definition);
    const manifest = Native.Roster.Manifest{ .log_sizes = .{7} };
    const component = try Native.Roster.Component(Native.Air).init(&definition, relation_plan, &manifest, .program, 7, .{}, &relations, claim_value);
    const handle = try @import("../recursion/air/block_v5_program_table_composition_v1.zig").verifier(&component);
    const composition_log = handle.maxConstraintLogDegreeBound();
    const split = handle.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split).?;
    const seed = scalar(71);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    var masks = try handle.maskPoints(temp, point, mask_log);
    defer masks.deinitDeep(temp);
    const concrete = try temp.alloc([][]Q, masks.items.len);
    const symbolic = try temp.alloc([][]S, masks.items.len);
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var previous_input: usize = undefined;
    for (masks.items, concrete, symbolic, 0..) |tree_masks, *out, *symbols, t| {
        out.* = try temp.alloc([]Q, tree_masks.len);
        symbols.* = try temp.alloc([]S, tree_masks.len);
        for (tree_masks, out.*, symbols.*, 0..) |column, *column_values, *syms, i| {
            column_values.* = try temp.alloc(Q, column.len);
            syms.* = try temp.alloc(S, column.len);
            for (column_values.*, syms.*, 0..) |*value, *sym, j| {
                if (t == 2 and i == 0 and j == 0) previous_input = inputs.items.len;
                value.* = scalar(@intCast(10 + t * 101 + i * 7 + j));
                sym.* = try input(&builder, temp, &inputs, value.*);
            }
        }
    }
    const random = scalar(17);
    var accumulator = core.air.accumulation.PointEvaluationAccumulator.init(random);
    var native_mask = core.air.components.MaskValues{ .items = concrete };
    try handle.evaluateConstraintQuotientsAtPoint(point, &native_mask, &accumulator, mask_log);
    const f0 = point.repeatedDouble(composition_log - split - 1).x;
    const f1 = point.repeatedDouble(composition_log - split).x;
    const higher = [_]Q{ scalar(33), scalar(44), scalar(55) };
    const chunk0 = accumulator.finalize().sub(f0.mul(higher[0])).sub(f1.mul(higher[1].add(f0.mul(higher[2]))));
    const challenge_input = inputs.items.len;
    var draws: [universal.RELATION_COUNT][2]S = undefined;
    for (&draws, relations.elements) |*pair, element| pair.* = .{ try input(&builder, temp, &inputs, element.z), try input(&builder, temp, &inputs, element.alpha) };
    const random_symbol = try input(&builder, temp, &inputs, random);
    const seed_symbol = try input(&builder, temp, &inputs, seed);
    const claim_input = inputs.items.len;
    const claim = try input(&builder, temp, &inputs, claim_value);
    const chunk_input = inputs.items.len;
    const chunks: [4]S = .{ try input(&builder, temp, &inputs, chunk0), try input(&builder, temp, &inputs, higher[0]), try input(&builder, temp, &inputs, higher[1]), try input(&builder, temp, &inputs, higher[2]) };
    var row: [6]S = undefined;
    for (&row, 0..) |*value, i| value.* = symbolic[0][i][0];
    var current: [4]S = undefined;
    var previous: [4]S = undefined;
    for (&current, &previous, 0..) |*now, *prior, i| {
        now.* = symbolic[2][i][1];
        prior.* = symbolic[2][i][0];
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const challenges = try r.ChallengeSet.init(draws);
    try @import("../recursion/air/block_v5_program_table_composition_v1.zig").recordEquation(&builder, &component, row, current, previous, claim, &challenges, random_symbol, seed_symbol, chunks);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const evaluated = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, evaluated);
    // Only program_access z participates; select its actual registry ordinal.
    const ordinal = @intFromEnum(@import("../air/lang/relation.zig").Domain.program_access);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = evaluated, .claim_input = claim_input, .row_input = 0, .previous_input = previous_input, .chunk_input = chunk_input + 1, .challenge_input = challenge_input + 2 * ordinal };
}
test "ROM recursion: exact native compiler equation and split2 quotient match symbolic authority and reject claim tuple recurrence challenge and chunk mutations" {
    var first = try equation(std.testing.allocator, scalar(111));
    defer first.deinit();
    var second = try equation(std.testing.allocator, scalar(222));
    defer second.deinit();
    try std.testing.expectEqualDeep(first.circuit.identity_digest, second.circuit.identity_digest);
    for ([_]usize{ first.claim_input, first.row_input, first.previous_input, first.chunk_input, first.challenge_input }) |index| {
        const old = first.inputs[index];
        first.inputs[index] = old.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
        first.inputs[index] = old;
        try first.evaluate();
    }
}
fn equationAllocation(a: std.mem.Allocator) !void {
    var value = try equation(a, scalar(111));
    defer value.deinit();
    try value.evaluate();
}
test "ROM recursion: compiler equation OOM preserves original error and releases all owned graph state" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, equationAllocation, .{});
}
fn policyAllocation(a: std.mem.Allocator) !void {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
}
test "ROM recursion: complete independent ROM census seal and domain policy reject mutations before proof loads" {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(std.testing.allocator);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
    admitted.logs[2][0] += 1;
    try std.testing.expectError(error.UntrustedProgramRecursiveGeometry, admitted.validate(admitted.template_id));
    admitted.logs[2][0] -= 1;
    var wrong = admitted;
    wrong.index = 1;
    try std.testing.expectError(error.UntrustedProgramRecursiveAdmission, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.seal.source_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedProgramRecursiveAdmission, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.plan.expected_fetches += 1;
    try std.testing.expectError(error.ProgramFetchCensusMismatch, wrong.validate(admitted.template_id));
    var altered = leaves;
    altered[1].value ^= 1;
    wrong = admitted;
    wrong.plan.leaves = &altered;
    try std.testing.expectError(error.ProgramRootMismatch, wrong.validate(admitted.template_id));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, policyAllocation, .{});
}
fn recordPrefix(a: std.mem.Allocator) !void {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var recorder = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    const claim = scalar(44);
    const actual = try @import("../recursion/air/block_v5_program_table_transcript_v1.zig").prefix(arena.allocator(), &recorder, &admitted, claim);
    var relation_channel = admitted.seal.sharedChannel();
    const expected = try universal.UniversalRelations.draw(arena.allocator(), &relation_channel);
    try std.testing.expectEqualDeep(expected, actual);
    var pcs = admitted.seal.proofChannel();
    pcs.mixFelts(&.{claim});
    try std.testing.expectEqualDeep(pcs, recorder.native);
    try std.testing.expectEqual(@as(usize, 47), recorder.relation_count);
    try std.testing.expectEqual(@as(usize, 2), recorder.root_count);
    var restarts: usize = 0;
    for (recorder.operations.items) |op| if (op == .restart) {
        try std.testing.expectEqual(@as(u32, 1), op.restart);
        restarts += 1;
    };
    try std.testing.expectEqual(@as(usize, 1), restarts);
}
test "ROM recursion: original two channels match exact draw and PCS framing with authenticated restart" {
    try recordPrefix(std.testing.allocator);
}
test "ROM recursion: two-channel recorder allocation failures release all prefix and policy state" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, recordPrefix, .{});
}
fn busValues() Bus.Values {
    return .{ .template = @splat(1), .sealed = @splat(2), .native_roster = @splat(3), .plan = @splat(4), .program_root = @splat(5), .roots = .{ @splat(6), @splat(7) }, .index = 0, .log_size = 7, .fetch_count = 5, .claim = scalar(19) };
}
const wires = [_]Bus.Wire{ .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 0, .uses = 2, .source = .sealed, .coordinate = 0 }, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 8, .uses = 1, .source = .native_roster, .coordinate = 0 }, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 16, .uses = 1, .source = .plan, .coordinate = 0 }, .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 24, .uses = 1, .source = .program_root, .coordinate = 0 }, .{ .circuit = 1500, .wire = 2, .uses = 1, .source = .claim, .coordinate = 0 }, .{ .circuit = @import("../recursion/air/blake3_root_sources.zig").CIRCUIT, .wire = 8, .uses = 8, .source = .main_root, .coordinate = 0 } };
test "ROM recursion: shared setup public schedule rejects identity config and claim substitution" {
    const first = busValues();
    const geometry = Base.Key{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = first.template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(8), @splat(9), @splat(10) }, .transcript_plan_id = @splat(11) }, .log_sizes = @splat(4), .preprocessed_root = @splat(12) };
    const key = try Protocol.Key.fromGeometry(geometry, &wires);
    const id = try key.identity();
    const authority = try Protocol.Admission.init(key, id, &wires, first);
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try universal.UniversalRelations.draw(std.testing.allocator, &channel);
    const baseline = try Bus.supply(&wires, first, relations);
    inline for (.{ "sealed", "native_roster", "plan", "program_root", "roots", "claim" }) |field| {
        var changed = first;
        if (comptime std.mem.eql(u8, field, "roots")) changed.roots[1][0] ^= 1 else if (comptime std.mem.eql(u8, field, "claim")) changed.claim = changed.claim.add(Q.one()) else @field(changed, field)[0] ^= 1;
        const other = try Protocol.Admission.init(key, id, &wires, changed);
        try std.testing.expect(!std.meta.eql(try authority.publicInputIdentity(), try other.publicInputIdentity()));
        try std.testing.expect(!baseline.eql(try Bus.supply(&wires, changed, relations)));
    }
    var invalid = first;
    invalid.index = 1;
    try std.testing.expectError(error.InvalidProgramPublicInputs, invalid.validate());
    invalid = first;
    invalid.template[0] ^= 1;
    try std.testing.expectError(error.UntrustedProgramRecursiveTemplate, Protocol.Admission.init(key, id, &wires, invalid));
    var security = key;
    security.context.child_config.pow_bits = 26;
    try std.testing.expectError(error.ProgramRecursiveSecurityMismatch, Protocol.Admission.init(security, id, &wires, first));
}
test "ROM recursion: repeated channel restart authenticates initial state counters prior exports and version" {
    const Recorder = @import("../recursion/air/blake3_native_recorder.zig");
    const tape = @import("../recursion/air/blake3_transcript_witness.zig");
    const Plan = @import("../recursion/air/blake3_transcript_plan.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var rec = Recorder.Recorder{ .a = a, .universal_relations = true };
    rec.mixU32s(&.{17});
    const first = try rec.drawSecureFelts(a, 2);
    var native = core.proof_suites.Blake3.Channel{};
    native.mixU32s(&.{17});
    const expected = try native.drawSecureFelts(a, 2);
    try std.testing.expectEqualDeep(expected, first);
    try rec.restartChannel();
    const second = try rec.drawSecureFelts(a, 2);
    native = .{};
    try std.testing.expectEqualDeep(try native.drawSecureFelts(a, 2), second);
    try rec.restartChannel();
    const third = try rec.drawSecureFelts(a, 2);
    native = .{};
    try std.testing.expectEqualDeep(try native.drawSecureFelts(a, 2), third);
    try std.testing.expectEqualDeep(second, third);
    try std.testing.expectEqual(@as(usize, 3), rec.relation_count);
    var planned = try Plan.Plan.initCompact(std.testing.allocator, .{ .namespace = 901, .attempt_capacity = 2 }, rec.operations.items);
    defer planned.deinit();
    var live = try planned.prepare(std.testing.allocator, rec.operations.items);
    defer live.deinit();
    try std.testing.expectEqualDeep(rec.native.digestBytes(), live.final_digest.?);
    try std.testing.expectEqual(rec.native.n_draws, live.next_draw);
    try std.testing.expectEqual(@as(usize, 3), live.draw_outputs.len);
    for (live.draw_outputs, 0..) |out, i| {
        try std.testing.expectEqual(i, out.role.universal);
    }
    var changed: std.ArrayList(tape.Operation) = .empty;
    var removed = false;
    for (rec.operations.items) |op| {
        if (op == .restart and !removed) {
            removed = true;
            continue;
        }
        try changed.append(a, op);
    }
    var other = try Plan.Plan.initCompact(std.testing.allocator, .{ .namespace = 901, .attempt_capacity = 2 }, changed.items);
    defer other.deinit();
    try std.testing.expect(!std.meta.eql(planned.id, other.id));
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, planned.prepare(std.testing.allocator, changed.items));
    rec.mixRoot(@splat(9));
    const root_index = rec.root_count;
    const relation_index = rec.relation_count;
    try rec.restartChannel();
    try std.testing.expectEqual(root_index, rec.root_count);
    try std.testing.expectEqual(relation_index, rec.relation_count);
    const fresh = core.proof_suites.Blake3.Channel{};
    try std.testing.expectEqualDeep(fresh, rec.native);
    const invalid = [_]tape.Operation{.{ .restart = 2 }};
    try std.testing.expectError(error.InvalidBlake3Transcript, tape.trusted(std.testing.allocator, 901, &invalid));
}
