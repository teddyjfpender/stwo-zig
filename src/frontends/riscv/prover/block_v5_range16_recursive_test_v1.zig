//! Pure equation, framing, independent-policy and ownership fixtures. Literal
//! metadata and arbitrary OODS values are NOT accepted as STARK proof captures.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Recorder = @import("../recursion/air/composition_graph_recorder.zig");
const S = Recorder.Scalar;
const Spec = @import("block_v5_range16_component_v1.zig").Spec;
const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
const Range = @import("block_v5_range16_v1.zig");
const Native = @import("block_v5_range16_proof_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Admission = @import("block_v5_range16_recursive_admission_v1.zig");
const Bus = @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_range16_parent_protocol_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
fn scalar(seed: u32) Q {
    return Q.fromU32Unchecked(seed + 1, seed + 2, seed + 3, seed + 4);
}
const Fixture = struct {
    shard: Range.Shard = .{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = 37 },
    plan: [32]u8 = @splat(7),
    roots: [2][32]u8 = .{ @splat(8), @splat(9) },
    entries: [6]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init() !Fixture {
        var self: Fixture = undefined;
        self.shard = .{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = 37 };
        self.plan = @splat(7);
        self.roots = .{ @splat(8), @splat(9) };
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
            .{ .family = .memory_range, .index = 0, .instance_id = Native.instanceId(self.plan, 0), .roots = self.roots },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        self.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = Base.PCS_CONFIG, .counts = counts };
        self.sealed = try Seal.seal(self.pins, &self.entries);
        return self;
    }
    fn prepared(self: *const Fixture, a: std.mem.Allocator) !Admission.Prepared {
        return Admission.Prepared.init(a, self.shard, self.plan, self.roots, self.sealed, self.pins, &self.entries, .{});
    }
};
const Equation = struct {
    arena: std.heap.ArenaAllocator,
    circuit: Recorder.Circuit,
    inputs: []Q,
    values: []Q,
    sum_input: usize,
    count_input: usize,
    previous_input: usize,
    chunk_input: usize,
    fn deinit(self: *Equation) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    fn evaluate(self: *Equation) !void {
        try self.circuit.evaluateInto(self.inputs, self.values);
    }
};
fn input(builder: *Recorder.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    return symbol.value;
}
fn equation(a: std.mem.Allocator, count: u32) !Equation {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var channel = core.proof_suites.Blake3.Channel{};
    const challenges = try Word.Challenges.drawFromChannel(temp, &channel);
    const spec = Spec{ .claim = .{ .sum = scalar(111), .count = count }, .challenges = &challenges };
    const component = Component{ .spec = spec, .log_size = Range.TABLE_LOG };
    const seed = scalar(71);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    var masks = try component.maskPoints(temp, point, Range.TABLE_LOG);
    defer masks.deinitDeep(temp);
    const concrete = try temp.alloc([][]Q, masks.items.len);
    const symbolic = try temp.alloc([][]S, masks.items.len);
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var previous_input: usize = undefined;
    for (masks.items, concrete, symbolic, 0..) |tree, *out, *symbols, t| {
        out.* = try temp.alloc([]Q, tree.len);
        symbols.* = try temp.alloc([]S, tree.len);
        for (tree, out.*, symbols.*, 0..) |column, *values, *syms, i| {
            values.* = try temp.alloc(Q, column.len);
            syms.* = try temp.alloc(S, column.len);
            for (values.*, syms.*, 0..) |*value, *sym, j| {
                if (t == 2 and i == 0 and j == 1) previous_input = inputs.items.len;
                value.* = scalar(@intCast(10 + t * 101 + i * 7 + j));
                sym.* = try input(&builder, temp, &inputs, value.*);
            }
        }
    }
    const random = scalar(17);
    var accumulated = core.air.accumulation.PointEvaluationAccumulator.init(random);
    var native_mask = core.air.components.MaskValues{ .items = concrete };
    try component.evaluateConstraintQuotientsAtPoint(point, &native_mask, &accumulated, Range.TABLE_LOG);
    const chunk1 = scalar(33);
    const chunk0 = accumulated.finalize().sub(point.repeatedDouble(Range.TABLE_LOG - 1).x.mul(chunk1));
    const sum_input = inputs.items.len;
    const sum = try input(&builder, temp, &inputs, spec.claim.sum);
    const count_input = inputs.items.len;
    const count_symbol = try input(&builder, temp, &inputs, Q.fromBase(M.fromCanonical(count)));
    const z = try input(&builder, temp, &inputs, challenges.range16.z);
    const random_symbol = try input(&builder, temp, &inputs, random);
    const seed_symbol = try input(&builder, temp, &inputs, seed);
    const chunk_input = inputs.items.len;
    const chunks: [2]S = .{ try input(&builder, temp, &inputs, chunk0), try input(&builder, temp, &inputs, chunk1) };
    var current: [8]S = undefined;
    var previous: [8]S = undefined;
    for (&current, &previous, 0..) |*now, *prior, i| {
        now.* = symbolic[2][i][0];
        prior.* = symbolic[2][i][1];
    }
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    try @import("../recursion/air/block_v5_range16_composition_v1.zig").recordEquation(&builder, .{symbolic[0][0][0]}, .{symbolic[1][0][0]}, current, previous, sum, count_symbol, z, random_symbol, seed_symbol, chunks);
    builder.deactivate();
    active = false;
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = values, .sum_input = sum_input, .count_input = count_input, .previous_input = previous_input, .chunk_input = chunk_input };
}
test "range recursion: exact CPU OODS quotient equals typed symbolic equations and rejects sum count previous and split chunk mutations" {
    var first = try equation(std.testing.allocator, 37);
    defer first.deinit();
    var second = try equation(std.testing.allocator, 91);
    defer second.deinit();
    try std.testing.expectEqualDeep(first.circuit.identity_digest, second.circuit.identity_digest);
    for ([_]usize{ first.sum_input, first.count_input, first.previous_input, first.chunk_input }) |index| {
        const old = first.inputs[index];
        first.inputs[index] = old.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
        first.inputs[index] = old;
        try first.evaluate();
    }
}
fn equationAllocation(a: std.mem.Allocator) !void {
    var owned = try equation(a, 37);
    defer owned.deinit();
    try owned.evaluate();
}
test "range recursion: equation graph construction failures release all owned circuit and arena state" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, equationAllocation, .{});
}
fn policyAllocation(a: std.mem.Allocator) !void {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(a);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
}
test "range recursion: independent shard roster config and fixed geometry admit before capture and allocation failures unwind" {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(std.testing.allocator);
    defer admitted.deinit();
    try admitted.validate(admitted.template_id);
    admitted.logs[2][0] += 1;
    try std.testing.expectError(error.UntrustedRangeRecursiveGeometry, admitted.validate(admitted.template_id));
    admitted.logs[2][0] -= 1;
    var wrong = admitted;
    wrong.shard.index = 1;
    try std.testing.expectError(error.MissingV5Range16Shard, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.plan_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5Range16Shard, wrong.validate(admitted.template_id));
    wrong = admitted;
    wrong.config.pow_bits = 1;
    try std.testing.expectError(error.UntrustedRangeRecursiveAdmission, wrong.validate(admitted.template_id));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, policyAllocation, .{});
}
test "range recursion: recorder replays original B5SS universal word suffix and every shard claim framing byte" {
    const fixture = try Fixture.init();
    var admitted = try fixture.prepared(std.testing.allocator);
    defer admitted.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var r = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    const claim = @import("block_v5_range16_component_v1.zig").Claim{ .sum = scalar(44), .count = fixture.shard.request_count };
    const challenges = try @import("../recursion/air/block_v5_range16_transcript_v1.zig").prefix(arena.allocator(), &r, &admitted, claim);
    const expected = try Native.proofChannel(arena.allocator(), fixture.sealed, fixture.shard, fixture.plan, claim);
    try std.testing.expectEqualDeep(expected, r.native);
    try std.testing.expectEqualDeep(try Word.Challenges.draw(arena.allocator(), fixture.sealed), challenges);
    try std.testing.expectEqual(@as(usize, 52), r.relation_count);
    try std.testing.expectEqual(@as(usize, 2), r.root_count);
}
fn busValues() Bus.Values {
    return .{ .template = @splat(1), .sealed = @splat(2), .plan = @splat(3), .roots = .{ @splat(4), @splat(5) }, .shard = .{ .index = 2, .first_instance = 4, .instance_count = 3, .request_count = 37 }, .sum = scalar(19), .count = 37 };
}
const wires = [_]Bus.Wire{
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 0, .uses = 2, .source = .sealed, .coordinate = 0 },
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 8, .uses = 2, .source = .plan, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 1, .uses = 1, .source = .sum, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 2, .uses = 1, .source = .count, .coordinate = 0 },
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 16, .uses = 2, .source = .shard_header, .coordinate = 3 },
    .{ .circuit = @import("../recursion/air/blake3_root_sources.zig").CIRCUIT, .wire = 8, .uses = 8, .source = .main_root, .coordinate = 0 },
};
test "range recursion: reusable statement bus changes value identity and rejects proof-policy or public closure substitution" {
    const first = busValues();
    const geometry = Base.Key{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = first.template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try Protocol.Key.fromGeometry(geometry, &wires);
    const expected = try key.identity();
    const authority = try Protocol.Admission.init(key, expected, &wires, first);
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(std.testing.allocator, &channel);
    const baseline = try Bus.supply(&wires, first, relations);
    inline for (.{ "sealed", "plan", "roots", "sum", "count", "index" }) |field| {
        var changed = first;
        if (comptime std.mem.eql(u8, field, "roots")) changed.roots[1][0] ^= 1 else if (comptime std.mem.eql(u8, field, "sum")) changed.sum = changed.sum.add(Q.one()) else if (comptime std.mem.eql(u8, field, "count")) {
            changed.count += 1;
            changed.shard.request_count += 1;
        } else if (comptime std.mem.eql(u8, field, "index")) changed.shard.index += 1 else @field(changed, field)[0] ^= 1;
        const other = try Protocol.Admission.init(key, expected, &wires, changed);
        try std.testing.expect(!std.meta.eql(try authority.publicInputIdentity(), try other.publicInputIdentity()));
        try std.testing.expect(!baseline.eql(try Bus.supply(&wires, changed, relations)));
    }
    var outside = wires;
    outside[2].coordinate = 1;
    try std.testing.expectError(error.InvalidRangePublicSchedule, Bus.scheduleDigest(&outside));
    var substituted = first;
    substituted.template[0] ^= 1;
    try std.testing.expectError(error.UntrustedRangeRecursiveTemplate, Protocol.Admission.init(key, expected, &wires, substituted));
    var security = key;
    security.context.child_config.pow_bits = 26;
    try std.testing.expectError(error.RangeRecursiveSecurityMismatch, Protocol.Admission.init(security, expected, &wires, first));
}
