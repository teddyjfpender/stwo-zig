//! Arbitrary canonical OODS/equation and independently admitted literal policy
//! fixtures. They do NOT produce or accept a native/recursive STARK capture.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Recorder = @import("../recursion/air/composition_graph_recorder.zig");
const S = Recorder.Scalar;
const Lane = @import("block_v5_ram_lanes_proof_v1.zig");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const Spec = @import("block_v5_ram_lanes_component_v1.zig").Spec;
const Air = @import("../air/block/word_memory_lanes_v1.zig");
const WordAir = @import("../air/block/word_memory_v5.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Admission = @import("block_v5_ram_lanes_recursive_admission_v1.zig");
const Composition = @import("../recursion/air/block_v5_ram_lanes_composition_v1.zig");
const Bus = @import("../recursion/block_v5_ram_lanes_recursive_public_bus_v1.zig");
const Parent = @import("../recursion/block_v5_reusable_ram_lanes_parent_protocol_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
fn scalar(seed: u32) Q {
    return Q.fromU32Unchecked(seed + 1, seed + 2, seed + 3, seed + 4);
}
fn event(index: u32) Event {
    return .{ .space = 1, .address = 0x8000_0000, .clock = (@as(u64, 1) << 40) + index, .before = 0xffff_0000 + index, .after = 0xffff_0001 + index };
}
fn pin(events: u32, first: u64, last: bool) Lane.Pin {
    return .{ .claim = .{ .first_event = first, .total_events = first + events + (if (last) @as(u64, 0) else 1), .events = events, .row_log = 2, .first = event(@intCast(first)), .last = event(@intCast(first + events - 1)), .preceding = if (first == 0) null else event(@intCast(first - 1)) }, .index = 0, .roots = .{ @splat(8), @splat(9) }, .request_count = 14 * @as(u64, events) - (if (first == 0) @as(u64, 4) else 0), .counter_digest = @splat(10), .config = Base.PCS_CONFIG };
}
fn sums(p: Lane.Pin) Interaction.Claim {
    return .{ .event_count = p.claim.events, .transition_sum = scalar(20), .link_sum = scalar(30), .initial_sum = scalar(40), .endpoint_sum = scalar(50), .endpoint_count = 1, .range_count = p.request_count, .range_sums = @splat(scalar(60)) };
}
const Fixture = struct {
    pin: Lane.Pin,
    entries: [6]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init() !Fixture {
        var self: Fixture = undefined;
        self.pin = pin(3, 0, true);
        self.entries = .{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            try self.pin.entry(),
            .{ .family = .memory_range, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (self.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        self.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = 1, .config = Base.PCS_CONFIG, .counts = counts };
        self.sealed = try Seal.seal(self.pins, &self.entries);
        return self;
    }
    fn prepared(self: *const Fixture, a: std.mem.Allocator) !Admission.Prepared {
        return Admission.Prepared.init(a, self.pin, self.sealed, self.pins, &self.entries, .{});
    }
};
const Equation = struct {
    arena: std.heap.ArenaAllocator,
    circuit: Recorder.Circuit,
    inputs: []Q,
    values: []Q,
    public_offset: usize,
    prior_offset: usize,
    interaction_offset: usize,
    chunk_offset: usize,
    fn deinit(self: *Equation) void {
        self.circuit.deinit();
        self.arena.deinit();
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
fn equation(a: std.mem.Allocator, p: Lane.Pin) !Equation {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var channel = @import("block_v5_universal_channel_v1.zig").init(@splat(77));
    const challenges = try Word.Challenges.drawFromChannel(temp, &channel);
    const claimed = sums(p);
    const spec = Spec{ .claim = p.claim, .interaction_claim = claimed, .challenges = &challenges };
    const Adapter = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
    const component = Adapter{ .log_size = p.claim.row_log, .spec = spec };
    const seed = scalar(71);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    var masks = try component.maskPoints(temp, point, p.claim.row_log);
    defer masks.deinitDeep(temp);
    const concrete = try temp.alloc([][]Q, masks.items.len);
    const symbolic = try temp.alloc([][]S, masks.items.len);
    var prior_offset: usize = undefined;
    var interaction_offset: usize = undefined;
    for (masks.items, concrete, symbolic, 0..) |tree, *out, *symbols, t| {
        out.* = try temp.alloc([]Q, tree.len);
        symbols.* = try temp.alloc([]S, tree.len);
        for (tree, out.*, symbols.*, 0..) |column, *values, *syms, i| {
            values.* = try temp.alloc(Q, column.len);
            syms.* = try temp.alloc(S, column.len);
            for (values.*, syms.*, 0..) |*value, *sym, j| {
                if (t == 1 and i == Air.shiftedColumns[0] and j == 1) prior_offset = inputs.items.len;
                if (t == 2 and i == 0 and j == 0) interaction_offset = inputs.items.len;
                value.* = scalar(@intCast(10 + t * 101 + i * 7 + j));
                sym.* = try input(&builder, temp, &inputs, value.*);
            }
        }
    }
    const random = scalar(17);
    var accumulated = core.air.accumulation.PointEvaluationAccumulator.init(random);
    var native_mask = core.air.components.MaskValues{ .items = concrete };
    try component.evaluateConstraintQuotientsAtPoint(point, &native_mask, &accumulated, p.claim.row_log);
    const x0 = point.repeatedDouble(p.claim.row_log - 1).x;
    const x1 = point.repeatedDouble(p.claim.row_log).x;
    const chunk_tail: [3]Q = .{ scalar(33), scalar(34), scalar(35) };
    const chunk0 = accumulated.finalize().sub(x0.mul(chunk_tail[0])).sub(x1.mul(chunk_tail[1].add(x0.mul(chunk_tail[2]))));
    var challenge_symbols: [10]S = undefined;
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |field, i| {
        challenge_symbols[2 * i] = try input(&builder, temp, &inputs, @field(challenges, field).z);
        challenge_symbols[2 * i + 1] = try input(&builder, temp, &inputs, @field(challenges, field).alpha);
    }
    const public_offset = inputs.items.len;
    const public_values = try Composition.publicInputs(temp, p, claimed, @splat(77));
    var public: [Composition.PUBLIC_COUNT]S = undefined;
    for (&public, public_values) |*symbol, value| symbol.* = try input(&builder, temp, &inputs, value);
    const random_symbol = try input(&builder, temp, &inputs, random);
    const seed_symbol = try input(&builder, temp, &inputs, seed);
    const chunk_offset = inputs.items.len;
    const chunks: [4]S = .{ try input(&builder, temp, &inputs, chunk0), try input(&builder, temp, &inputs, chunk_tail[0]), try input(&builder, temp, &inputs, chunk_tail[1]), try input(&builder, temp, &inputs, chunk_tail[2]) };
    var fixed: [24]S = undefined;
    var main: [54]S = undefined;
    var prior_main: [54]S = @splat(S.zero());
    var current: [92]S = undefined;
    var previous: [92]S = undefined;
    for (&fixed, 0..) |*out, i| out.* = symbolic[0][i][0];
    for (&main, 0..) |*out, i| {
        out.* = symbolic[1][i][0];
        if (Spec.PREVIOUS_MAIN_MASK[i]) prior_main[i] = symbolic[1][i][1];
    }
    for (&current, &previous, 0..) |*out, *before, i| {
        out.* = symbolic[2][i][0];
        before.* = symbolic[2][i][1];
    }
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    try Composition.recordEquation(&builder, p.claim.row_log, fixed, main, prior_main, current, previous, public, challenge_symbols, random_symbol, seed_symbol, chunks);
    builder.deactivate();
    active = false;
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = values, .public_offset = public_offset, .prior_offset = prior_offset, .interaction_offset = interaction_offset, .chunk_offset = chunk_offset };
}

test "RAM recursion: all117 scalar quotients match shared symbolic AIR masks and four split chunks" {
    const a = std.testing.allocator;
    var baseline = try equation(a, pin(3, 0, true));
    defer baseline.deinit();
    for ([_]Lane.Pin{ pin(4, 0, false), pin(3, 1, true), pin(2, 1, false) }) |p| {
        var other = try equation(a, p);
        defer other.deinit();
        try std.testing.expectEqualDeep(baseline.circuit.identity_digest, other.circuit.identity_digest);
    }
    for ([_]usize{ baseline.prior_offset, baseline.interaction_offset, baseline.chunk_offset, baseline.public_offset + 0, baseline.public_offset + 4, baseline.public_offset + 5, baseline.public_offset + 23, baseline.public_offset + 32, baseline.public_offset + 43, baseline.public_offset + 54, baseline.public_offset + 55, baseline.public_offset + 56, baseline.public_offset + 57, baseline.public_offset + 58, baseline.public_offset + 59, baseline.public_offset + 60 }) |index| {
        const old = baseline.inputs[index];
        baseline.inputs[index] = old.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, baseline.evaluate());
        baseline.inputs[index] = old;
        try baseline.evaluate();
    }
}
fn equationAllocation(a: std.mem.Allocator) !void {
    var owned = try equation(a, pin(3, 0, true));
    defer owned.deinit();
    try owned.evaluate();
}
test "RAM recursion: equation allocation failures release every graph and arena owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, equationAllocation, .{});
}

test "RAM recursion: lifted endpoints share unchanged direct order degrees and exact previous main mask" {
    const p = pin(3, 1, true);
    var fixed: [24]Q = undefined;
    var flat: [54]Q = undefined;
    var prior_flat: [54]Q = undefined;
    for (&fixed, 0..) |*value, i| value.* = scalar(@intCast(10 + i));
    for (&flat, &prior_flat, 0..) |*value, *prior_value, i| {
        value.* = scalar(@intCast(40 + i));
        prior_value.* = scalar(@intCast(120 + i));
    }
    const public = Trace.fixedPoint(Q, fixed, p.claim);
    var prior: [9]Q = undefined;
    var first: [11]Q = undefined;
    var last: [11]Q = undefined;
    for (&prior, Word.endpointTuple(p.claim.preceding.?)) |*value, cell| value.* = Q.fromBase(cell);
    for (&first, Word.transitionTuple(p.claim.first)) |*value, cell| value.* = Q.fromBase(cell);
    for (&last, Word.transitionTuple(p.claim.last)) |*value, cell| value.* = Q.fromBase(cell);
    const rows: Air.Algebra(Q).Row = .{ flat[0..27].*, flat[27..54].* };
    const previous: Air.Algebra(Q).Row = .{ prior_flat[0..27].*, prior_flat[27..54].* };
    try std.testing.expectEqualDeep(Air.constraints(p.claim, public, rows, previous), Air.Algebra(Q).constraintsWithEndpoints(prior, first, last, public, rows, previous));
    try std.testing.expectEqualDeep(WordAir.constraints(p.claim.legacy(), public[0], rows[0], previous[1]), WordAir.Algebra(Q).constraintsWithEndpoints(prior, first, last, public[0], rows[0], previous[1]));
    var shifted_count: usize = 0;
    for (Spec.PREVIOUS_MAIN_MASK, 0..) |needed, column| {
        var listed = false;
        for (Air.shiftedColumns) |expected| listed = listed or column == expected;
        try std.testing.expectEqual(listed, needed);
        shifted_count += @intFromBool(needed);
    }
    try std.testing.expectEqual(@as(usize, 9), shifted_count);
    try std.testing.expectEqual(@as(usize, 117), Spec.CONSTRAINT_COUNT);
    const degree_component = @import("block_v5_ram_lanes_component_v1.zig").Component{ .inner = .{ .spec = undefined, .log_size = p.claim.row_log } };
    for (0..Spec.CONSTRAINT_COUNT) |i| try std.testing.expect(try degree_component.constraintDegreeBound(i) <= 4);
}
fn policyAllocation(a: std.mem.Allocator) !void {
    const fixture = try Fixture.init();
    var prepared = try fixture.prepared(a);
    defer prepared.deinit();
    try prepared.validate(prepared.template_id);
}
test "RAM recursion: independent physical geometry seal endpoint and resource admission fails closed" {
    const fixture = try Fixture.init();
    var prepared = try fixture.prepared(std.testing.allocator);
    defer prepared.deinit();
    prepared.logs[1][0] += 1;
    try std.testing.expectError(error.UntrustedRamRecursiveGeometry, prepared.validate(prepared.template_id));
    prepared.logs[1][0] -= 1;
    var wrong = prepared;
    wrong.pin.roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, wrong.validate(prepared.template_id));
    wrong = prepared;
    wrong.pin.claim.last.after ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, wrong.validate(prepared.template_id));
    wrong = prepared;
    wrong.pin.claim.row_log += 1;
    try std.testing.expectError(error.UntrustedV5RamLanesEntry, wrong.validate(prepared.template_id));
    wrong = prepared;
    wrong.limits.max_capture_bytes = 0;
    try std.testing.expectError(error.UntrustedRamRecursiveAdmission, wrong.validate(prepared.template_id));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, policyAllocation, .{});
}
test "RAM recursion: original52 pairs lane pin and all90 claim words replay exactly" {
    const fixture = try Fixture.init();
    var prepared = try fixture.prepared(std.testing.allocator);
    defer prepared.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var r = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator(), .universal_relations = true };
    const claimed = sums(fixture.pin);
    const challenges = try @import("../recursion/air/block_v5_ram_lanes_transcript_v1.zig").prefix(arena.allocator(), &r, &prepared, claimed);
    try std.testing.expectEqualDeep(try Lane.proofChannel(arena.allocator(), fixture.sealed, fixture.pin, claimed), r.native);
    try std.testing.expectEqualDeep(try Word.Challenges.draw(arena.allocator(), fixture.sealed), challenges);
    try std.testing.expectEqual(@as(usize, 52), r.relation_count);
    try std.testing.expectEqual(@as(usize, 2), r.root_count);
    const values = try Bus.Values.fromLanes(&prepared, .{ .pin = fixture.pin, .sums = claimed, .sealed_digest = fixture.sealed.digest });
    const words = values.claimWords();
    try std.testing.expectEqual(@as(u32, 3), words[0]);
    try std.testing.expectEqual(@as(u32, @intCast(claimed.range_count)), words[88]);
}
const wires = [_]Bus.Wire{
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 0, .uses = 2, .source = .sealed, .coordinate = 0 },
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 8, .uses = 2, .source = .pin_identity, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 1, .uses = 1, .source = .equation, .coordinate = 0 },
    .{ .circuit = 1500, .wire = 2, .uses = 1, .source = .equation, .coordinate = 32 },
    .{ .circuit = Bus.PUBLIC_CIRCUIT, .wire = 16, .uses = 2, .source = .claim_words, .coordinate = 0 },
    .{ .circuit = @import("../recursion/air/blake3_root_sources.zig").CIRCUIT, .wire = 8, .uses = 8, .source = .main_root, .coordinate = 0 },
};
test "RAM recursion: independently derived public inputs reject census endpoint schedule and claim substitution" {
    const fixture = try Fixture.init();
    var prepared = try fixture.prepared(std.testing.allocator);
    defer prepared.deinit();
    const first = try Bus.Values.fromLanes(&prepared, .{ .pin = fixture.pin, .sums = sums(fixture.pin), .sealed_digest = fixture.sealed.digest });
    const geometry = Base.Key{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = first.template, .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try Parent.Key.fromGeometry(geometry, &wires);
    const expected = try key.identity();
    const authority = try Parent.Admission.init(key, expected, &wires, first);
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(std.testing.allocator, &channel);
    const baseline = try Bus.supply(&wires, first, relations);
    var changed = first;
    changed.sums.transition_sum = changed.sums.transition_sum.add(Q.one());
    changed.equation_inputs = try Composition.publicInputs(std.testing.allocator, changed.pin, changed.sums, changed.sealed);
    const other = try Parent.Admission.init(key, expected, &wires, changed);
    try std.testing.expect(!std.meta.eql(try authority.publicInputIdentity(), try other.publicInputIdentity()));
    try std.testing.expect(!baseline.eql(try Bus.supply(&wires, changed, relations)));
    changed = first;
    changed.equation_inputs[32] = changed.equation_inputs[32].add(Q.one());
    try std.testing.expectError(error.InvalidRamPublicInputs, changed.validate());
    changed = first;
    changed.sums.range_count -= 1;
    try std.testing.expectError(error.InvalidRamPublicInputs, changed.validate());
    changed = first;
    changed.sums.transition_sum.c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidV5RamLanesInteractionClaim, changed.validate());
    var outside = wires;
    outside[2].coordinate = Composition.PUBLIC_COUNT;
    try std.testing.expectError(error.InvalidRamPublicSchedule, Bus.scheduleDigest(&outside));
    var security = key;
    security.context.child_config.pow_bits = 26;
    try std.testing.expectError(error.RamRecursiveSecurityMismatch, Parent.Admission.init(security, expected, &wires, first));
}

test "RAM recursion: actual borrowed verifier all adapters publication cache and fresh leaf bodies retained only" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Capture = @import("block_v5_ram_lanes_recursive_capture_v1.zig");
    const Stage = @import("block_v5_ram_lanes_recursive_stage_v1.zig").ForBackend(Cpu);
    const Leaf = @import("../recursion/block_v5_ram_lanes_recursive_leaf_v1.zig");
    inline for (.{ &Capture.ForBackend(Cpu).verifyBorrowed, &Capture.VerifiedCapture.validate, &Composition.prepare, &@import("../recursion/air/block_v5_ram_lanes_deep_v1.zig").prepare, &@import("../recursion/air/block_v5_ram_lanes_transcript_v1.zig").planReplay, &@import("../recursion/air/block_v5_ram_lanes_roots_v1.zig").prepare, &Bus.prepare, &Stage.publish, &Stage.publishFromVerifiedCapture, &Leaf.verify }) |function| {
        std.mem.doNotOptimizeAway(function);
        try std.testing.expect(@intFromPtr(function) != 0);
    }
}
