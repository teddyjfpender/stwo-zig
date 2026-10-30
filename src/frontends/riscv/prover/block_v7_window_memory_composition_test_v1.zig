//! Arbitrary OODS parity against the actual original quotient adapter. These
//! tests qualify the equation kernels, not a recursive proof or publication.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const R = @import("block_v7_memory_relations_v1.zig");
const G = @import("../recursion/air/composition_graph_recorder.zig");
const S = G.Scalar;
const Kernel = @import("../recursion/air/block_v7_window_memory_kernels_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
fn scalar(seed: u32) Q {
    return Q.fromU32Unchecked(seed + 1, seed + 2, seed + 3, seed + 4);
}
fn event(i: u32) @import("../air/block/memory_transition.zig").Transition {
    return .{ .space = 1, .address = 0x100000, .clock = (@as(u64, 1) << 40) + i, .before = 100 + i, .after = 101 + i };
}
fn geometry(first: u64, last: bool) Geometry.Claim {
    return .{ .first_event = first, .total_events = first + 3 + @as(u64, @intFromBool(!last)), .events = 3, .row_log = 2, .first = event(@intCast(first)), .last = event(@intCast(first + 2)), .preceding = if (first == 0) null else event(@intCast(first - 1)) };
}
const Equation = struct {
    arena: std.heap.ArenaAllocator,
    circuit: G.Circuit,
    inputs: []Q,
    values: []Q,
    public_offset: usize,
    chunk_offset: usize,
    interaction_offset: usize,
    fn deinit(self: *Equation) void {
        self.circuit.deinit();
        self.arena.deinit();
    }
    fn evaluate(self: *Equation) !void {
        try self.circuit.evaluateInto(self.inputs, self.values);
    }
    fn reject(self: *Equation, index: usize) !void {
        const original = self.inputs[index];
        self.inputs[index] = original.add(Q.one());
        defer self.inputs[index] = original;
        try std.testing.expectError(error.UnsatisfiedCircuit, self.evaluate());
    }
};
fn input(b: *G.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), value: Q) !S {
    const symbol = try b.input();
    try inputs.append(a, value);
    return symbol.value;
}
fn equation(comptime family: Kernel.Family, a: std.mem.Allocator, claim: Geometry.Claim) !Equation {
    return equationAtLog(family, a, claim, null);
}
fn equationAtLog(comptime family: Kernel.Family, a: std.mem.Allocator, claim: Geometry.Claim, global_log: ?u32) !Equation {
    const Spec = Kernel.Spec(family);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var b = G.Builder.init(a);
    defer b.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var ch: R.Challenges(Q) = undefined;
    var challenges: [10]S = undefined;
    inline for (.{ "transition", "link", "interval", "range16" }, .{ 11, 13, 6, 1 }, 0..) |name, arity, i| {
        const z = scalar(501 + 4 * i);
        const alpha = scalar(502 + 4 * i);
        @field(ch, name) = .from(@import("../air/relation_challenges.zig").RelationElements(arity).init(z, alpha));
        challenges[2 * i] = try input(&b, temp, &inputs, z);
        challenges[2 * i + 1] = try input(&b, temp, &inputs, alpha);
    }
    const delta_z = scalar(751);
    const delta_alpha = scalar(752);
    const delta = R.Relation(Q, 5).from(@import("../air/relation_challenges.zig").RelationElements(5).init(delta_z, delta_alpha));
    challenges[8] = try input(&b, temp, &inputs, delta_z);
    challenges[9] = try input(&b, temp, &inputs, delta_alpha);
    var sums: [Kernel.planes(family)]Q = undefined;
    for (&sums, 0..) |*v, i| v.* = scalar(@intCast(30 + i));
    const row_log: u32 = switch (family) {
        .ram => claim.row_log,
        .range16 => 16,
        .terminal => 4,
        .interval => 7,
    };
    var output: [43]u8 = @splat(0);
    output[32] = 1;
    const halt = try @import("block_v7_halt_algebra_v1.zig").derive(.{ .final_cycle = 100, .halt_address = 0x100100, .length_address = 0x100104, .data_address = 0x100108, .output_end = 0x100180, .output = output });
    const spec = if (family == .ram) Spec{ .claim = claim, .sums = sums, .challenges = ch, .halt = halt, .delta = delta } else Spec{ .sums = sums, .challenges = ch };
    const max_log = global_log orelse row_log;
    const Adapter = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
    const component = Adapter{ .log_size = row_log, .spec = spec };
    const seed = scalar(71);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    var masks = try component.maskPoints(temp, point, max_log);
    defer masks.deinitDeep(temp);
    const concrete = try temp.alloc([][]Q, masks.items.len);
    const symbolic = try temp.alloc([][]S, masks.items.len);
    var interaction_offset: usize = undefined;
    for (masks.items, concrete, symbolic, 0..) |tree, *values, *symbols, t| {
        values.* = try temp.alloc([]Q, tree.len);
        symbols.* = try temp.alloc([]S, tree.len);
        for (tree, values.*, symbols.*, 0..) |column, *v, *s, i| {
            v.* = try temp.alloc(Q, column.len);
            s.* = try temp.alloc(S, column.len);
            for (v.*, s.*, 0..) |*x, *y, j| {
                if (t == 2 and i == 0 and j == 0) interaction_offset = inputs.items.len;
                x.* = scalar(@intCast(10 + t * 101 + i * 7 + j));
                y.* = try input(&b, temp, &inputs, x.*);
            }
        }
    }
    if (family == .ram) try checkScalarPrefix(spec, concrete);
    const randomness = scalar(17);
    var accumulated = core.air.accumulation.PointEvaluationAccumulator.init(randomness);
    if (global_log != null) accumulated.accumulate(scalar(901));
    var native_mask = core.air.components.MaskValues{ .items = concrete };
    try component.evaluateConstraintQuotientsAtPoint(point, &native_mask, &accumulated, max_log);
    const x0 = point.repeatedDouble(max_log - 1).x;
    const x1 = point.repeatedDouble(max_log).x;
    const tail: [3]Q = .{ scalar(33), scalar(34), scalar(35) };
    const chunk0 = accumulated.finalize().sub(x0.mul(tail[0])).sub(x1.mul(tail[1].add(x0.mul(tail[2]))));
    const public_offset = inputs.items.len;
    const public_values = if (family == .ram) try Kernel.ramPublic(claim, sums, halt) else sums;
    var public: [Kernel.publicCount(family)]S = undefined;
    for (&public, public_values) |*v, x| v.* = try input(&b, temp, &inputs, x);
    const random_symbol = try input(&b, temp, &inputs, randomness);
    const seed_symbol = try input(&b, temp, &inputs, seed);
    const chunk_offset = inputs.items.len;
    const chunks: [4]S = .{ try input(&b, temp, &inputs, chunk0), try input(&b, temp, &inputs, tail[0]), try input(&b, temp, &inputs, tail[1]), try input(&b, temp, &inputs, tail[2]) };
    var fixed: [Spec.FIXED_COUNT]S = undefined;
    var main: [Spec.MAIN_COUNT]S = undefined;
    var prior: [Spec.MAIN_COUNT]S = @splat(S.zero());
    var now: [Spec.INTERACTION_COUNT]S = undefined;
    var before: [Spec.INTERACTION_COUNT]S = undefined;
    for (&fixed, 0..) |*v, i| v.* = symbolic[0][i][0];
    for (&main, 0..) |*v, i| {
        v.* = symbolic[1][i][0];
        if (Spec.PREVIOUS_MAIN_MASK[i]) prior[i] = symbolic[1][i][1];
    }
    for (&now, &before, 0..) |*v, *p, i| {
        v.* = symbolic[2][i][0];
        p.* = symbolic[2][i][1];
    }
    try b.activate();
    var active = true;
    defer if (active) b.deactivate();
    var joint = if (global_log != null) S.fromSecure(scalar(901)) else S.zero();
    try Kernel.accumulate(family, row_log, max_log, fixed, main, prior, now, before, public, challenges, random_symbol, seed_symbol, &joint);
    const reconstructed = try G.reconstructSplitComposition(&chunks, G.pointFromSeed(seed_symbol), max_log + Spec.EXPANSION_BITS, Spec.EXPANSION_BITS);
    try b.constrainZero(reconstructed.sub(joint));
    b.deactivate();
    active = false;
    var circuit = try b.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = values, .public_offset = public_offset, .chunk_offset = chunk_offset, .interaction_offset = interaction_offset };
}
test "nonterminal window exact scalar quotient and symbolic graph bind all31 physical sums" {
    var e = try equation(.ram, std.testing.allocator, geometry(0, true));
    defer e.deinit();
    // Original161 equations remain, plus exactly two delta recurrences.
    try std.testing.expectEqual(@as(usize, 163), Kernel.Spec(.ram).CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 124), Kernel.Spec(.ram).INTERACTION_COUNT);
    for (0..29) |i| try e.reject(e.public_offset + i);
    try e.reject(e.public_offset + 84);
    try e.reject(e.public_offset + 85);
    for (0..4) |i| try e.reject(e.chunk_offset + i);
    // Each delta sum occupies one separate4-column prefix, never an aggregate.
    try e.reject(e.interaction_offset + 116 * 2);
    try e.reject(e.interaction_offset + 120 * 2);
    try e.evaluate();
}

test "nonterminal window OODS mixedlog Horner and public endpoints never choose code" {
    var baseline = try equationAtLog(.ram, std.testing.allocator, geometry(0, true), 16);
    defer baseline.deinit();
    for ([_]Geometry.Claim{ geometry(0, false), geometry(1, false), geometry(1, true) }) |claim| {
        var e = try equationAtLog(.ram, std.testing.allocator, claim, 16);
        defer e.deinit();
        try std.testing.expectEqualDeep(baseline.circuit.identity_digest, e.circuit.identity_digest);
        for ([_]usize{ 29, 38, 49, 60, 61, 66, 67, 68, 72, 76, 80, 84, 85 }) |offset| try e.reject(e.public_offset + offset);
        if (claim.first_event != 0) try e.reject(e.public_offset + 62);
        // Word.initial's z and alpha must be independent bound circuit inputs.
        try e.reject(8);
        try e.reject(9);
        try e.evaluate();
    }
}

fn checkScalarPrefix(spec: Kernel.Spec(.ram), mask: [][][]Q) !void {
    const Old = @import("block_v7_ram_component_v1.zig");
    const Window = @import("block_v7_window_ram_component_v1.zig");
    const Word = @import("../air/block/word_memory_v5.zig");
    const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
    var fixed: [24]Q = undefined;
    var row: [88]Q = undefined;
    var previous_row: [88]Q = @splat(Q.zero());
    var current: [124]Q = undefined;
    var previous: [124]Q = undefined;
    for (&fixed, 0..) |*v, i| v.* = mask[0][i][0];
    for (&row, 0..) |*v, i| {
        v.* = mask[1][i][0];
        if (Old.Spec.PREVIOUS_MAIN_MASK[i]) previous_row[i] = mask[1][i][1];
    }
    for (&current, &previous, 0..) |*v, *p, i| {
        v.* = mask[2][i][0];
        p.* = mask[2][i][1];
    }
    const size = @as(u32, 1) << @intCast(spec.claim.row_log);
    const actual = try spec.evaluate(fixed, row, previous_row, current, previous, size);
    const original = try (Old.Spec{ .claim = spec.claim, .halt = spec.halt, .sums = spec.sums[0..29].*, .challenges = spec.challenges }).evaluate(fixed, row, previous_row, current[0..116].*, previous[0..116].*, size);
    try std.testing.expectEqualDeep(original, actual[0..161].*);
    const lanes = Trace.fixedPoint(Q, fixed, spec.claim);
    const rows = Old.rows(Q, row);
    const normalized = try R.normalize(2, spec.sums[29..31].*, size);
    const delta = Window.deltaEquations(Q, lanes, row, current[116..124].*, previous[116..124].*, spec.delta, normalized);
    for (rows, lanes, 0..) |values, lane, i| {
        // Independent explicit snapshot tuple: (space,address low/high,value
        // low/high). After contributes positively; before negatively. These
        // are secure arbitrary OODS samples, not Boolean/fixed base rows.
        const key = .{values[Word.Layout.current_key + 2]} ++ values[Word.Layout.current_key..][0..2].*;
        const after = spec.delta.combineSecure(key ++ values[Word.Layout.after..][0..2].*);
        const before = spec.delta.combineSecure(key ++ values[Word.Layout.before..][0..2].*);
        const at = 116 + 4 * i;
        const change = Q.fromPartialEvals(current[at..][0..4].*).sub(Q.fromPartialEvals(previous[at..][0..4].*)).add(normalized[i]);
        const expected = change.mul(after).mul(before).sub(lane.active.mul(before)).add(lane.active.mul(after));
        try std.testing.expectEqualDeep(expected, delta[i]);
        try std.testing.expectEqualDeep(expected, actual[161 + i]);
    }
}

test "nonterminal window delta challenge is exact epoch Word initial pair49" {
    const E = @import("block_v7_execution_epoch_v1.zig");
    const Word = @import("block_v5_word_memory_protocol_v1.zig");
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    const entries = [_]E.Entry{
        try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)}),
        try E.Entry.init(.window_memory_joint, 0, @splat(3), &.{ @splat(4), @splat(5) }),
    };
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    counts[@intFromEnum(E.Family.window_memory_joint)] = 1;
    const epoch = try E.Epoch.init(@splat(6), config, counts, &entries, entries.len);
    const drawn = try epoch.draw(a);
    var channel = epoch.sharedChannel();
    const words = try Word.Challenges.drawFromChannel(a, &channel);
    try std.testing.expectEqualDeep(words.initial, drawn.word.initial);
    try std.testing.expectEqual(@as(usize, 49), Kernel.relation_pair_indices[4]);
    const delta = R.Relation(Q, 5).from(drawn.word.initial);
    try std.testing.expectEqualDeep(words.initial.z, delta.z);
    try std.testing.expectEqualDeep(words.initial.alpha, delta.powers[1]);
    try std.testing.expectEqualDeep(Q.one(), delta.powers[0]);
    for (delta.powers, 0..) |power, i| {
        var expected = Q.one();
        for (0..i) |_| expected = expected.mul(words.initial.alpha);
        try std.testing.expectEqualDeep(expected, power);
    }
}
