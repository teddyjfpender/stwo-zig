//! Arbitrary OODS parity against the actual original quotient adapter. These
//! tests qualify the equation kernels, not a recursive proof or publication.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const R = @import("block_v7_memory_relations_v1.zig");
const G = @import("../recursion/air/composition_graph_recorder.zig");
const S = G.Scalar;
const Kernel = @import("../recursion/air/block_v7_memory_composition_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
test "v7 memory composition joint compiler lifecycle codegen" {
    std.mem.doNotOptimizeAway(&@import("../recursion/air/block_v7_memory_joint_composition_v1.zig").compile);
}
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
    var challenges: [8]S = undefined;
    inline for (.{ "transition", "link", "interval", "range16" }, .{ 11, 13, 6, 1 }, 0..) |name, arity, i| {
        const z = scalar(501 + 4 * i);
        const alpha = scalar(502 + 4 * i);
        @field(ch, name) = .from(@import("../air/relation_challenges.zig").RelationElements(arity).init(z, alpha));
        challenges[2 * i] = try input(&b, temp, &inputs, z);
        challenges[2 * i + 1] = try input(&b, temp, &inputs, alpha);
    }
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
    const spec = if (family == .ram) Spec{ .claim = claim, .sums = sums, .challenges = ch, .halt = halt } else Spec{ .sums = sums, .challenges = ch };
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
    if (global_log == null) try coldParity(family, a, row_log, concrete, public_values, randomness, seed, .{ chunk0, tail[0], tail[1], tail[2] });
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
    if (global_log != null) {
        var joint = S.fromSecure(scalar(901));
        try Kernel.accumulate(family, row_log, max_log, fixed, main, prior, now, before, public, challenges, random_symbol, seed_symbol, &joint);
        const reconstructed = try G.reconstructSplitComposition(&chunks, G.pointFromSeed(seed_symbol), max_log + Spec.EXPANSION_BITS, Spec.EXPANSION_BITS);
        try b.constrainZero(reconstructed.sub(joint));
    } else try Kernel.recordEquation(family, &b, row_log, fixed, main, prior, now, before, public, challenges, random_symbol, seed_symbol, chunks);
    b.deactivate();
    active = false;
    var circuit = try b.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = values, .public_offset = public_offset, .chunk_offset = chunk_offset, .interaction_offset = interaction_offset };
}
fn coldParity(comptime family: Kernel.Family, a: std.mem.Allocator, row_log: u32, native_samples: [][][]Q, public: [Kernel.publicCount(family)]Q, randomness: Q, seed: Q, chunks: [4]Q) !void {
    const Cold = @import("../recursion/air/block_v7_memory_shape_composition_v1.zig").For(family);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    const shape = try Cold.Shape.init(a, row_log, config, .{});
    defer shape.deinit();
    var compiled = try Cold.compile(a, shape);
    defer compiled.deinit();
    try compiled.validateAgainst(shape);
    var samples: std.ArrayList(Q) = .empty;
    defer samples.deinit(a);
    for (native_samples) |tree| for (tree) |column| try samples.appendSlice(a, column);
    for (chunks) |chunk| for (chunk.toM31Array()) |limb| try samples.append(a, Q.fromBase(limb));
    try std.testing.expectEqual(try shape.sampleCount(), samples.items.len);
    var challenge_values: [106]Q = @splat(Q.zero());
    for (Kernel.relation_pair_indices, 0..) |pair, i| {
        challenge_values[2 * pair] = scalar(@intCast(501 + 4 * i));
        challenge_values[2 * pair + 1] = scalar(@intCast(502 + 4 * i));
    }
    const values = try a.alloc(Q, compiled.circuit.nodes.len);
    defer a.free(values);
    const inputs = try a.alloc(Q, compiled.sources.len);
    defer a.free(inputs);
    for (inputs, compiled.sources) |*v, source| v.* = switch (source) {
        .sample => |i| samples.items[i],
        .challenge => |i| challenge_values[i],
        .public_input => |i| public[i],
        .composition => randomness,
        .oods => seed,
        else => return error.UnexpectedV7CompositionSource,
    };
    try compiled.circuit.evaluateInto(inputs, values);
    // A self-consistent mutable source map cannot become an independent key.
    compiled.sources[0] = .{ .sample = 1 };
    compiled.seal = compiled.identity();
    try std.testing.expectError(error.UntrustedV7MemoryComposition, compiled.validateAgainst(shape));
}
test "v7 memory composition exact original quotients for all four families and physical sum mutations" {
    inline for (comptime std.meta.tags(Kernel.Family)) |family| {
        var e = try equation(family, std.testing.allocator, geometry(0, true));
        defer e.deinit();
        for (0..Kernel.planes(family)) |i| try e.reject(e.public_offset + i);
        for (0..4) |i| try e.reject(e.chunk_offset + i);
        try e.reject(e.interaction_offset);
        try e.evaluate();
    }
}
test "v7 memory composition RAM endpoint geometry does not choose graph and incoming link is constrained" {
    var baseline = try equation(.ram, std.testing.allocator, geometry(0, true));
    defer baseline.deinit();
    for ([_]Geometry.Claim{ geometry(0, false), geometry(1, false), geometry(1, true) }) |claim| {
        var e = try equation(.ram, std.testing.allocator, claim);
        defer e.deinit();
        try std.testing.expectEqualDeep(baseline.circuit.identity_digest, e.circuit.identity_digest);
        for ([_]usize{ 29, 38, 49, 60, 61, 66, 67, 68, 72, 76, 80 }) |offset| try e.reject(e.public_offset + offset);
        if (claim.first_event != 0) try e.reject(e.public_offset + 62);
    }
}
test "v7 memory composition challenge ports match the actual whole execution epoch" {
    const E = @import("block_v7_execution_epoch_v1.zig");
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    const entries = [_]E.Entry{try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)})};
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    const epoch = try E.Epoch.init(@splat(3), config, counts, &entries, entries.len);
    const drawn = try epoch.draw(a);
    var ports: [106]Q = undefined;
    for (drawn.word.universal_prefix.elements, 0..) |element, i| {
        ports[2 * i] = element.z;
        ports[2 * i + 1] = element.alpha;
    }
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
        ports[94 + 2 * i] = @field(drawn.word, name).z;
        ports[95 + 2 * i] = @field(drawn.word, name).alpha;
    }
    var channel = epoch.sharedChannel();
    _ = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ 0x4237494e, E.VERSION, 6 });
    ports[104] = channel.drawSecureFelt();
    ports[105] = channel.drawSecureFelt();
    try std.testing.expectEqualDeep(channel, drawn.channel);
    inline for (.{ "transition", "link", "interval", "range16" }, 0..) |name, i| {
        const relation = @field(drawn.memory, name);
        const pair = Kernel.relation_pair_indices[i];
        try std.testing.expect(relation.z.eql(ports[2 * pair]));
        try std.testing.expect(relation.powers[0].eql(Q.one()));
        if (relation.powers.len > 1) try std.testing.expect(relation.powers[1].eql(ports[2 * pair + 1]));
    }
}
test "v7 memory composition heterogeneous logs preserve original joint Horner accumulator" {
    inline for (comptime std.meta.tags(Kernel.Family)) |family| {
        var e = try equationAtLog(family, std.testing.allocator, geometry(1, true), 16);
        defer e.deinit();
        try e.reject(e.public_offset);
        try e.reject(e.chunk_offset);
        try e.reject(e.interaction_offset);
        try e.evaluate();
    }
}
