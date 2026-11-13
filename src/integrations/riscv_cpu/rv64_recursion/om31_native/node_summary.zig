//! Typed public statements for fold v3. Authentication remains the caller's
//! obligation: bind child outputs AND verify their proof/T_rec membership.
//! Native.chi is a Blake digest, kept as raw words exactly as native FS uses
//! it. Bus coordinates and integer fields instead have canonical M31 encoding.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const Public = @import("frame.zig");
const Bounds = @import("../node_summary.zig");
const Types = @import("../../word16_global_execution/services/types.zig");
const B = circuit.builder;
const Word = Public.Word;
const Digest = [32]u8;
pub const VERSION: u32 = 3;
/// Separate CPU-call and truth-consumption counters, then sponge, CPU ordinal,
/// and two raw address limbs for the optional memory-boundary class.
pub const COUNTERS = 2 * Types.FAMILIES + 4;
pub const Index = struct {
    pub const header = 0;
    pub const tnat = 2;
    pub const trec = tnat + 8;
    pub const image = trec + 8;
    pub const statement = image + 8;
    pub const chi = statement + 8;
    pub const lo = chi + 8;
    pub const hi = lo + 1;
    pub const count = hi + 1;
    pub const m_in = count + 1;
    pub const m_out = m_in + 8;
    pub const s_in = m_out + 8;
    pub const s_out = s_in + 8;
    pub const bus = s_out + 8;
    pub const mass = bus + 24;
    pub const ctr_in = mass + 3;
    pub const ctr_out = ctr_in + COUNTERS;
    pub const steps_in = ctr_out + COUNTERS;
    pub const steps_out = steps_in + 1;
    pub const expected = steps_out + 1;
    pub const output = expected + 8;
    pub const output_seen = output + 8;
    pub const depth = output_seen + 1;
};
pub const N_WORDS = Index.depth + 1;
pub const Native = struct {
    tnat: Digest,
    trec: Digest,
    image: Digest,
    statement: Digest,
    chi: Digest,
    lo: u32,
    hi: u32,
    count: u32,
    m_in: Digest,
    m_out: Digest,
    s_in: Digest,
    s_out: Digest,
    bus: [3]C.O,
    mass: [3]u32,
    ctr_in: [COUNTERS]u32,
    ctr_out: [COUNTERS]u32,
    steps_in: u32,
    steps_out: u32,
    expected: Digest,
    output: Digest,
    output_seen: bool,
    depth: u32,

    pub fn words(self: Native) [N_WORDS]u32 {
        var out: [N_WORDS]u32 = undefined;
        out[0] = VERSION;
        out[1] = N_WORDS;
        inline for (.{ "tnat", "trec", "image", "statement", "chi", "m_in", "m_out", "s_in", "s_out", "expected", "output" }) |name| {
            const digest = @field(self, name);
            for (0..8) |i| out[@field(Index, name) + i] = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        }
        inline for (.{ "lo", "hi", "count", "steps_in", "steps_out", "depth" }) |name| out[@field(Index, name)] = @field(self, name);
        for (self.bus, 0..) |value, relation| for (value.toM31Array(), 0..) |coordinate, i| {
            out[Index.bus + 8 * relation + i] = coordinate.v;
        };
        @memcpy(out[Index.mass..][0..3], &self.mass);
        @memcpy(out[Index.ctr_in..][0..COUNTERS], &self.ctr_in);
        @memcpy(out[Index.ctr_out..][0..COUNTERS], &self.ctr_out);
        out[Index.output_seen] = @intFromBool(self.output_seen);
        return out;
    }
    pub fn fromWords(raw: []const u32) !Native {
        if (raw.len != N_WORDS or raw[0] != VERSION or raw[1] != N_WORDS) return error.TypedSummaryHeader;
        var out: Native = undefined;
        inline for (.{ "tnat", "trec", "image", "statement", "chi", "m_in", "m_out", "s_in", "s_out", "expected", "output" }) |name| {
            for (0..8) |i| std.mem.writeInt(u32, @field(out, name)[4 * i ..][0..4], raw[@field(Index, name) + i], .little);
        }
        inline for (.{ "lo", "hi", "count", "steps_in", "steps_out", "depth" }) |name| @field(out, name) = raw[@field(Index, name)];
        for (&out.bus, 0..) |*value, relation| {
            var coordinates: [8]@import("stwo_core").fields.m31.M31 = undefined;
            for (&coordinates, 0..) |*coordinate, i| {
                const word = raw[Index.bus + 8 * relation + i];
                if (word >= Bounds.P) return error.NoncanonicalSummaryCoordinate;
                coordinate.* = .fromCanonical(word);
            }
            value.* = C.O.fromM31Array(coordinates);
        }
        @memcpy(&out.mass, raw[Index.mass..][0..3]);
        @memcpy(&out.ctr_in, raw[Index.ctr_in..][0..COUNTERS]);
        @memcpy(&out.ctr_out, raw[Index.ctr_out..][0..COUNTERS]);
        if (raw[Index.output_seen] > 1) return error.TypedSummaryOutputPresence;
        out.output_seen = raw[Index.output_seen] == 1;
        for (out.mass) |mass| if (mass >= Bounds.P) return error.NoncanonicalSummaryInteger;
        for ([_][]const u32{ out.ctr_in[0 .. COUNTERS - 2], out.ctr_out[0 .. COUNTERS - 2], &.{ out.lo, out.hi, out.count, out.steps_in, out.steps_out, out.depth } }) |integers| {
            for (integers) |integer| if (integer >= Bounds.P) return error.NoncanonicalSummaryInteger;
        }
        if (out.lo > out.hi or out.hi >= Bounds.MAX_PROOFS or out.count != out.hi - out.lo + 1 or out.depth > Bounds.D_MAX) return error.TypedSummaryBounds;
        if (!out.output_seen and !std.mem.allEqual(u8, &out.output, 0)) return error.TypedSummaryAbsentOutput;
        return out;
    }
    pub fn fromOutputs(outputs: []const C.Q) !Native {
        if (outputs.len != N_WORDS) return error.TypedSummaryOutputCount;
        var raw: [N_WORDS]u32 = undefined;
        for (&raw, outputs) |*word, value| {
            const coordinates = value.toM31Array();
            if (coordinates[0].v > 0xffff or coordinates[1].v > 0xffff or coordinates[2].v != 0 or coordinates[3].v != 0) return error.TypedSummaryRawWord;
            word.* = coordinates[0].v | (coordinates[1].v << 16);
        }
        return fromWords(&raw);
    }
    /// Honest assignment only; every equality is also enforced in `combine`.
    pub fn combine(children: []const Native) !Native {
        if (children.len < 2 or children.len > 4) return error.InvalidFoldArity;
        var out = children[0];
        const last = children[children.len - 1];
        out.hi = last.hi;
        out.m_out = last.m_out;
        out.s_out = last.s_out;
        out.ctr_out = last.ctr_out;
        out.steps_out = last.steps_out;
        out.count = 0;
        out.bus = @splat(C.O.zero());
        out.mass = @splat(0);
        out.output_seen = false;
        out.output = @splat(0);
        out.depth = 0;
        for (children) |child| {
            out.count = try std.math.add(u32, out.count, child.count);
            out.depth = @max(out.depth, child.depth);
            for (&out.bus, child.bus) |*sum, value| sum.* = sum.add(value);
            for (&out.mass, child.mass) |*sum, value| {
                sum.* = try std.math.add(u32, sum.*, value);
                if (sum.* >= Bounds.P) return error.MassExceedsCharacteristic;
            }
            if (child.output_seen) {
                if (out.output_seen) return error.DuplicateTerminalOutput;
                out.output = child.output;
                out.output_seen = true;
            }
        }
        out.depth = try std.math.add(u32, out.depth, 1);
        return out;
    }
};
pub const Wires = struct {
    raw: [N_WORDS]Word,
    assignment: Native,
    pub fn guess(ctx: *C.Context, native: Native) !Wires {
        var self: Wires = .{ .raw = undefined, .assignment = native };
        for (&self.raw, native.words()) |*out, value| out.* = try B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, value));
        try self.validate(ctx);
        return self;
    }
    pub fn bind(ctx: *C.Context, outputs: []const C.Var, native: Native) !Wires {
        if (outputs.len != N_WORDS) return error.TypedSummaryOutputCount;
        const self = try guess(ctx, native);
        for (self.raw, outputs) |word, output| try ctx.eq(word.get(), output);
        return self;
    }
    /// Reduce then demand the unique canonical raw encoding. A u32 p aliases
    /// zero under reduction, but fails the round-trip equality below.
    pub fn integer(self: Wires, ctx: *C.Context, index: usize) !C.Var {
        const base = try circuit.native_verifier.channel.wordToM31(C.Q, ctx, self.raw[index]);
        const canonical = try B.blake.m31ToU32(C.Q, ctx, base);
        try ctx.eq(canonical.get(), self.raw[index].get());
        return base;
    }
    pub fn secure(self: Wires, ctx: *C.Context, relation: usize) !C.F {
        var coordinates: [8]C.Var = undefined;
        for (&coordinates, 0..) |*out, i| out.* = try self.integer(ctx, Index.bus + 8 * relation + i);
        return C.F.wire(try B.ops.fromPartialEvals(C.Q, ctx, coordinates[0..4].*), try B.ops.fromPartialEvals(C.Q, ctx, coordinates[4..8].*));
    }
    fn massLimbs(self: Wires, ctx: *C.Context, relation: usize) !Bounds.Mass {
        _ = try self.integer(ctx, Index.mass + relation);
        const encoded = [1]C.Var{self.raw[Index.mass + relation].get()};
        const lanes = B.simd.Simd.fromPacked(&encoded, 2);
        return .{ .lo = try B.simd.unpackIdx(C.Q, ctx, lanes, 0), .hi = try B.simd.unpackIdx(C.Q, ctx, lanes, 1) };
    }
    fn validate(self: Wires, ctx: *C.Context) !void {
        try ctx.eq(self.raw[0].get(), (try B.wrappers.constU32(C.Q, ctx, VERSION)).get());
        try ctx.eq(self.raw[1].get(), (try B.wrappers.constU32(C.Q, ctx, N_WORDS)).get());
        const lo = try self.integer(ctx, Index.lo);
        const hi = try self.integer(ctx, Index.hi);
        const w = Bounds.intervalWitness(self.assignment.lo, self.assignment.hi);
        try Bounds.rangeBits(ctx, lo, 16, w.lo_bits);
        try Bounds.rangeBits(ctx, try ctx.sub(hi, lo), 16, w.span_bits);
        const max_index = try ctx.constant(C.Q.fromU32Unchecked(Bounds.MAX_PROOFS - 1, 0, 0, 0));
        try Bounds.rangeBits(ctx, try ctx.sub(max_index, hi), 16, w.rest_bits);
        const count = try self.integer(ctx, Index.count);
        try ctx.eq(count, try ctx.add(try ctx.sub(hi, lo), ctx.one()));
        for (0..3) |relation| {
            _ = try self.secure(ctx, relation);
            _ = try self.massLimbs(ctx, relation);
        }
        // Address counters are raw u32 limbs, never added in M31. All other
        // counters/step totals are < p under this named profile's admission.
        for (0..COUNTERS - 2) |i| {
            _ = try self.integer(ctx, Index.ctr_in + i);
            _ = try self.integer(ctx, Index.ctr_out + i);
        }
        _ = try self.integer(ctx, Index.steps_in);
        _ = try self.integer(ctx, Index.steps_out);
        const depth = try self.integer(ctx, Index.depth);
        try Bounds.rangeBits(ctx, depth, 4, Bounds.bitsOf(self.assignment.depth, 4));
        const max_depth = try ctx.constant(C.Q.fromU32Unchecked(Bounds.D_MAX, 0, 0, 0));
        try Bounds.rangeBits(ctx, try ctx.sub(max_depth, depth), 4, Bounds.bitsOf(@as(u64, Bounds.D_MAX) -% self.assignment.depth, 4));
        const seen = try self.integer(ctx, Index.output_seen);
        try ctx.eq(try ctx.mul(seen, seen), seen);
        const absent = try ctx.sub(ctx.one(), seen);
        for (self.raw[Index.output..][0..8]) |word| try ctx.eq(try ctx.mul(word.get(), absent), ctx.zero());
    }
};
fn equalRange(ctx: *C.Context, left: Wires, right: Wires, begin: usize, count: usize) !void {
    for (left.raw[begin..][0..count], right.raw[begin..][0..count]) |l, r| try ctx.eq(l.get(), r.get());
}
/// Circuit combine, with no host acceptance shortcut. The parent is itself a
/// range-checked public statement; caller must expose its raw words as outputs.
pub fn combine(ctx: *C.Context, children: []const Wires, parent: Wires) !void {
    if (children.len < 2 or children.len > 4) return error.InvalidFoldArity;
    const first = children[0];
    const last = children[children.len - 1];
    for (children) |child| {
        try equalRange(ctx, child, parent, Index.tnat, 40);
        try equalRange(ctx, child, parent, Index.expected, 8);
    }
    for (children[0 .. children.len - 1], children[1..]) |left, right| {
        try ctx.eq(try right.integer(ctx, Index.lo), try ctx.add(try left.integer(ctx, Index.hi), ctx.one()));
        for (0..8) |i| {
            try ctx.eq(left.raw[Index.m_out + i].get(), right.raw[Index.m_in + i].get());
            try ctx.eq(left.raw[Index.s_out + i].get(), right.raw[Index.s_in + i].get());
        }
        for (0..COUNTERS) |i| try ctx.eq(left.raw[Index.ctr_out + i].get(), right.raw[Index.ctr_in + i].get());
        try ctx.eq(left.raw[Index.steps_out].get(), right.raw[Index.steps_in].get());
    }
    try ctx.eq(parent.raw[Index.lo].get(), first.raw[Index.lo].get());
    try ctx.eq(parent.raw[Index.hi].get(), last.raw[Index.hi].get());
    inline for (.{ Index.m_in, Index.s_in }) |index| try equalRange(ctx, parent, first, index, 8);
    inline for (.{ Index.m_out, Index.s_out }) |index| try equalRange(ctx, parent, last, index, 8);
    try equalRange(ctx, parent, first, Index.ctr_in, COUNTERS);
    try equalRange(ctx, parent, last, Index.ctr_out, COUNTERS);
    try equalRange(ctx, parent, first, Index.steps_in, 1);
    try equalRange(ctx, parent, last, Index.steps_out, 1);
    var counts: [4]C.Var = undefined;
    var count_values: [4]u64 = undefined;
    var depths: [4]C.Var = undefined;
    var depth_values: [4]u64 = undefined;
    var seen = ctx.zero();
    var output: [8]C.Var = @splat(ctx.zero());
    for (children, 0..) |child, i| {
        counts[i] = try child.integer(ctx, Index.count);
        count_values[i] = child.assignment.count;
        depths[i] = try child.integer(ctx, Index.depth);
        depth_values[i] = child.assignment.depth;
        seen = try ctx.add(seen, try child.integer(ctx, Index.output_seen));
        for (&output, child.raw[Index.output..][0..8]) |*sum, word| sum.* = try ctx.add(sum.*, word.get());
    }
    try ctx.eq(try parent.integer(ctx, Index.count), try Bounds.foldKappa(ctx, counts[0..children.len], count_values[0..children.len]));
    try ctx.eq(try parent.integer(ctx, Index.depth), try Bounds.foldDepth(ctx, depths[0..children.len], Bounds.depthWitness(depth_values[0..children.len])));
    try ctx.eq(try parent.integer(ctx, Index.output_seen), seen);
    for (parent.raw[Index.output..][0..8], output) |word, sum| try ctx.eq(word.get(), sum);
    for (0..3) |relation| {
        var sum = C.F.zero();
        var masses: [4]Bounds.Mass = undefined;
        var mass_values: [4]u64 = undefined;
        for (children, 0..) |child, i| {
            sum = sum.add(try child.secure(ctx, relation));
            masses[i] = try child.massLimbs(ctx, relation);
            mass_values[i] = child.assignment.mass[relation];
        }
        try C.eq(ctx, sum, try parent.secure(ctx, relation));
        const total = try Bounds.foldMass(ctx, masses[0..children.len], try Bounds.massWitness(mass_values[0..children.len]));
        const actual = try parent.massLimbs(ctx, relation);
        try ctx.eq(total.lo, actual.lo);
        try ctx.eq(total.hi, actual.hi);
    }
    try C.lane.check();
}

fn sample(index: u32) Native {
    return .{ .tnat = @splat(1), .trec = @splat(2), .image = @splat(3), .statement = @splat(4), .chi = @splat(5), .lo = index, .hi = index, .count = 1, .m_in = @splat(@intCast(index)), .m_out = @splat(@intCast(index + 1)), .s_in = @splat(@intCast(index + 8)), .s_out = @splat(@intCast(index + 9)), .bus = @splat(C.O.fromBase(@import("stwo_core").fields.m31.M31.fromCanonical(index + 1))), .mass = .{ 7, 11, 13 }, .ctr_in = @splat(index), .ctr_out = @splat(index + 1), .steps_in = index * 10, .steps_out = (index + 1) * 10, .expected = @splat(6), .output = if (index == 3) @splat(41) else @splat(0), .output_seen = index == 3, .depth = 0 };
}
test "fold-v3 typed combine binds agreements adjacency counters mass and unique output" {
    const honest = [_]Native{ sample(0), sample(1), sample(2), sample(3) };
    const parent = try Native.combine(&honest);
    for (0..11) |mutation| {
        var values = honest;
        var expected = parent;
        switch (mutation) {
            0 => {},
            1 => values[1].chi[0] ^= 1,
            2 => values[1].lo = 0,
            3 => values[1].ctr_in[0] += 1,
            4 => values[1].s_in[2] ^= 1,
            5 => values[2].steps_in += 1,
            6 => values[1].tnat[0] ^= 1,
            7 => expected.mass[1] -= 1,
            8 => {
                values[0].output_seen = true;
                values[0].output = @splat(1);
            },
            9 => expected.depth = @intCast(Bounds.P - 1),
            10 => values[1].ctr_in[0] = @intCast(Bounds.P),
            else => unreachable,
        }
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        var children: [4]Wires = undefined;
        for (&children, values) |*out, value| out.* = try Wires.guess(&ctx, value);
        const output = try Wires.guess(&ctx, expected);
        try combine(&ctx, &children, output);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
test "fold-v3 summary receiver refuses alternate encodings and malformed headers" {
    const input = sample(0);
    const raw = input.words();
    try std.testing.expectEqualDeep(input, try Native.fromWords(&raw));
    var outputs: [N_WORDS]C.Q = undefined;
    for (&outputs, raw) |*out, word| out.* = B.ivalue.packU32(C.Q, word);
    try std.testing.expectEqualDeep(input, try Native.fromOutputs(&outputs));
    for ([_]usize{ 0, 1, Index.bus, Index.mass, Index.ctr_in, Index.output_seen, Index.depth }) |index| {
        var bad = raw;
        bad[index] = if (index == Index.depth) @intCast(Bounds.P - 1) else @intCast(Bounds.P);
        if (Native.fromWords(&bad)) |_| return error.BadSummaryAccepted else |_| {}
    }
    outputs[0] = C.Q.fromU32Unchecked(VERSION, 0, 1, 0);
    try std.testing.expectError(error.TypedSummaryRawWord, Native.fromOutputs(&outputs));
}

pub const Counter = struct {
    pub const cpu_calls = 0;
    pub const truth_next = Types.FAMILIES;
    pub const sponge_next = 2 * Types.FAMILIES;
    pub const cpu_next = sponge_next + 1;
    pub const boundary_lo = cpu_next + 1;
    pub const boundary_hi = boundary_lo + 1;
};
