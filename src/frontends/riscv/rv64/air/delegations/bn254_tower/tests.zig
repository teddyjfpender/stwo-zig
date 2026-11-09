//! Independent polynomial and carried-integer qualification of the OP candidate.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("../curves/spec.zig");
const C = @import("../curves/mod.zig");
const S = @import("spec.zig");
const Exec = S.execution;
const H = @import("../curves/tests.zig").Harness(Exec.Kind.mul034);
const N = H.N;
const Q = core.fields.qm31.QM31;
const Z = i1024;
const P = Base.BN254_P;

/// Formal monomial reduction. This does not use the executor's Fq2/Fq6
/// products or the AIR's static list of 88 product terms.
fn term(out: *[12]Z, i: usize, u: usize, w: usize, coefficient: Z) void {
    if (w >= 2) return term(out, i, u + 1, w - 2, coefficient);
    if (u >= 3) {
        term(out, i, u - 3, w, 9 * coefficient);
        return term(out, i + 1, u - 3, w, coefficient);
    }
    if (i >= 2) return term(out, i - 2, u, w, -coefficient);
    out[2 * (u + 3 * w) + i] += coefficient;
}
fn oracle(input: *const [20]u256) [12]u256 {
    var coefficients: [12]Z = @splat(0);
    for (0..12) |a| for ([_]usize{ 0, 3, 4 }, 0..) |place, b| for (0..2) |part| {
        term(&coefficients, a % 2 + part, a / 2 % 3 + place % 3, a / 6 + place / 3, @as(Z, input[a]) * input[12 + 2 * b + part] * (if (b == 0) @as(Z, input[19]) else if (b == 1) @as(Z, input[18]) else 1));
    };
    var result: [12]u256 = undefined;
    for (&result, coefficients) |*dst, x| dst.* = @intCast(@mod(x, @as(Z, P)));
    return result;
}
fn packet(input: *const [20]u256) N.Packet {
    var values: [20]Base.Big = undefined;
    for (&values, input.*) |*dst, x| dst.* = x;
    return H.packetOf(&values);
}
fn qualify(input: *const [20]u256) !void {
    const expected = oracle(input);
    try std.testing.expectEqual(expected, Exec.compute(input));
    var main: [H.L.MAIN]Q = undefined;
    const p = packet(input);
    const witness = try H.rowOf(&p, &main);
    for (witness.out, expected) |x, y| try std.testing.expectEqual(@as(Base.Big, y), x);
    try std.testing.expect(H.accepted(&main));
}

test "OP sparse034 explicit ABI and independent basis polynomial agree" {
    // Every one of the 72 input basis products, plus maximal/noncanonical
    // byte-bounded representatives, exercises all signs/nonresidue placements.
    for (0..12) |a| for (0..6) |b| {
        var input: [20]u256 = @splat(0);
        input[a] = 1;
        input[12 + b] = 1;
        input[18] = 1;
        input[19] = 1;
        try qualify(&input);
    };
    for ([_]u256{ 0, 1, P - 1, P, P + 1, std.math.maxInt(u256) }) |v| {
        const input: [20]u256 = @splat(v);
        try qualify(&input);
    }
    var rng = std.Random.DefaultPrng.init(0x5350415253453033);
    for (0..16) |_| {
        var input: [20]u256 = undefined;
        for (&input) |*x| x.* = rng.random().int(u256);
        try qualify(&input);
    }
}

test "OP sparse034 carried relations reject forged outputs canonicality and carries" {
    var input: [20]u256 = undefined;
    for (&input, 0..) |*x, i| x.* = (@as(u256, 1) << 247) + 731 * i + 29;
    const p = packet(&input);
    var main: [H.L.MAIN]Q = undefined;
    const honest = try H.rowOf(&p, &main);
    var outputs: [12][32]i64 = undefined;
    for (&outputs, honest.out) |*out, x| out.* = H.bytesOf(x);
    var witnesses: [14][32]i64 = undefined;
    for (&witnesses, honest.wit) |*out, x| out.* = H.bytesOf(x);
    for (0..12) |j| {
        const old = outputs[j];
        outputs[j][0] ^= 1;
        H.forge(&p, &outputs, &witnesses, &main);
        try std.testing.expect(!H.accepted(&main));
        outputs[j] = H.bytesOf(honest.out[j] + P);
        H.forge(&p, &outputs, &witnesses, &main);
        try std.testing.expect(!H.accepted(&main));
        outputs[j] = old;
    }
    for (0..14) |j| {
        const old = witnesses[j];
        witnesses[j][0] ^= 1;
        H.forge(&p, &outputs, &witnesses, &main);
        try std.testing.expect(!H.accepted(&main));
        witnesses[j] = old;
    }
    inline for (0..H.L.RELATIONS) |r| {
        _ = try H.rowOf(&p, &main);
        main[H.L.CARRY[r]] = main[H.L.CARRY[r]].add(Q.one());
        try std.testing.expect(!H.accepted(&main));
    }
    _ = try H.rowOf(&p, &main);
    main[H.L.ACTIVE] = Q.fromBase(core.fields.m31.M31.fromCanonical(2));
    try std.testing.expect(!H.accepted(&main));
}

test "OP sparse034 bounded executor preserves the read-only line and refuses wrong size" {
    var before: [Exec.WORDS]u64 = undefined;
    for (&before, 0..) |*x, i| x.* = 0x9e3779b97f4a7c15 *% (i + 1);
    const after = try Exec.execute(&before);
    try std.testing.expectEqualSlices(u64, before[Exec.WRITTEN_WORDS..], after[Exec.WRITTEN_WORDS..]);
    try std.testing.expectError(error.TowerPacketShape, Exec.execute(before[0 .. Exec.WORDS - 1]));
    // Legacy per-call captures retain their existing bounded width and roster.
    const legacy = @import("../../../ethereum_services/curves.zig");
    try std.testing.expectEqual(@as(usize, 24), legacy.MAX_WORDS);
    try std.testing.expect(legacy.opOfTag(Exec.TAG) == null);
    try std.testing.expect(H.L.MAIN + H.L.INTERACTION < 13 * (C.Layout(.bn254_fp2_mul).MAIN + C.Layout(.bn254_fp2_mul).INTERACTION));
    std.debug.print("OP_TOWER_COST main={} inter={} constraints={} byte_queries={} legacy13_cells={} candidate_cells={} degree={}\n", .{ H.L.MAIN, H.L.INTERACTION, H.L.CONSTRAINTS, H.L.BYTE_QUERIES, 13 * (C.Layout(.bn254_fp2_mul).MAIN + C.Layout(.bn254_fp2_mul).INTERACTION), H.L.MAIN + H.L.INTERACTION, H.L.DEGREE });
}

test "OP sparse034 source-owned asymmetric carry intervals are complete and strictly nonwrapping" {
    @setEvalBranchQuota(1000000);
    inline for (H.L.GEOMETRY, 0..) |g, r| {
        const range = @as(u64, 1) << @intCast(g.carry_bits);
        try std.testing.expect(g.carry_offset >= g.honest_negative_carry);
        try std.testing.expect(range - 1 - g.carry_offset >= g.honest_positive_carry);
        try std.testing.expect(g.residual_positive_bound < Base.M31);
        try std.testing.expect(g.residual_negative_bound < Base.M31);
        var main: [H.L.MAIN]Q = @splat(Q.zero());
        main[H.L.ACTIVE] = Q.one();
        const view = H.View{ .fixed_values = @splat(Q.zero()), .main_values = &main, .previous_active = Q.zero() };
        // Both admitted encoded endpoints decode exactly, including an
        // asymmetric negative endpoint that is not a power of two.
        try std.testing.expect(H.Eq.carry(Q, &view, r, 0).eql(@import("../curves/tests.zig").qi(-@as(i64, @intCast(g.carry_offset)))));
        for (0..g.carry_bytes) |b| main[H.L.CARRY[r] + b] = @import("../curves/tests.zig").q(@intCast(((range - 1) >> @intCast(8 * b)) & 0xff));
        try std.testing.expect(H.Eq.carry(Q, &view, r, 0).eql(@import("../curves/tests.zig").qi(@intCast(range - 1 - g.carry_offset))));
        // One step outside either interval cannot hide as a field residue.
        main[H.L.CARRY[r]] = @import("../curves/tests.zig").qi(-1);
        try std.testing.expect(H.outOfRangeQuery(&main));
        for (0..g.carry_bytes) |b| main[H.L.CARRY[r] + b] = @import("../curves/tests.zig").q(@intCast((range >> @intCast(8 * b)) & (if (b + 1 == g.carry_bytes) @as(u64, 0xffff) else 0xff)));
        try std.testing.expect(H.outOfRangeQuery(&main));
    }
    const profile = @import("../../../execution_profile.zig");
    try std.testing.expect(Exec.TAG != profile.KECCAK_SPONGE_TAG);
    for (profile.CURVE_TAGS) |tag| try std.testing.expect(Exec.TAG != tag);
}

test "OP sparse034 packet bridge keeps legacy captures narrow and validates every predecessor" {
    const B = @import("../secp256k1/mod.zig").word16_bridge;
    const allocator = std.testing.allocator;
    var call: B.types.TowerCall = undefined;
    call.pointer = 0x1000;
    call.epoch = 2;
    call.tick = 17;
    for (&call.before, 0..) |*v, i| v.* = 0x9e3779b97f4a7c15 *% (i + 1);
    call.after = try Exec.execute(&call.before);
    for (&call.predecessors, call.before) |*state, value| state.* = .{ .value = value, .epoch = 1, .tick = 13, .rights = 3 };
    try B.source.validateTower(.bn254_sparse034, call);
    var source = try B.source.TowerSource.init(allocator, .bn254_sparse034, &.{call}, 7, 6);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 20), B.types.coordinates(source.kind));
    try std.testing.expectEqual(@as(usize, 12), B.types.written(source.kind));
    try std.testing.expectEqual(@as(u32, 0x40001), B.types.tag(source.kind));
    for (0..12) |i| try std.testing.expectEqual(@as(u32, @intCast(20 + i)), B.types.outputWire(source.kind, i));
    try std.testing.expectError(error.InvalidWord16PacketCapacity, B.source.Source.init(allocator, .bn254_sparse034, &.{}, 7, 6));
    try std.testing.expectError(error.InvalidWord16PacketCapacity, B.source.TowerSource.init(allocator, .bn254_fp2_mul, &.{}, 7, 6));
    var bad = call;
    bad.pointer += 1;
    try std.testing.expectError(error.InvalidWord16SecpCall, B.source.validateTower(.bn254_sparse034, bad));
    bad = call;
    bad.pointer = std.math.maxInt(u64) - 31;
    try std.testing.expectError(error.InvalidWord16SecpCall, B.source.validateTower(.bn254_sparse034, bad));
    for (0..Exec.WORDS) |i| {
        bad = call;
        bad.predecessors[i].value ^= 1;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
        bad = call;
        bad.predecessors[i].epoch = 2;
        bad.predecessors[i].tick = 17;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
    }
    for (Exec.WRITTEN_WORDS..Exec.WORDS) |i| {
        bad = call;
        bad.after[i] ^= 1;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
    }
    for (0..Exec.WRITTEN_WORDS) |i| {
        bad = call;
        bad.predecessors[i].rights = 1;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
    }
}

test "immutable narrow tower DAG agrees on arbitrary representatives and has exact fanout" {
    const D = @import("dag.zig");
    const X = @import("../../../ethereum_services/bn254_tower.zig");
    const Bounds = @import("../curves/spec.zig");
    var random = std.Random.DefaultPrng.init(0x40_0001_32);
    for (0..24) |trial| {
        var input: [20]u256 = undefined;
        for (&input, 0..) |*x, i| x.* = switch (trial) {
            0 => 0,
            1 => std.math.maxInt(u256),
            2 => Bounds.BN254_P,
            3 => if (i % 2 == 0) Bounds.BN254_P - 1 else 1,
            else => random.random().int(u256),
        };
        const values = D.evaluate(&input);
        const expected = X.compute(&input);
        try std.testing.expectEqualSlices(u256, &expected, values[34..46]);
        for (values[20..]) |x| try std.testing.expect(x < Bounds.BN254_P);
    }
    var read_counts: [D.VALUES]u8 = @splat(0);
    for (D.PROGRAM) |instruction| for (instruction.operands()) |id| {
        if (id < D.VALUES) read_counts[id] += 1;
    };
    try std.testing.expectEqualSlices(u8, &D.FANOUT, &read_counts);
    try std.testing.expect(D.READS > 0);
}

const Micro = @import("micro.zig");
const MicroView = struct {
    row: *const Micro.Row,
    preprocessing: [Micro.FIXED]u32,
    pub fn main(self: *const @This(), column: usize) Q {
        return Q.fromBase(core.fields.m31.M31.fromCanonical(self.row[column]));
    }
    pub fn fixed(self: *const @This(), column: usize) Q {
        return Q.fromBase(core.fields.m31.M31.fromCanonical(self.preprocessing[column]));
    }
};
fn microAccepted(step: usize, row: *const Micro.Row) bool {
    const E = @import("../../evaluation.zig");
    const view = MicroView{ .row = row, .preprocessing = Micro.fixed(step) };
    var residuals: [512]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    Micro.emitMain(Q, &view, &sink);
    for (residuals[0..sink.count]) |residual| if (!residual.isZero()) {
        return false;
    };
    for (0..Micro.RANGE_QUERIES) |index| if (Micro.rangeQuery(row, index) >= Micro.rangeQueryLimit(index)) {
        return false;
    };
    return true;
}
test "narrow tower arithmetic rows bind every carry and canonical writer" {
    const D = @import("dag.zig");
    try std.testing.expect(Micro.G.residual_positive_bound < Base.M31);
    try std.testing.expect(Micro.G.residual_negative_bound < Base.M31);
    try std.testing.expect(Micro.MAIN < 600);
    var random = std.Random.DefaultPrng.init(0x1536_40001);
    for (0..8) |trial| {
        var input: [20]u256 = undefined;
        for (&input) |*x| x.* = if (trial == 0) std.math.maxInt(u256) else random.random().int(u256);
        const values = D.evaluate(&input);
        for (0..D.STEPS) |step| {
            const honest = Micro.fill(step, &values);
            try std.testing.expect(microAccepted(step, &honest));
            try std.testing.expectEqual(values[D.PROGRAM[step].output], Micro.read(&honest, Micro.RESULT));
            for ([_]usize{ Micro.RESULT, Micro.QUOTIENT, Micro.DISTANCE, Micro.BORROW }) |column| {
                var forged = honest;
                forged[column] ^= 1;
                try std.testing.expect(!microAccepted(step, &forged));
            }
            for (0..Micro.G.carries) |carry| {
                var forged = honest;
                forged[Micro.CARRY + carry] ^= 1;
                try std.testing.expect(!microAccepted(step, &forged));
            }
        }
    }
    try Micro.validateMass(22_185);
    try std.testing.expectError(error.TowerMassBound, Micro.validateMass(0));
    try std.testing.expectError(error.TowerMassBound, Micro.validateMass(Base.M31));
    std.debug.print("OP_TOWER_NARROW main={d} range_queries={d} steps={d} SSA_reads={d} group={d} carry_bits={d}\n", .{ Micro.MAIN, Micro.RANGE_QUERIES, D.STEPS, D.READS, Micro.G.group, Micro.G.carry_bits });
}

test "narrow full packet schedule has exact source-owned characteristic mass" {
    const Schedule = @import("schedule.zig");
    const D = @import("dag.zig");
    Schedule.checkSchedule();
    const measured = try Schedule.mass(22_185);
    try std.testing.expectEqual(@as(u64, 22_185 * 2 * D.READS), measured.local_ssa);
    try std.testing.expectEqual(@as(u64, 22_185 * 64), measured.global_wire);
    try Schedule.validateGeometry(22_185, 1, 21);
    try std.testing.expectError(error.TowerGeometry, Schedule.validateGeometry(22_185, 1, 20));
    try std.testing.expectError(error.TowerGeometry, Schedule.validateGeometry(2, Base.M31 - 1, 8));
    try std.testing.expectError(error.TowerMassBound, Schedule.mass(Base.M31));
    try std.testing.expectError(error.TowerMassBound, (Schedule.Mass{ .local_ssa = Base.M31, .local_range = 0, .global_wire = 0 }).validate());
}

const NarrowSource = @import("narrow_source.zig");
const SourceView = struct {
    values: []const u32,
    preprocessing: [NarrowSource.FIXED]u32,
    previous: u32,
    pub fn main(self: *const @This(), c: usize) Q {
        return Q.fromBase(core.fields.m31.M31.fromCanonical(self.values[c]));
    }
    pub fn fixed(self: *const @This(), c: usize) Q {
        return Q.fromBase(core.fields.m31.M31.fromCanonical(self.preprocessing[c]));
    }
    pub fn previousActive(self: *const @This()) Q {
        return Q.fromBase(core.fields.m31.M31.fromCanonical(self.previous));
    }
};
const SourceLedger = struct {
    const Item = struct { key: [35]u32, weight: i64 };
    entries: [512]Item = undefined,
    count: usize = 0,
    valid_ranges: bool = true,
    pub fn byte(self: *@This(), value: Q, weight: Q) void {
        if (weight.isZero()) return;
        const x = value.tryIntoM31() catch {
            self.valid_ranges = false;
            return;
        };
        self.valid_ranges = self.valid_ranges and x.v < 256;
    }
    pub fn carry(self: *@This(), value: Q, weight: Q) void {
        if (weight.isZero()) return;
        const x = value.tryIntoM31() catch {
            self.valid_ranges = false;
            return;
        };
        self.valid_ranges = self.valid_ranges and x.v < Micro.CARRY_LIMIT;
    }
    pub fn ssa(self: *@This(), tuple: [35]Q, weight: Q) void {
        const numerator = weight.tryIntoM31() catch unreachable;
        if (numerator.v == 0) return;
        var key: [35]u32 = undefined;
        for (&key, tuple) |*x, field| x.* = (field.tryIntoM31() catch unreachable).v;
        self.entries[self.count] = .{ .key = key, .weight = if (numerator.v < Base.M31 / 2) numerator.v else @as(i64, numerator.v) - Base.M31 };
        self.count += 1;
    }
    fn less(_: void, a: Item, b: Item) bool {
        for (a.key, b.key) |x, y| if (x != y) {
            return x < y;
        };
        return false;
    }
    fn closed(self: *@This()) bool {
        std.mem.sort(Item, self.entries[0..self.count], {}, less);
        var at: usize = 0;
        while (at < self.count) {
            const key = self.entries[at].key;
            var total: i64 = 0;
            while (at < self.count and std.mem.eql(u32, &key, &self.entries[at].key)) : (at += 1) total += self.entries[at].weight;
            if (total != 0) return false;
        }
        return self.valid_ranges;
    }
};
fn sourceMainAccepted(comptime role: NarrowSource.Role, index: usize, data: []const u32) bool {
    const E = @import("../../evaluation.zig");
    const view = SourceView{ .values = data, .preprocessing = NarrowSource.fixedRow(role, index, 8), .previous = @intFromBool(index > 0) };
    var residuals: [512]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    NarrowSource.emitMain(role, Q, &view, .{ .calls = 1, .first_id = 17 }, &sink);
    for (residuals[0..sink.count]) |x| if (!x.isZero()) {
        return false;
    };
    return true;
}
test "narrow separate frontier and arithmetic source authority closes SSA and rejects orphan operands" {
    const D = @import("dag.zig");
    var input: [20]u256 = undefined;
    for (&input, 0..) |*value, i| value.* = std.math.maxInt(u256) - @as(u256, i) * 317;
    const values = D.evaluate(&input);
    var honest = SourceLedger{};
    var forged = SourceLedger{};
    for (0..D.INPUTS) |step| {
        const row = NarrowSource.frontierRow(&input, step);
        try std.testing.expect(sourceMainAccepted(.frontier, step, &row));
        const view = SourceView{ .values = &row, .preprocessing = NarrowSource.fixedRow(.frontier, step, 8), .previous = @intFromBool(step > 0) };
        NarrowSource.emitLocal(.frontier, Q, &view, .{ .calls = 1, .first_id = 17 }, &honest);
        NarrowSource.emitLocal(.frontier, Q, &view, .{ .calls = 1, .first_id = 17 }, &forged);
        const wire = NarrowSource.globalFraction(.frontier, Q, &view, .{ .calls = 1, .first_id = 17 });
        try std.testing.expectEqual(@as(u32, @intCast(step)), (wire.tuple[2].tryIntoM31() catch unreachable).v);
        try std.testing.expectEqual(Q.one().neg(), wire.weight);
    }
    for (0..D.STEPS) |step| {
        const row = Micro.fill(step, &values);
        try std.testing.expect(sourceMainAccepted(.arithmetic, step, &row));
        const view = SourceView{ .values = &row, .preprocessing = NarrowSource.fixedRow(.arithmetic, step, 8), .previous = @intFromBool(step > 0) };
        NarrowSource.emitLocal(.arithmetic, Q, &view, .{ .calls = 1, .first_id = 17 }, &honest);
        // A self-consistent arithmetic row is insufficient. Change one operand
        // and recompute all its advice: the local edge ledger must still fail.
        var forged_values = values;
        const changed = D.PROGRAM[step].operands()[0];
        if (step == 0) forged_values[changed] -%= 1;
        const bad_row = Micro.fill(step, &forged_values);
        try std.testing.expect(microAccepted(step, &bad_row));
        const bad_view = SourceView{ .values = &bad_row, .preprocessing = NarrowSource.fixedRow(.arithmetic, step, 8), .previous = @intFromBool(step > 0) };
        NarrowSource.emitLocal(.arithmetic, Q, &bad_view, .{ .calls = 1, .first_id = 17 }, &forged);
    }
    try std.testing.expect(honest.closed());
    try std.testing.expect(!forged.closed());
    const budget = try NarrowSource.cost(.{ .calls = 22_185, .first_id = 1 });
    try std.testing.expectEqual(@as(u32, 19), budget.frontier_log);
    try std.testing.expectEqual(@as(u32, 20), budget.arithmetic_log);
    std.debug.print("OP_TOWER_NARROW_ROSTER {any}\n", .{budget});
}

test "narrow classic shape stays degree three and under one thousand lifted columns" {
    const Eq = @import("narrow_equations.zig");
    const A = Eq.Layout(.arithmetic);
    const F = Eq.Layout(.frontier);
    try std.testing.expectEqual(@as(usize, 370), A.MAIN);
    try std.testing.expectEqual(@as(usize, 280), A.INTERACTION);
    try std.testing.expectEqual(@as(usize, 33), F.MAIN);
    try std.testing.expectEqual(@as(usize, 8), F.INTERACTION);
    try std.testing.expectEqual(@as(u8, 3), @as(u8, A.DEGREE));
    const lifted = A.MAIN + A.INTERACTION * 2 + F.MAIN + F.INTERACTION * 2;
    try std.testing.expect(lifted < 1000);
    const cells = @as(u64, A.MAIN + A.INTERACTION * 2) * (1 << 20) + @as(u64, F.MAIN + F.INTERACTION * 2) * (1 << 19);
    std.debug.print("OP_TOWER_NARROW_CLASSIC lifted_columns={d} cells={d} frontier={d}/{d} arithmetic={d}/{d}\n", .{ lifted, cells, F.MAIN, F.INTERACTION * 2, A.MAIN, A.INTERACTION * 2 });
    try A.validateGeometry(22_185, 1, 20);
    try std.testing.expectError(error.TowerGeometry, A.validateGeometry(1, 1, 14));
    // Force semantic instantiation of all source expression / classic AIR code.
    const front: NarrowSource.FrontierRow = @splat(0);
    const view = SourceView{ .values = &front, .preprocessing = NarrowSource.fixedRow(.frontier, 0, 8), .previous = 0 };
    const q = Q.fromBase(core.fields.m31.M31.fromCanonical(123456));
    const wire = @import("../curves/equations.zig").Wire{ .offset = q, .coefficients = @splat(q) };
    const challenges = Eq.Challenges{ .bytes = q, .carries = q, .ssa = wire, .wire = wire };
    const E = @import("../../evaluation.zig");
    var sink = E.Sink{ .values = null };
    Eq.Equations(.frontier).emitMain(Q, &view, .{ .calls = 1, .first_id = 1 }, &sink);
    try std.testing.expectEqual(F.MAIN_CONSTRAINTS, sink.count);
    _ = Eq.Equations(.frontier).fraction(Q, &view, .{ .calls = 1, .first_id = 1 }, challenges, .ssa, 0);
    _ = Eq.Equations(.frontier).fraction(Q, &view, .{ .calls = 1, .first_id = 1 }, challenges, .wire, 0);
}

test "narrow frontier column source commits source-owned shape and complete prefix" {
    const T = @import("narrow_trace.zig");
    const a = std.testing.allocator;
    const input: T.Input = @splat(17);
    var source = try T.Source(.frontier).init(a, &.{input}, 7, 8);
    defer source.deinit();
    const q = Q.fromBase(core.fields.m31.M31.fromCanonical(123456));
    const wire = @import("../curves/equations.zig").Wire{ .offset = q, .coefficients = @splat(q) };
    const NE = @import("narrow_equations.zig");
    const claims = try source.generateInteraction(.{ .bytes = q, .carries = q, .ssa = wire, .wire = wire });
    try std.testing.expect(!claims.ssa.isZero());
    try std.testing.expect(!claims.wire.isZero());
    const Component = @import("narrow_component.zig").Component(.frontier);
    const component = Component{ .log_size = 8, .public = source.public(), .claims = claims, .challenges = .{ .bytes = q, .carries = q, .ssa = wire, .wire = wire } };
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    try std.testing.expectEqual(NE.Layout(.frontier).CONSTRAINTS, component.nConstraints());
}

test "narrow complete classic equations have degree at most three including fixed ROM" {
    const NE = @import("narrow_equations.zig");
    const E = @import("../../evaluation.zig");
    const View = struct {
        values: []const Q,
        width: usize,
        pub fn fixed(self: *const @This(), index: usize) Q {
            return self.values[index];
        }
        pub fn main(self: *const @This(), index: usize) Q {
            return self.values[NarrowSource.FIXED + index];
        }
        pub fn previousActive(self: *const @This()) Q {
            return self.values[self.values.len - 1];
        }
        pub fn interaction(self: *const @This(), index: usize) Q {
            return self.values[NarrowSource.FIXED + self.width + index];
        }
        pub fn previousInteraction(self: *const @This(), index: usize) Q {
            return self.values[NarrowSource.FIXED + self.width + index].add(Q.one());
        }
    };
    const chq = Q.fromU32Unchecked(11, 17, 23, 29);
    const wire = @import("../curves/equations.zig").Wire{ .offset = chq, .coefficients = @splat(chq) };
    const challenges = NE.Challenges{ .bytes = chq, .carries = chq.add(Q.one()), .ssa = wire, .wire = wire };
    inline for (.{ NarrowSource.Role.frontier, NarrowSource.Role.arithmetic }) |role| {
        const L = NE.Layout(role);
        var values: [NarrowSource.FIXED + L.MAIN + L.INTERACTION + 1]Q = undefined;
        var residuals: [5][L.CONSTRAINTS]Q = undefined;
        for (0..5) |step| {
            for (&values, 0..) |*value, index| value.* = Q.fromU32Unchecked(@intCast(index + 1), 2, 3, 4).add(Q.fromU32Unchecked(5, @intCast(index + 7), 11, 13).mulM31(core.fields.m31.M31.fromCanonical(@intCast(step))));
            const view = View{ .values = &values, .width = L.MAIN };
            var sink = E.Sink{ .values = &residuals[step] };
            NE.Equations(role).emit(Q, &view, .{ .calls = 1, .first_id = 7 }, .{ .ssa = chq, .wire = chq }, challenges, &sink);
            try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
        }
        for (0..L.CONSTRAINTS) |constraint| {
            const fourth = residuals[0][constraint].sub(residuals[1][constraint].mulM31(core.fields.m31.M31.fromCanonical(4))).add(residuals[2][constraint].mulM31(core.fields.m31.M31.fromCanonical(6))).sub(residuals[3][constraint].mulM31(core.fields.m31.M31.fromCanonical(4))).add(residuals[4][constraint]);
            try std.testing.expect(fourth.isZero());
        }
    }
}

test "narrow QM31 and OM31 bounded inversion chunks preserve every scalar interaction cell" {
    const Trace = @import("narrow_trace.zig");
    const Eq = @import("narrow_equations.zig");
    const Source = @import("narrow_source.zig");
    const a = std.testing.allocator;
    // Five calls cross a128-row arithmetic chunk; the last partial chunk and
    // all padded range-provider rows remain covered in both field families.
    var inputs: [5]Trace.Input = undefined;
    for (&inputs, 0..) |*input, call| for (input, 0..) |*value, coordinate| {
        value.* = (@as(u256, 1) << 248) + (call + 1) * (coordinate + 3);
    };
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |Field| {
        const degree = @import("../../evaluation.zig").extensionDegree(Field);
        var coordinates: [degree]core.fields.m31.M31 = undefined;
        for (&coordinates, 0..) |*value, k| value.* = core.fields.m31.M31.fromCanonical(@intCast(k + 11));
        const seed = Field.fromM31Array(coordinates);
        const wire = @import("../curves/equations.zig").WireFor(Field){ .offset = seed, .coefficients = @splat(seed.add(Field.one())) };
        const ch = Eq.ChallengesFor(Field){ .bytes = seed, .carries = seed.add(seed), .ssa = wire, .wire = wire };
        inline for (.{ Source.Role.frontier, Source.Role.arithmetic }) |role| {
            const log: u32 = if (role == .frontier) 8 else 15;
            var scalar = try Trace.SourceForField(role, Field).init(a, &inputs, 7, log);
            defer scalar.deinit();
            var batched = try Trace.SourceForField(role, Field).init(a, &inputs, 7, log);
            defer batched.deinit();
            const expected = try scalar.generateInteractionScalarForTesting(ch);
            const actual = try batched.generateInteraction(ch);
            try std.testing.expect(expected.ssa.eql(actual.ssa));
            try std.testing.expect(expected.wire.eql(actual.wire));
            try std.testing.expectEqualSlices(core.fields.m31.M31, scalar.interaction, batched.interaction);
            var released = try Trace.SourceForField(role, Field).initWithoutFixed(a, &inputs, 7, log);
            defer released.deinit();
            const main_bytes = released.main.len * @sizeOf(core.fields.m31.M31);
            const backing = try released.takeMain();
            a.free(backing);
            released.releaseFixed();
            try std.testing.expectError(error.TowerMainAlreadyReleased, released.takeMain());
            const retained = try released.generateInteraction(ch);
            try std.testing.expect(retained.ssa.eql(expected.ssa));
            try std.testing.expect(retained.wire.eql(expected.wire));
            try std.testing.expectEqualSlices(core.fields.m31.M31, scalar.interaction, released.interaction);
            if (role == .arithmetic) try std.testing.expect(released.retainedAdviceBytes() < main_bytes / 10);
            try released.releaseAdvice();
            try std.testing.expectEqual(@as(u32, 5), released.public().calls);
            try std.testing.expectError(error.TowerAdviceRetired, released.generateInteraction(ch));
            try std.testing.expectError(error.TowerAdviceRetired, released.releaseAdvice());
        }
    }
}

test "narrow cost honors physical provider widths and minimum range table geometry" {
    const NE = @import("narrow_equations.zig");
    const source = @import("narrow_source.zig");
    for ([_]u32{ 1, 12, 13, 20, 1023, 1024, 22_185 }) |calls| {
        const budget = try source.cost(.{ .calls = calls, .first_id = 1 });
        try NE.Layout(.frontier).validateGeometry(calls, 1, budget.frontier_log);
        try NE.Layout(.arithmetic).validateGeometry(calls, 1, budget.arithmetic_log);
        const expected = (@as(u64, NE.Layout(.frontier).MAIN) << @intCast(budget.frontier_log)) + (@as(u64, NE.Layout(.arithmetic).MAIN) << @intCast(budget.arithmetic_log));
        try std.testing.expectEqual(expected, budget.committed_main_cells);
        try std.testing.expectEqual(NE.Layout(.frontier).MAIN + NE.Layout(.arithmetic).MAIN, budget.lifted_main_columns);
    }
    try std.testing.expectEqual(@as(u32, 8), (try source.cost(.{ .calls = 1, .first_id = 1 })).frontier_log);
    try std.testing.expectEqual(@as(u32, 15), (try source.cost(.{ .calls = 1, .first_id = 1 })).arithmetic_log);
    try std.testing.expectEqual(@as(u32, 15), (try source.cost(.{ .calls = 1023, .first_id = 1 })).arithmetic_log);
    try std.testing.expectEqual(@as(u32, 16), (try source.cost(.{ .calls = 1024, .first_id = 1 })).arithmetic_log);
}
