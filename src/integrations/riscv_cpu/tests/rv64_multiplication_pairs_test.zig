//! MUL byte-pair encoding (Geometry.mul_u8_pairs) at equation level: cubic
//! residuals, packed/QM31 parity, honest witness satisfies every residual and
//! balances against the AND pair-table counts, parallel = serial oracle, and
//! forged witnesses (pair slot, fused FUNCTION, pair pole, out-of-range pair
//! element, drop-and-compensate) are rejected.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const rv = @import("stwo_riscv_frontend").rv64_air;
const Mul = rv.arithmetic.multiplication;
const L = Mul.pairs_layout;
const PP = Mul.pairs_provider;
const Tables = rv.providers.tables;
const E = rv.evaluation;
const Q = E.Q;
const M = core.fields.m31.M31;
const Fixture = @import("../delegations/multiplication/degree3_fixture.zig");
const a = std.testing.allocator;
const DELTA = Q.fromU32Unchecked(3, 1, 4, 1);

fn dictionary(pc: Tables.Challenges) ![]Q {
    const out = try a.alloc(Q, 65536);
    for (out, 0..) |*v, i| v.* = try Tables.pairDenominatorFor(Q, pc, E.q(@intCast(i >> 8)), E.q(@intCast(i & 255))).inv();
    return out;
}
const Drawn = struct { ch: Mul.provider.Challenges, pc: Tables.Challenges, claim: Q };
fn draw() Drawn {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = Mul.provider.Challenges.draw(&channel);
    const pc = Tables.Challenges.draw(&channel);
    return .{ .ch = ch, .pc = pc, .claim = channel.drawSecureFelt() };
}

test "MUL byte-pair authority is genuinely cubic for every arbitrary extension residual" {
    const d = draw();
    const N = L.FIXED + L.MAIN + L.INTERACTION + 4 + 1;
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{7});
    var origin: [N]Q = undefined;
    var slope: [N]Q = undefined;
    for (&origin, &slope) |*o, *s| {
        o.* = channel.drawSecureFelt();
        s.* = channel.drawSecureFelt();
    }
    var evaluated: [5][L.CONSTRAINTS]Q = undefined;
    for (&evaluated, 0..) |*values, i| {
        var input: [N]Q = undefined;
        for (&input, origin, slope) |*v, o, s| v.* = o.add(s.mul(E.q(@intCast(i))));
        var sink = E.Sink{ .values = values };
        PP.evaluateFor(Q, input[0..3].*, input[3..][0..L.MAIN], input[3 + L.MAIN ..][0..L.INTERACTION], E.secureFor(Q, &input, 3 + L.MAIN + L.INTERACTION), input[N - 1], E.q(17), d.ch, d.pc, d.claim, &sink);
        try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
        var reference: [L.ARITHMETIC_CONSTRAINTS]Q = undefined;
        var oracle = E.Sink{ .values = &reference };
        Mul.provider.arithmeticFor(Q, input[0..3].*, input[3..][0..L.MAIN], input[N - 1], E.q(17), &oracle);
        try std.testing.expectEqualSlices(Q, &reference, values[0..L.ARITHMETIC_CONSTRAINTS]);
    }
    var cubic: usize = 0;
    for (0..L.CONSTRAINTS) |c| {
        var differences: [5]Q = undefined;
        for (&differences, evaluated) |*v, row| v.* = row[c];
        for (0..4) |order| {
            for (0..4 - order) |i| differences[i] = differences[i + 1].sub(differences[i]);
            if (order == 2 and !differences[0].isZero()) cubic += 1;
        }
        if (!differences[0].isZero()) return error.UnexpectedMultiplicationDegree;
    }
    // Every pair inverse and the fused prefix are genuinely cubic.
    try std.testing.expect(cubic >= L.PAIR_COLUMNS + 1);
    try std.testing.expectEqual(@as(usize, 100), L.INTERACTION);
    try std.testing.expectEqual(@as(usize, 141 + 24 + 2), L.CONSTRAINTS);
}

fn fieldValue(comptime F: type, c: usize, lane: usize) Q {
    const x: u32 = @intCast(1 + 64 * c + 4 * lane);
    return if (F == E.PackedBase) E.q(x) else Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
}
fn pack(comptime F: type, comptime n: usize, start: usize) [n]F {
    var values: [n]F = undefined;
    for (&values, 0..) |*v, c| {
        if (F == E.PackedBase) {
            var lanes: [16]M = undefined;
            for (&lanes, 0..) |*x, lane| x.* = fieldValue(F, start + c, lane).toM31Array()[0];
            v.* = F.fromLanes(lanes);
        } else {
            var lanes: [16]Q = undefined;
            for (&lanes, 0..) |*x, lane| x.* = fieldValue(F, start + c, lane);
            v.* = F.fromLanes(lanes);
        }
    }
    return values;
}
test "every MUL byte-pair residual matches scalar in PackedM31 and full secure lanes" {
    const d = draw();
    inline for (.{ E.PackedBase, E.PackedSecure }) |F| {
        const fixed = pack(F, 3, 0);
        const main = pack(F, L.MAIN, 3);
        const inter = pack(F, L.INTERACTION, 3 + L.MAIN);
        const previous = pack(F, 4, 3 + L.MAIN + L.INTERACTION);
        const count = pack(F, 1, 7 + L.MAIN + L.INTERACTION);
        var results: [L.CONSTRAINTS]E.PackedSecure = undefined;
        var sink = E.SinkFor(F){ .values = &results };
        PP.evaluateFor(F, fixed, &main, &inter, E.secureFromCoordinatesFor(F, previous), count[0], E.qFor(F, 15), d.ch, d.pc, d.claim, &sink);
        for (0..16) |lane| {
            var f: [3]Q = undefined;
            var m: [L.MAIN]Q = undefined;
            var i: [L.INTERACTION]Q = undefined;
            var prior: [4]Q = undefined;
            for (&f, 0..) |*v, c| v.* = fieldValue(F, c, lane);
            for (&m, 0..) |*v, c| v.* = fieldValue(F, 3 + c, lane);
            for (&i, 0..) |*v, c| v.* = fieldValue(F, 3 + L.MAIN + c, lane);
            for (&prior, 0..) |*v, c| v.* = fieldValue(F, 3 + L.MAIN + L.INTERACTION + c, lane);
            var expected: [L.CONSTRAINTS]Q = undefined;
            var scalar = E.Sink{ .values = &expected };
            PP.evaluateFor(Q, f, &m, &i, Q.fromPartialEvals(prior), fieldValue(F, 7 + L.MAIN + L.INTERACTION, lane), E.q(15), d.ch, d.pc, d.claim, &scalar);
            for (results, expected) |actual, want| try std.testing.expect(actual.lane(lane).eql(want));
        }
    }
}

/// Honest pair-mode trace of the fixture requests: MAIN copy, interaction and claim.
const Honest = struct {
    trace: Mul.trace.Trace,
    main: []M,
    claim: Q,
    pair_counts: []u64,
    fn init(d: Drawn, dict: []const Q) !Honest {
        var trace = try Mul.trace.Trace.init(a, &Fixture.REQUESTS);
        errdefer trace.deinit();
        const main = try a.dupe(M, trace.main);
        errdefer a.free(main);
        const counts = try a.alloc(u64, 65536);
        errdefer a.free(counts);
        @memset(counts, 0);
        try trace.addBytePairCounts(counts);
        try trace.releaseMain();
        const claim = try Mul.degree3_source.generatePairsSerial(&trace, d.ch, dict);
        return .{ .trace = trace, .main = main, .claim = claim, .pair_counts = counts };
    }
    fn deinit(self: *Honest) void {
        self.trace.deinit();
        a.free(self.main);
        a.free(self.pair_counts);
    }
    fn n(self: *const Honest) usize {
        return self.trace.domainSize();
    }
    fn mainRow(self: *const Honest, logical: usize) [L.MAIN]Q {
        var m: [L.MAIN]Q = undefined;
        const row = rv.witness.physical(logical, self.trace.log_size);
        for (&m, 0..) |*v, c| v.* = Q.fromBase(self.main[c * self.n() + row]);
        return m;
    }
    /// All residuals at `logical` over an interaction matrix `inter`.
    fn residuals(self: *const Honest, d: Drawn, main: [L.MAIN]Q, inter: []const M, logical: usize, claim: Q) [L.CONSTRAINTS]Q {
        const size = self.n();
        const row = rv.witness.physical(logical, self.trace.log_size);
        const prev = rv.witness.physical((logical + size - 1) % size, self.trace.log_size);
        var f: [3]Q = undefined;
        var i: [L.INTERACTION]Q = undefined;
        var prior: [4]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(self.trace.fixed[c * size + row]);
        for (&i, 0..) |*v, c| v.* = Q.fromBase(inter[c * size + row]);
        for (&prior, 0..) |*v, c| v.* = Q.fromBase(inter[(L.PREFIX + c) * size + prev]);
        var out: [L.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &out };
        PP.evaluateFor(Q, f, &main, &i, Q.fromPartialEvals(prior), Q.fromBase(self.main[Mul.layout.COUNT * size + prev]), E.q(self.trace.count), d.ch, d.pc, claim, &sink);
        return out;
    }
    fn allZero(self: *const Honest, d: Drawn, inter: []const M, claim: Q) bool {
        for (0..self.n()) |logical| for (self.residuals(d, self.mainRow(logical), inter, logical, claim)) |v| if (!v.isZero()) return false;
        return true;
    }
};
fn readQ(data: []const M, size: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * size + row], data[(column + 1) * size + row], data[(column + 2) * size + row], data[(column + 3) * size + row]);
}
fn writeQ(data: []M, size: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(column + c) * size + row] = v;
}

test "honest MUL byte-pair witness satisfies every residual and balances exactly against the AND pair-table counts" {
    const d = draw();
    const dict = try dictionary(d.pc);
    defer a.free(dict);
    var honest = try Honest.init(d, dict);
    defer honest.deinit();
    try std.testing.expect(honest.allZero(d, honest.trace.interaction, honest.claim));
    // claim = sum over pair queries of 1/p - sum over active rows of 1/d_fn;
    // the pair part is exactly what the AND pair column must serve.
    var pairs = Q.zero();
    var mass: u64 = 0;
    for (honest.pair_counts, dict) |count, inverse| {
        pairs = pairs.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
        mass += count;
    }
    try std.testing.expectEqual(@as(u64, L.PAIR_QUERIES) * honest.n(), mass);
    var functions = Q.zero();
    for (Fixture.REQUESTS) |request| functions = functions.add(try d.ch.denominator(&try Mul.trace.requestTuple(request)).inv());
    try std.testing.expect(honest.claim.eql(pairs.sub(functions)));
}

test "forged MUL byte-pair witnesses are rejected: pair slot, fused FUNCTION, prefix, drop-and-compensate" {
    const d = draw();
    const dict = try dictionary(d.pc);
    defer a.free(dict);
    var honest = try Honest.init(d, dict);
    defer honest.deinit();
    const size = honest.n();
    const inter = try a.dupe(M, honest.trace.interaction);
    defer a.free(inter);
    const log = honest.trace.log_size;
    // (1) Pair inverse slot += delta on an active row and on a padding row:
    // the strict inverse residual alone rejects it.
    for ([_]usize{ 0, size - 1 }) |logical| for ([_]usize{ 0, L.PAIR_COLUMNS - 1 }) |column| {
        @memcpy(inter, honest.trace.interaction);
        const row = rv.witness.physical(logical, log);
        writeQ(inter, size, row, 4 * column, readQ(inter, size, row, 4 * column).add(DELTA));
        try std.testing.expect(!honest.residuals(d, honest.mainRow(logical), inter, logical, honest.claim)[L.ARITHMETIC_CONSTRAINTS + column].isZero());
    };
    // (2) Prefix += delta at one row: its fused residual and the next row's reject.
    @memcpy(inter, honest.trace.interaction);
    const r3 = rv.witness.physical(3, log);
    writeQ(inter, size, r3, L.PREFIX, readQ(inter, size, r3, L.PREFIX).add(DELTA));
    const fused = L.ARITHMETIC_CONSTRAINTS + L.PAIR_COLUMNS;
    try std.testing.expect(!honest.residuals(d, honest.mainRow(3), inter, 3, honest.claim)[fused].isZero());
    try std.testing.expect(!honest.residuals(d, honest.mainRow(4), inter, 4, honest.claim)[fused].isZero());
    // (3) Drop a row's first pair fraction and compensate at a later row: the
    // final claim is unchanged, yet both rows' fused residuals reject.
    for ([_][2]usize{ .{ 0, 9 }, .{ size - 1, 2 } }) |pair| {
        @memcpy(inter, honest.trace.interaction);
        const tail = try PP.nativePairDenominators(&honest.mainRow(pair[0]), d.pc)[0].inv();
        const lo = @min(pair[0], pair[1]);
        const hi = @max(pair[0], pair[1]);
        const sign = if (pair[0] < pair[1]) Q.one().neg() else Q.one();
        for (lo..hi) |logical| {
            const row = rv.witness.physical(logical, log);
            writeQ(inter, size, row, L.PREFIX, readQ(inter, size, row, L.PREFIX).add(tail.mul(sign)));
        }
        try std.testing.expect(!honest.allZero(d, inter, honest.claim));
        try std.testing.expect(!honest.residuals(d, honest.mainRow(pair[0]), inter, pair[0], honest.claim)[fused].isZero());
        try std.testing.expect(!honest.residuals(d, honest.mainRow(pair[1]), inter, pair[1], honest.claim)[fused].isZero());
    }
    // (4) FUNCTION fraction dropped on an active row (prefix repaired from there on).
    @memcpy(inter, honest.trace.interaction);
    const tail = try d.ch.denominator(&Mul.provider.tuple(&honest.mainRow(1))).inv();
    for (1..size) |logical| {
        const row = rv.witness.physical(logical, log);
        writeQ(inter, size, row, L.PREFIX, readQ(inter, size, row, L.PREFIX).add(tail));
    }
    try std.testing.expect(!honest.residuals(d, honest.mainRow(1), inter, 1, honest.claim)[fused].isZero());
    // (5) Fused-FUNCTION pole: if d_fn = 0 the residual reads `active`, so an
    // active row cannot be satisfied for ANY prefix step.
    var zero = d;
    zero.ch.offset = zero.ch.offset.sub(zero.ch.denominator(&Mul.provider.tuple(&honest.mainRow(0))));
    try std.testing.expect(zero.ch.denominator(&Mul.provider.tuple(&honest.mainRow(0))).isZero());
    try std.testing.expect(honest.residuals(zero, honest.mainRow(0), honest.trace.interaction, 0, honest.claim)[fused].eql(Q.one()));
}

test "MUL byte-pair poles and out-of-range pair elements cannot alias a canonical table pair" {
    const d = draw();
    // A one-sided pair pole makes the strict inverse residual read -1.
    const honest_dict = try dictionary(d.pc);
    defer a.free(honest_dict);
    var honest = try Honest.init(d, honest_dict);
    defer honest.deinit();
    var pole = d;
    const p0 = PP.nativePairDenominators(&honest.mainRow(0), d.pc)[0];
    pole.pc.offset = pole.pc.offset.sub(p0);
    try std.testing.expect(PP.nativePairDenominators(&honest.mainRow(0), pole.pc)[0].isZero());
    try std.testing.expect(honest.residuals(pole, honest.mainRow(0), honest.trace.interaction, 0, honest.claim)[L.ARITHMETIC_CONSTRAINTS].eql(Q.one().neg()));
    // Out-of-range element: (x + 256*k, y) or (x, y + 256) never equals a
    // canonical table pair (x', y', 0, 1) nor an AND tuple (x', y', x'&y', 0).
    for ([_][2]u32{ .{ 256, 0 }, .{ 0, 256 }, .{ 300, 7 }, .{ 255, 511 }, .{ M.fromCanonical(0).sub(M.one()).v, 0 } }) |bad| {
        const p = Tables.pairDenominatorFor(Q, d.pc, E.q(bad[0]), E.q(bad[1]));
        for (0..65536) |i| {
            const x: u32 = @intCast(i >> 8);
            const y: u32 = @intCast(i & 255);
            try std.testing.expect(!p.eql(Tables.pairDenominatorFor(Q, d.pc, E.q(x), E.q(y))));
            try std.testing.expect(!p.eql(d.pc.denominator(&.{ E.q(x), E.q(y), E.q(x & y) })));
        }
    }
    // A carry limb shifted by 256 keeps the integer product (every arithmetic
    // residual holds) but produces a non-byte pair element.
    // (A field wrap of CARRY_HIGH to p-1 is equally invisible to arithmetic.)
    var main = honest.mainRow(0);
    main[Mul.layout.CARRY_HIGH] = main[Mul.layout.CARRY_HIGH].sub(Q.one());
    main[Mul.layout.CARRY_LOW] = main[Mul.layout.CARRY_LOW].add(E.q(256));
    {
        var arithmetic: [L.ARITHMETIC_CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &arithmetic };
        const size = honest.n();
        const prev = rv.witness.physical(size - 1, honest.trace.log_size);
        Mul.provider.arithmeticFor(Q, .{ E.q(0), E.q(1), E.q(0) }, &main, Q.fromBase(honest.main[Mul.layout.COUNT * size + prev]), E.q(honest.trace.count), &sink);
        for (arithmetic) |v| try std.testing.expect(v.isZero());
        var non_byte = false;
        for (Mul.provider.byteValues(&main)) |v| non_byte = non_byte or v.toM31Array()[0].v >= 256;
        try std.testing.expect(non_byte);
    }
}

fn requests(count: usize) ![]Mul.trace.Request {
    const out = try a.alloc(Mul.trace.Request, count);
    for (out, 0..) |*r, i| {
        const x = @as(u64, @intCast(i + 3)) *% 0x9e3779b97f4a7c15;
        const y = (x >> 7) ^ 0xd1b54a32d192ed03;
        const product = @as(u128, x) * y;
        r.* = if (i % 2 == 0) .{ .opcode = .MUL, .a = x, .b = y, .result = @truncate(product) } else .{ .opcode = .MULHU, .a = x, .b = y, .result = @intCast(product >> 64) };
    }
    return out;
}
test "joined parallel MUL byte-pair interactions equal the serial oracle byte for byte" {
    const d = draw();
    const dict = try dictionary(d.pc);
    defer a.free(dict);
    inline for (.{ 14, 17 }) |log| {
        for ([_]usize{ 1 << log, (1 << log) - 4097, 5051, 0 }) |count| {
            const input = try requests(count);
            defer a.free(input);
            var oracle = try Mul.trace.Trace.initWithLog(a, input, log);
            defer oracle.deinit();
            try oracle.releaseMain();
            const expected = try Mul.degree3_source.generatePairsSerial(&oracle, d.ch, dict);
            for ([_]usize{ 1, 3, 8 }) |workers| {
                var pool: work.WorkPool = .{};
                try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = if (@import("builtin").mode == .Debug) 1 << 20 else 1 << 18, .backing_allocator = a });
                defer pool.deinit();
                var binding = try work.ScopedPoolBinding.init(&pool);
                defer binding.deinit();
                var trace = try Mul.trace.Trace.initWithLog(a, input, log);
                defer trace.deinit();
                try trace.releaseMain();
                const claim = try Mul.degree3_source.generatePairs(&trace, d.ch, dict);
                try std.testing.expect(claim.eql(expected));
                try std.testing.expectEqual(L.INTERACTION << log, trace.interaction.len);
                try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(oracle.interaction), std.mem.sliceAsBytes(trace.interaction));
            }
        }
    }
    var short = try Mul.trace.Trace.initWithLog(a, &.{}, 5);
    defer short.deinit();
    try std.testing.expectError(error.InvalidRv64MultiplicationPairDictionary, Mul.degree3_source.generatePairsSerial(&short, d.ch, dict[0..255]));
}

test "MUL byte-pair native domain kernel equals the scalar reference" {
    const engine = @import("stwo_prover_engine");
    const cp = engine.air.component_prover;
    const Acc = engine.air.accumulation.DomainEvaluationAccumulator;
    const Component = Mul.degree3_component.Component;
    var coefficients: [32]M = undefined;
    for (&coefficients, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 19 + 1));
    const source = cp.Poly{ .log_size = 6, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficients) };
    const polys: [L.FIXED + L.MAIN + L.INTERACTION]cp.Poly = @splat(source);
    var headers = [_][]const cp.Poly{ polys[0..L.FIXED], polys[L.FIXED..][0..L.MAIN], polys[L.FIXED + L.MAIN ..] };
    const trace = cp.Trace{ .polys = core.pcs.TreeVec([]const cp.Poly).initOwned(&headers) };
    const d = draw();
    const component = Component{ .log_size = 5, .count = 17, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = d.ch, .byte_alpha = Q.zero(), .claim = d.claim, .pairs = d.pc };
    try std.testing.expectEqual(L.CONSTRAINTS, component.nConstraints());
    try std.testing.expectEqual(L.INTERACTION, component.interactionWidth());
    var packed_acc = try Acc.init(a, E.q(7), 6, L.CONSTRAINTS);
    defer packed_acc.deinit();
    var scalar_acc = try Acc.init(a, E.q(7), 6, L.CONSTRAINTS);
    defer scalar_acc.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &packed_acc);
    try Mul.degree3_component.testing.scalarErased(&component, &trace, &scalar_acc);
    var packed_out = try packed_acc.finalize();
    defer packed_out.deinit(a);
    var scalar_out = try scalar_acc.finalize();
    defer scalar_out.deinit(a);
    for (packed_out.columns, scalar_out.columns) |want, got| try std.testing.expectEqualSlices(M, want, got);
}
