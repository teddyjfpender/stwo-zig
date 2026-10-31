//! Small diagnostic witnesses, including bypassed-constructor AIR attacks.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const X = rv.word16_v1.alu_experiment;
const A = X.equations;
const P = X.lookup;
const C = rv.word16_v1.binary_component;
const U = X.range_source;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const N = 32;
pub const Attack = enum { none, result, carry, sign_range, sum_zero_range };
fn row(i: usize) !A.RowFor(Q) {
    return switch (i) {
        0 => A.witness(.add, 0xffffffffffffffff, 1),
        1 => A.witness(.sub, 0, 1),
        2 => A.witness(.addw, 0x7fffffff, 1),
        3 => A.witness(.subw, 0x80000000, 1),
        4 => A.witness(.slt, 1, 0),
        5 => A.witness(.sltu, 0x8000000000000000, 1),
        6 => A.witness(.eq, 0xffff0000ffff, 0xffff0000ffff),
        7 => A.witness(.ne, 0x1234, 0x1234),
        8 => A.witness(.ge, 0x7fffffffffffffff, 0x8000000000000000),
        9 => A.witness(.geu, 0, 0xffffffffffffffff),
        else => blk: {
            var r = try A.witness(.add, 0, 0);
            r.active = Q.zero();
            r.selectors[0] = Q.zero();
            break :blk r;
        },
    };
}
/// Narrow semantic statement, independent of physical ALU hint encoding.
pub fn expectedRoster() !C.ExpectedRoster {
    var roster: C.ExpectedRoster = @splat(@splat(M.zero()));
    for (0..N) |i| {
        const r = try row(i);
        for (r.payload, 0..) |value, c| roster[i][c] = try value.tryIntoM31();
        roster[i][13] = try r.active.tryIntoM31();
    }
    return roster;
}
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    roster: C.ExpectedRoster,
    known_fixed: []M,
    known_main: []M,
    known_interaction: []M = &.{},
    counts: []u64,
    setup: U.Setup,
    range: U.Source,
    pub fn init(a: std.mem.Allocator, attack: Attack) !Fixture {
        _ = try rv.word16_v1.function_bus.admitPositiveMass(&.{20 * N});
        const fixed = try a.alloc(M, 2 * N);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        fixed[rv.witness.physical(0, 5)] = M.one();
        fixed[N + rv.witness.physical(N - 1, 5)] = M.one();
        const main = try a.alloc(M, P.MAIN * N);
        errdefer a.free(main);
        const counts = try a.alloc(u64, U.SIZE);
        errdefer a.free(counts);
        @memset(counts, 0);
        var roster: C.ExpectedRoster = @splat(@splat(M.zero()));
        for (0..N) |i| {
            var r = if (i == 6 and attack == .sum_zero_range) try A.witness(.eq, 65536, 1) else try row(i);
            const honest = r;
            if (i == 0 and attack == .result) r.payload[9] = r.payload[9].add(Q.one());
            if (i == 0 and attack == .carry) r.carry[0] = rv.evaluation.q(2);
            if (i == 4 and attack == .sign_range) {
                r.sign[0] = Q.one();
                r.low[0] = rv.evaluation.q(32768).neg();
                r.signed_less = Q.one();
                r.payload[9] = Q.one();
                var residuals: [A.CONSTRAINTS]Q = undefined;
                var sink = rv.evaluation.Sink{ .values = &residuals };
                A.emitFor(Q, &r, &sink);
                for (residuals) |v| if (!v.isZero()) return error.InvalidAluForgeryOracle;
            }
            if (i == 6 and attack == .sum_zero_range) {
                r.difference = .{ Q.one().neg(), Q.one(), Q.zero(), Q.zero() };
                r.borrow = @splat(Q.zero());
                r.zero = Q.one();
                r.inverse = Q.zero();
                r.sign[3] = Q.zero();
                r.low[3] = Q.one();
                r.payload[9] = Q.one();
                var residuals: [A.CONSTRAINTS]Q = undefined;
                var sink = rv.evaluation.Sink{ .values = &residuals };
                A.emitFor(Q, &r, &sink);
                for (residuals) |v| if (!v.isZero()) return error.InvalidAluSumForgeryOracle;
            }
            const values = P.rowToColumnsFor(Q, r);
            const physical = rv.witness.physical(i, 5);
            for (values, 0..) |v, c| main[c * N + physical] = try v.tryIntoM31();
            main[A.LOCAL_MAIN * N + physical] = try r.active.tryIntoM31();
            for (r.payload, 0..) |v, c| roster[i][c] = try v.tryIntoM31();
            roster[i][13] = try r.active.tryIntoM31();
            for (0..A.RANGE_QUERIES) |query| {
                const value = (try A.rangeValueFor(Q, &honest, query).tryIntoM31()).v;
                if (value >= U.SIZE) return error.InvalidAluNativeRange;
                counts[value] += 1;
            }
        }
        const known_fixed = try C.expectedMainFixed(a);
        errdefer a.free(known_fixed);
        const known_main = try C.expectedMainValues(a, &roster);
        errdefer a.free(known_main);
        var setup = try U.Setup.init(a);
        errdefer setup.deinit();
        return .{ .allocator = a, .fixed = fixed, .main = main, .roster = roster, .known_fixed = known_fixed, .known_main = known_main, .counts = counts, .setup = setup, .range = try U.Source.init(a, &setup, counts) };
    }
    pub fn deinit(self: *Fixture) void {
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.main);
        a.free(self.interaction);
        a.free(self.known_fixed);
        a.free(self.known_main);
        a.free(self.known_interaction);
        self.range.deinit();
        self.setup.deinit();
        a.free(self.counts);
        self.* = undefined;
    }
    pub fn columns(self: *const Fixture, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const a = self.allocator;
        const small = switch (tree) {
            0 => [_][]const M{ self.fixed, self.known_fixed },
            1 => [_][]const M{ self.main, self.known_main },
            2 => [_][]const M{ self.interaction, self.known_interaction },
            else => return error.InvalidAluTree,
        };
        const large = switch (tree) {
            0 => self.setup.fixed,
            1 => self.range.main,
            2 => self.range.interaction,
            else => unreachable,
        };
        const headers = try a.alloc(engine.pcs.ColumnEvaluation, small[0].len / N + small[1].len / N + large.len / U.SIZE);
        var cursor: usize = 0;
        for (small) |data| for (0..data.len / N) |c| {
            headers[cursor] = .{ .log_size = 5, .values = data[c * N ..][0..N] };
            cursor += 1;
        };
        for (0..large.len / U.SIZE) |c| {
            headers[cursor] = .{ .log_size = 16, .values = large[c * U.SIZE ..][0..U.SIZE] };
            cursor += 1;
        }
        return headers;
    }
    pub fn generate(self: *Fixture, ch: P.Challenges) ![4]Q {
        const a = self.allocator;
        const output = try a.alloc(M, P.INTERACTION * N);
        errdefer a.free(output);
        const known = try a.alloc(M, 8 * N);
        errdefer a.free(known);
        const table_claim = try self.range.generate(ch.range16);
        var range_sum = Q.zero();
        var function_sum = Q.zero();
        var known_sum = Q.zero();
        for (0..N) |i| {
            const physical = rv.witness.physical(i, 5);
            var main: [P.MAIN]Q = undefined;
            for (&main, 0..) |*v, c| v.* = Q.fromBase(self.main[c * N + physical]);
            const r = P.rowFromColumnsFor(Q, &main);
            for (0..10) |batch| {
                const dx = ch.range16.denominatorFor(Q, A.rangeValueFor(Q, &r, 2 * batch));
                const dy = ch.range16.denominatorFor(Q, A.rangeValueFor(Q, &r, 2 * batch + 1));
                const inverse = try dx.mul(dy).inv();
                store(output, physical, 4 * batch, inverse);
                range_sum = range_sum.add(dx.add(dy).mul(inverse));
            }
            store(output, physical, 40, range_sum);
            const inverse = try ch.function.denominatorFor(Q, r.payload).inv();
            store(output, physical, 44, inverse);
            function_sum = function_sum.sub(inverse.mul(main[A.LOCAL_MAIN]));
            store(output, physical, 48, function_sum);
            var tuple: [13]Q = undefined;
            for (&tuple, 0..) |*v, c| v.* = Q.fromBase(self.known_main[c * N + physical]);
            const known_inverse = try ch.function.denominatorFor(Q, tuple).inv();
            store(known, physical, 0, known_inverse);
            known_sum = known_sum.add(known_inverse.mulM31(self.known_main[13 * N + physical]));
            store(known, physical, 4, known_sum);
        }
        for ([_]usize{ 40, 48 }, [_]Q{ range_sum, function_sum }) |start, claim| {
            const correction = claim.toM31Array();
            for (correction, 0..) |v, c| for (0..N) |r| {
                output[(start + c) * N + r] = output[(start + c) * N + r].sub(v);
            };
        }
        const correction = known_sum.toM31Array();
        for (correction, 0..) |v, c| for (0..N) |r| {
            known[(4 + c) * N + r] = known[(4 + c) * N + r].sub(v);
        };
        self.interaction = output;
        self.known_interaction = known;
        return .{ range_sum, function_sum, known_sum, table_claim };
    }
};
fn store(data: []M, row_: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * N + row_] = v;
}
