//! Diagnostic SHIFT lookup witnesses and bypassed-constructor mutations.
const std = @import("std");
const Profile = @import("fixture_profile.zig");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const X = rv.word16_v1.shift_word_experiment;
const S = X.equations;
const P = X.lookup;
const C = rv.word16_v1.binary_component;
const U = rv.word16_v1.alu_experiment.range_source;
const Tables = rv.providers.tables;
const WordTable = X.table;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const N = 32;
pub const Attack = enum { none, result, table, quotient_alias, sign_alias };
fn row(i: usize) S.RowFor(Q) {
    return switch (i) {
        0 => S.witness(.sll, 1, 1),
        1 => S.witness(.srl, 0x8000000000000000, 63),
        2 => S.witness(.sra, 0x8000000000000000, 32),
        3 => S.witness(.sllw, 0, 0),
        4 => S.witness(.srlw, 0xffffffff80000000, 31),
        5 => S.witness(.sraw, 0x0000000080000000, 63),
        6 => S.witness(.sll, 1, 0),
        else => blk: {
            var r = S.witness(.sll, 0, 0);
            r.active = Q.zero();
            r.selectors = @splat(Q.zero());
            r.offset = @splat(Q.zero());
            r.payload[0] = Q.zero();
            break :blk r;
        },
    };
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
    shift_setup: WordTable.Setup,
    shift: WordTable.Request,
    pub fn init(a: std.mem.Allocator, attack: Attack) !Fixture {
        return initWithRecorder(a, attack, null);
    }
    pub fn initWithRecorder(a: std.mem.Allocator, attack: Attack, recorder: ?*Profile.Recorder) !Fixture {
        _ = try rv.word16_v1.function_bus.admitPositiveMass(&.{9 * N});
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
        const shift_counts = try a.alloc(u64, WordTable.SIZE);
        defer a.free(shift_counts);
        @memset(shift_counts, 0);
        var roster: C.ExpectedRoster = @splat(@splat(M.zero()));
        for (0..N) |i| {
            var r = row(i);
            const honest = r;
            if (i == 0 and attack == .result) r.payload[9] = r.payload[9].add(Q.one());
            if (i == 0 and attack == .table) {
                r.table_outputs[0][0] = rv.evaluation.q(3);
                r.payload[9] = rv.evaluation.q(3);
            }
            if (i == 6 and attack == .quotient_alias) {
                r.payload[5] = Q.one();
                r.quotient = rv.evaluation.q(1 << 25);
            }
            if (i == 3 and attack == .sign_alias) {
                r.sign[2] = Q.one();
                r.payload[11] = rv.evaluation.q(65535);
                r.payload[12] = rv.evaluation.q(65535);
            }
            if ((attack == .table and i == 0) or (attack == .quotient_alias and i == 6) or (attack == .sign_alias and i == 3)) {
                var residuals: [S.CONSTRAINTS]Q = undefined;
                var sink = rv.evaluation.Sink{ .values = &residuals };
                S.emitFor(Q, &r, &sink);
                if (sink.count != S.CONSTRAINTS) return error.InvalidShiftConstraintCount;
                for (residuals) |v| if (!v.isZero()) return error.InvalidShiftForgeryOracle;
            }
            const values = S.rowToColumnsFor(Q, &r);
            const physical = rv.witness.physical(i, 5);
            for (values, 0..) |v, c| main[c * N + physical] = try v.tryIntoM31();
            main[S.LOCAL_MAIN * N + physical] = try r.active.tryIntoM31();
            for (r.payload, 0..) |v, c| roster[i][c] = try v.tryIntoM31();
            roster[i][13] = try r.active.tryIntoM31();
            for (0..S.RANGE_QUERIES) |query| {
                const value = (try S.rangeValueFor(Q, &honest, query).tryIntoM31()).v;
                if (value >= U.SIZE) return error.InvalidShiftNativeRange;
                counts[value] += 1;
            }
            for (0..S.TABLE_QUERIES) |query| {
                const tuple = S.tableTupleFor(Q, &honest, query);
                var native: Tables.Tuple = undefined;
                for (tuple, 0..) |v, j| native[j] = (try v.tryIntoM31()).v;
                shift_counts[try WordTable.rowIndex(native)] += 1;
            }
        }
        const known_fixed = try C.expectedMainFixed(a);
        errdefer a.free(known_fixed);
        const known_main = try C.expectedMainValues(a, &roster);
        errdefer a.free(known_main);
        var setup = try U.Setup.init(a);
        errdefer setup.deinit();
        var range = try U.Source.init(a, &setup, counts);
        errdefer range.deinit();
        var shift_setup = blk: {
            var scope = try Profile.Scope.begin(recorder, "table.setup", "Build immutable shift table");
            defer scope.end();
            break :blk try WordTable.Setup.init(a);
        };
        errdefer shift_setup.deinit();
        const shift = blk: {
            var scope = try Profile.Scope.begin(recorder, "table.main", "Build precommitted shift multiplicities");
            defer scope.end();
            break :blk try WordTable.Request.init(a, shift_counts);
        };
        return .{ .allocator = a, .fixed = fixed, .main = main, .roster = roster, .known_fixed = known_fixed, .known_main = known_main, .counts = counts, .setup = setup, .range = range, .shift_setup = shift_setup, .shift = shift };
    }
    pub fn deinit(self: *Fixture) void {
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.main);
        a.free(self.interaction);
        a.free(self.known_fixed);
        a.free(self.known_main);
        a.free(self.known_interaction);
        self.shift.deinit();
        self.shift_setup.deinit();
        self.range.deinit();
        self.setup.deinit();
        a.free(self.counts);
        self.* = undefined;
    }
    pub fn columns(self: *const Fixture, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const data = switch (tree) {
            0 => [_][]const M{ self.fixed, self.known_fixed, self.shift_setup.fixed, self.setup.fixed },
            1 => [_][]const M{ self.main, self.known_main, self.shift.main, self.range.main },
            2 => [_][]const M{ self.interaction, self.known_interaction, self.shift.interaction, self.range.interaction },
            else => return error.InvalidShiftTree,
        };
        const logs = [_]u32{ 5, 5, 20, 16 };
        var count: usize = 0;
        for (data, logs) |part, log| count += part.len >> @intCast(log);
        const headers = try self.allocator.alloc(engine.pcs.ColumnEvaluation, count);
        var cursor: usize = 0;
        for (data, logs) |part, log| {
            const n = @as(usize, 1) << @intCast(log);
            for (0..part.len / n) |i| {
                headers[cursor] = .{ .log_size = log, .values = part[i * n ..][0..n] };
                cursor += 1;
            }
        }
        return headers;
    }
    pub fn generate(self: *Fixture, ch: P.Challenges) ![6]Q {
        return self.generateWithRecorder(ch, null);
    }
    pub fn generateWithRecorder(self: *Fixture, ch: P.Challenges, recorder: ?*Profile.Recorder) ![6]Q {
        const a = self.allocator;
        const output = try a.alloc(M, P.INTERACTION * N);
        errdefer a.free(output);
        const known = try a.alloc(M, 8 * N);
        errdefer a.free(known);
        const shift_claim = blk: {
            var scope = try Profile.Scope.begin(recorder, "table.interaction", "Build shift denominators inverses and prefix");
            defer scope.end();
            break :blk try self.shift.generateInteraction(ch.shift);
        };
        const range_claim = blk: {
            var scope = try Profile.Scope.begin(recorder, "range.interaction", "Build U16 dictionary and prefix");
            defer scope.end();
            break :blk try self.range.generate(ch.range16);
        };
        var consumer_scope = try Profile.Scope.begin(recorder, "consumer.interaction", "Build consumer lookup witnesses");
        defer consumer_scope.end();
        var shift_sum = Q.zero();
        var range_sum = Q.zero();
        var function_sum = Q.zero();
        var known_sum = Q.zero();
        for (0..N) |i| {
            const physical = rv.witness.physical(i, 5);
            var main: [P.MAIN]Q = undefined;
            for (&main, 0..) |*v, c| v.* = Q.fromBase(self.main[c * N + physical]);
            const r = S.rowFromColumnsFor(Q, &main);
            for (0..P.encoding.PAIRS) |pair| {
                const qa = 2 * pair;
                const qb = qa + 1;
                const dx = P.unitDenominatorFor(Q, &r, qa, ch);
                const dy = P.unitDenominatorFor(Q, &r, qb, ch);
                const inverse = try dx.mul(dy).inv();
                store(output, physical, 4 * pair, inverse);
                const ix = try dx.inv();
                const iy = try dy.inv();
                if (qa < 5) shift_sum = shift_sum.add(ix) else range_sum = range_sum.add(ix);
                if (qb < 5) shift_sum = shift_sum.add(iy) else range_sum = range_sum.add(iy);
            }
            const inverse = try ch.function.denominatorFor(Q, r.payload).inv();
            store(output, physical, P.FUNCTION_INVERSE, inverse);
            function_sum = function_sum.sub(inverse.mul(main[S.LOCAL_MAIN]));
            store(output, physical, P.PREFIX, shift_sum.add(range_sum).add(function_sum));
            var tuple: [13]Q = undefined;
            for (&tuple, 0..) |*v, c| v.* = Q.fromBase(self.known_main[c * N + physical]);
            const known_inverse = try ch.function.denominatorFor(Q, tuple).inv();
            store(known, physical, 0, known_inverse);
            known_sum = known_sum.add(known_inverse.mulM31(self.known_main[13 * N + physical]));
            store(known, physical, 4, known_sum);
        }
        for (shift_sum.add(range_sum).add(function_sum).toM31Array(), 0..) |v, c| for (0..N) |r| {
            output[(P.PREFIX + c) * N + r] = output[(P.PREFIX + c) * N + r].sub(v);
        };
        for (known_sum.toM31Array(), 0..) |v, c| for (0..N) |r| {
            known[(4 + c) * N + r] = known[(4 + c) * N + r].sub(v);
        };
        self.interaction = output;
        self.known_interaction = known;
        return .{ shift_sum, range_sum, function_sum, known_sum, shift_claim, range_claim };
    }
};
fn store(data: []M, row_: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * N + row_] = v;
}
