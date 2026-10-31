const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const S = @import("shift_word_source.zig");
const A = @import("shift_word.zig");
const P = @import("shift_word_lookup.zig");
const T = @import("shift_word_packed_table.zig");
const U = @import("u16_source.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const N = 32;
fn ch() P.Challenges {
    return .{ .shift = .{ .offset = Q.fromU32Unchecked(5, 7, 11, 13), .coefficients = .{ E.q(3), E.q(7), E.q(11), E.q(13), E.q(17), E.q(19) } }, .range16 = .{ .offset = Q.fromU32Unchecked(23, 29, 31, 37), .coefficient = E.q(41) }, .function = .{ .offset = Q.fromU32Unchecked(43, 47, 53, 59), .coefficients = .{ E.q(2), E.q(3), E.q(5), E.q(7), E.q(11), E.q(13), E.q(17), E.q(19), E.q(23), E.q(29), E.q(31), E.q(37), E.q(41) } } };
}
fn facts() [6]S.Fact {
    var result: [6]S.Fact = undefined;
    for (&result, 0..) |*f, i| {
        const op: @import("operations.zig").Shift = @enumFromInt(i);
        const a: u64 = if (i % 2 == 0) 0x0123456789abcdef else 0xffffffff80000000;
        const b: u64 = 0xfedcba9800000000 + 13 * i;
        f.* = .{ .op = op, .a = a, .b = b, .c = A.nativeResult(op, a, b) };
    }
    return result;
}
const Dictionaries = struct {
    table_setup: T.Setup,
    table: T.Request,
    range_setup: U.Setup,
    range: U.Source,
    fn init(a: std.mem.Allocator, source: *const S.Source) !Dictionaries {
        var ts = try T.Setup.init(a);
        errdefer ts.deinit();
        var tr = try T.Request.init(a, &ts, source.shift_counts);
        errdefer tr.deinit();
        var rs = try U.Setup.init(a);
        errdefer rs.deinit();
        var rr = try U.Source.init(a, &rs, source.range16_counts);
        errdefer rr.deinit();
        _ = try tr.generateInteraction(ch().shift);
        _ = try rr.generate(ch().range16);
        return .{ .table_setup = ts, .table = tr, .range_setup = rs, .range = rr };
    }
    fn deinit(self: *Dictionaries) void {
        self.table.deinit();
        self.table_setup.deinit();
        self.range.deinit();
        self.range_setup.deinit();
    }
};
test "native Word16 SHIFT writes physical columns exactly once and matches Q witness and semantic lookup ledgers" {
    const a = std.testing.allocator;
    const requests = facts();
    var source = try S.Source.init(a, &requests, 5);
    defer source.deinit();
    var empty = try S.Source.init(a, &.{}, 5);
    defer empty.deinit();
    try std.testing.expectEqualSlices(M, source.fixed, empty.fixed);
    try std.testing.expectEqual(@as(usize, 26 * N), @sizeOf(S.Metadata) * source.metadata.len);
    var range_counts: [65536]u64 = @splat(0);
    const table_counts = try a.alloc(u64, T.SEMANTIC_FACTS);
    defer a.free(table_counts);
    @memset(table_counts, 0);
    for (0..N) |i| {
        var row = if (i < requests.len) A.witness(requests[i].op, requests[i].a, requests[i].b) else A.witness(.sll, 0, 0);
        if (i >= requests.len) {
            row.active = Q.zero();
            row.selectors = @splat(Q.zero());
            row.offset = @splat(Q.zero());
            row.payload[0] = Q.zero();
        }
        const values = A.rowToColumnsFor(Q, &row);
        for (values, 0..) |value, c| try std.testing.expectEqual(try value.tryIntoM31(), source.main[c * N + physical(i, 5)]);
        try std.testing.expectEqual(try row.active.tryIntoM31(), source.main[A.LOCAL_MAIN * N + physical(i, 5)]);
        for (row.payload, source.metadata[i].payload) |v, value| try std.testing.expectEqual(value, (try v.tryIntoM31()).v);
        for (0..9) |q| range_counts[(try A.rangeValueFor(Q, &row, q).tryIntoM31()).v] += 1;
        for (0..5) |q| {
            const tuple = A.tableTupleFor(Q, &row, q);
            table_counts[(try tuple[0].tryIntoM31()).v * 16 + (try tuple[1].tryIntoM31()).v] += 1;
        }
    }
    try std.testing.expectEqualSlices(u64, &range_counts, source.range16_counts);
    try std.testing.expectEqualSlices(u64, table_counts, source.shift_counts);
    try std.testing.expectEqual(@as(u64, 5 * N), (try S.massForLog(5)).shift_queries);
    try std.testing.expectError(error.InvalidShiftGeometry, S.massForLog(27));
}
fn store(data: []M, row: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * N + row] = v;
}
fn oracle(a: std.mem.Allocator, main: []const M) !struct { values: []M, claims: P.Claims } {
    const output = try a.alloc(M, P.INTERACTION * N);
    errdefer a.free(output);
    var sums = [_]Q{ Q.zero(), Q.zero(), Q.zero() };
    const challenges = ch();
    for (0..N) |i| {
        const p = physical(i, 5);
        var row_values: [P.MAIN]Q = undefined;
        for (&row_values, 0..) |*v, c| v.* = Q.fromBase(main[c * N + p]);
        const row = A.rowFromColumnsFor(Q, &row_values);
        for (0..3) |batch| {
            const tuple_a = A.tableTupleFor(Q, &row, 2 * batch);
            const da = challenges.shift.denominator(&tuple_a);
            var product = da;
            var numerator = Q.one();
            if (2 * batch + 1 < 5) {
                const tuple_b = A.tableTupleFor(Q, &row, 2 * batch + 1);
                const db = challenges.shift.denominator(&tuple_b);
                product = product.mul(db);
                numerator = da.add(db);
            }
            const inverse = try product.inv();
            store(output, p, 4 * batch, inverse);
            sums[0] = sums[0].add(numerator.mul(inverse));
        }
        for (0..5) |batch| {
            const da = challenges.range16.denominatorFor(Q, A.rangeValueFor(Q, &row, 2 * batch));
            var product = da;
            var numerator = Q.one();
            if (2 * batch + 1 < 9) {
                const db = challenges.range16.denominatorFor(Q, A.rangeValueFor(Q, &row, 2 * batch + 1));
                product = product.mul(db);
                numerator = da.add(db);
            }
            const inverse = try product.inv();
            store(output, p, 16 + 4 * batch, inverse);
            sums[1] = sums[1].add(numerator.mul(inverse));
        }
        const inverse = try challenges.function.denominatorFor(Q, row.payload).inv();
        store(output, p, 40, inverse);
        sums[2] = sums[2].sub(inverse.mul(row_values[A.LOCAL_MAIN]));
        for ([_]usize{ 12, 36, 44 }, sums) |start, sum| store(output, p, start, sum);
    }
    for ([_]usize{ 12, 36, 44 }, sums) |start, sum| for (sum.toM31Array(), 0..) |v, c| for (0..N) |row| {
        output[(start + c) * N + row] = output[(start + c) * N + row].sub(v);
    };
    return .{ .values = output, .claims = .{ .shift = sums[0], .range16 = sums[1], .function = sums[2] } };
}
test "Word16 SHIFT owned and borrowed main retire before native generation with all48 interactions unchanged" {
    const a = std.testing.allocator;
    var requests = facts();
    var source = try S.Source.init(a, &requests, 5);
    defer source.deinit();
    const reference = try oracle(a, source.main);
    defer a.free(reference.values);
    var dictionaries = try Dictionaries.init(a, &source);
    defer dictionaries.deinit();
    const borrowed = try a.alloc(M, P.MAIN * N);
    defer a.free(borrowed);
    var other = try S.Source.initWithMainBuffers(a, &requests, 5, .{ .main = borrowed });
    defer other.deinit();
    try std.testing.expectEqualSlices(M, source.main, borrowed);
    @memset(std.mem.asBytes(&requests), 0);
    try std.testing.expectError(error.BorrowedShiftMain, other.takeMainForCommit());
    const detached = try source.takeMainForCommit();
    other.releaseMain();
    @memset(detached, M.zero());
    a.free(detached);
    @memset(borrowed, M.zero());
    const claims = try source.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary);
    const other_claims = try other.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary);
    try std.testing.expectEqualDeep(reference.claims, claims);
    try std.testing.expectEqualDeep(claims, other_claims);
    try std.testing.expectEqualSlices(M, reference.values, source.interaction);
    try std.testing.expectEqualSlices(M, source.interaction, other.interaction);
    try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
    try std.testing.expectError(error.InvalidShiftSourcePhase, source.generate(ch(), &.{}, &.{}));
    var empty = try S.Source.init(a, &.{}, 5);
    defer empty.deinit();
    const empty_reference = try oracle(a, empty.main);
    defer a.free(empty_reference.values);
    empty.releaseMain();
    const empty_claims = try empty.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary);
    try std.testing.expectEqualDeep(empty_reference.claims, empty_claims);
    try std.testing.expectEqualSlices(M, empty_reference.values, empty.interaction);
}
fn initFailure(a: std.mem.Allocator, requests: []const S.Fact) !void {
    var source = try S.Source.init(a, requests, 5);
    defer source.deinit();
}
fn generateFailure(a: std.mem.Allocator, requests: []const S.Fact, table: []const Q, range: []const Q) !void {
    var source = try S.Source.init(a, requests, 5);
    defer source.deinit();
    source.releaseMain();
    _ = try source.generate(ch(), table, range);
}
test "Word16 SHIFT allocation validation dictionary poles and late ledgers publish nothing and permit retry" {
    const a = std.testing.allocator;
    const requests = facts();
    try std.testing.checkAllAllocationFailures(a, initFailure, .{&requests});
    const borrowed = try a.alloc(M, P.MAIN * N);
    defer a.free(borrowed);
    for (0..4) |fail_index| {
        @memset(borrowed, M.fromCanonical(123));
        var failure = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
        try std.testing.expectError(error.OutOfMemory, S.Source.initWithMainBuffers(failure.allocator(), &requests, 5, .{ .main = borrowed }));
        for (borrowed) |v| try std.testing.expectEqual(M.fromCanonical(123), v);
    }
    var invalid = requests;
    invalid[0].c ^= @as(u64, 1) << 48;
    try std.testing.expectError(error.InvalidShiftFact, S.Source.initWithMainBuffers(a, &invalid, 5, .{ .main = borrowed }));
    for (borrowed) |v| try std.testing.expectEqual(M.fromCanonical(123), v);
    try std.testing.expectError(error.InvalidShiftMain, S.Source.initWithMainBuffers(a, &requests, 5, .{ .main = borrowed[1..] }));
    const aliased = @as([*]S.Fact, @ptrCast(@alignCast(borrowed.ptr)))[0..1];
    try std.testing.expectError(error.OverlappingShiftInputs, S.Source.initWithMainBuffers(a, aliased, 5, .{ .main = borrowed }));
    var source = try S.Source.init(a, &requests, 5);
    defer source.deinit();
    var dictionaries = try Dictionaries.init(a, &source);
    defer dictionaries.deinit();
    try std.testing.checkAllAllocationFailures(a, generateFailure, .{ &requests, dictionaries.table.dictionary, dictionaries.range.dictionary });
    source.releaseMain();
    const inverse = dictionaries.table.dictionary[17];
    dictionaries.table.dictionary[17] = inverse.add(Q.one());
    try std.testing.expectError(error.InvalidShiftDictionary, source.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary));
    dictionaries.table.dictionary[17] = inverse;
    const range_inverse = dictionaries.range.dictionary[1];
    dictionaries.range.dictionary[1] = range_inverse.add(Q.one());
    try std.testing.expectError(error.InvalidShiftDictionary, source.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary));
    dictionaries.range.dictionary[1] = range_inverse;
    const first_inverse = dictionaries.table.dictionary[0];
    dictionaries.table.dictionary[0].c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidShiftDictionary, source.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary));
    dictionaries.table.dictionary[0] = first_inverse;
    var poles = ch();
    poles.function = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    try std.testing.expectError(error.DivisionByZero, source.generate(poles, dictionaries.table.dictionary, dictionaries.range.dictionary));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    try std.testing.expectEqual(@as(usize, N), source.metadata.len);
    source.shift_counts[0] -= 1;
    source.shift_counts[16] += 1;
    try std.testing.expectError(error.InvalidShiftMetadata, source.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    source.shift_counts[0] += 1;
    source.shift_counts[16] -= 1;
    _ = try source.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary);
}

test "Word16 SHIFT full4096 interaction windows preserve all physical residuals" {
    const a = std.testing.allocator;
    const requests = facts();
    const log: u32 = 13;
    const n: usize = 1 << log;
    var source = try S.Source.init(a, &requests, log);
    defer source.deinit();
    var dictionaries = try Dictionaries.init(a, &source);
    defer dictionaries.deinit();
    const claims = try source.generate(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary);
    for (0..n) |logical| {
        const pos = physical(logical, log);
        const previous = physical((logical + n - 1) % n, log);
        var main: [P.MAIN]Q = undefined;
        var inter: [P.INTERACTION]Q = undefined;
        var prior: [P.INTERACTION]Q = undefined;
        for (&main, 0..) |*value, c| value.* = Q.fromBase(source.main[c * n + pos]);
        for (&inter, &prior, 0..) |*value, *pv, c| {
            value.* = Q.fromBase(source.interaction[c * n + pos]);
            pv.* = Q.fromBase(source.interaction[c * n + previous]);
        }
        var residuals: [P.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        P.emitFor(Q, &main, &inter, &prior, E.q(@intFromBool(logical == 0)), E.q(@intFromBool(logical + 1 == n)), claims, ch(), &sink);
        try std.testing.expectEqual(@as(usize, P.CONSTRAINTS), sink.count);
        for (residuals) |value| try std.testing.expect(value.isZero());
    }
}
