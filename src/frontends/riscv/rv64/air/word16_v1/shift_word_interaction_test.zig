//! Joined parallel SHIFT interaction generation against the serial oracle:
//! identical claims and identical interaction bytes for every worker count,
//! including nondivisible teams, weighted facts and padding-heavy domains.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const E = @import("../evaluation.zig");
const S = @import("shift_word_source.zig");
const A = @import("shift_word.zig");
const P = @import("shift_word_lookup.zig");
const T = @import("shift_word_packed_table.zig");
const U = @import("u16_source.zig");
const G = @import("shift_word_interaction.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
fn ch() P.Challenges {
    return .{ .shift = .{ .offset = Q.fromU32Unchecked(5, 7, 11, 13), .coefficients = .{ E.q(3), E.q(7), E.q(11), E.q(13), E.q(17), E.q(19) } }, .range16 = .{ .offset = Q.fromU32Unchecked(23, 29, 31, 37), .coefficient = E.q(41) }, .function = .{ .offset = Q.fromU32Unchecked(43, 47, 53, 59), .coefficients = .{ E.q(2), E.q(3), E.q(5), E.q(7), E.q(11), E.q(13), E.q(17), E.q(19), E.q(23), E.q(29), E.q(31), E.q(37), E.q(41) } } };
}
fn facts(count: usize) ![]S.Fact {
    const out = try a.alloc(S.Fact, count);
    for (out, 0..) |*f, i| {
        const x = @as(u64, @intCast(i + 1)) *% 0x9e3779b97f4a7c15;
        const y = ~x ^ (x << 13);
        const op: @import("operations.zig").Shift = @enumFromInt(i % 6);
        f.* = .{ .op = op, .a = x, .b = y, .c = A.nativeResult(op, x, y) };
    }
    return out;
}
const Dictionaries = struct {
    table_setup: T.Setup,
    table: T.Request,
    range_setup: U.Setup,
    range: U.Source,
    fn init(source: *const S.Source) !Dictionaries {
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
fn build(input: []const S.Fact, weights: ?[]const u32, log: u32) !S.Source {
    var source = if (weights) |w| try S.Source.testing.initWeightedSerial(a, input, w, log) else try S.Source.testing.initSerial(a, input, log);
    source.releaseMain();
    return source;
}
fn expectSame(expected: []const M, actual: []const M) !void {
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
}
test "joined parallel SHIFT interactions equal the serial oracle byte for byte at1 2 3 8workers" {
    const log: u32 = 14;
    const n: usize = 1 << log;
    for ([_]usize{ n, n - 4097, 5000, 1 }) |count| {
        const input = try facts(count);
        defer a.free(input);
        const weights = try a.alloc(u32, count);
        defer a.free(weights);
        for (weights, 0..) |*w, i| w.* = @intCast((i * 7) % 5);
        for ([_]bool{ false, true }) |weighted| {
            const w: ?[]const u32 = if (weighted) weights else null;
            var oracle = try build(input, w, log);
            defer oracle.deinit();
            var dictionaries = try Dictionaries.init(&oracle);
            defer dictionaries.deinit();
            const expected = try oracle.generateSerial(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary);
            for ([_]usize{ 1, 2, 3, 8 }) |workers| {
                var pool: work.WorkPool = .{};
                try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = G.MIN_STACK_BYTES, .backing_allocator = a });
                defer pool.deinit();
                var source = try build(input, w, log);
                defer source.deinit();
                const claims = try G.generate(&source, ch(), dictionaries.table.dictionary, dictionaries.range.dictionary, &pool);
                try std.testing.expect(claims.shift.eql(expected.shift) and claims.range16.eql(expected.range16) and claims.function.eql(expected.function));
                try std.testing.expectEqual(P.INTERACTION * n, source.interaction.len);
                try expectSame(oracle.interaction, source.interaction);
                try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
                try std.testing.expectEqual(workers, pool.availableWorkers());
            }
        }
    }
}
test "joined parallel SHIFT rejects corrupt dictionaries and ledgers and drains failed submissions before a retry" {
    const log: u32 = 14;
    const input = try facts(6000);
    defer a.free(input);
    var oracle = try build(input, null, log);
    defer oracle.deinit();
    var dictionaries = try Dictionaries.init(&oracle);
    defer dictionaries.deinit();
    _ = try oracle.generateSerial(ch(), dictionaries.table.dictionary, dictionaries.range.dictionary);
    var pool: work.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = G.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    var source = try build(input, null, log);
    defer source.deinit();
    const late = dictionaries.table.dictionary[16 * 60000 + 3];
    dictionaries.table.dictionary[16 * 60000 + 3] = late.add(Q.one());
    try std.testing.expectError(error.InvalidShiftDictionary, G.generate(&source, ch(), dictionaries.table.dictionary, dictionaries.range.dictionary, &pool));
    dictionaries.table.dictionary[16 * 60000 + 3] = late;
    source.shift_counts[0] -= 1;
    source.shift_counts[16] += 1;
    try std.testing.expectError(error.InvalidShiftMetadata, G.generate(&source, ch(), dictionaries.table.dictionary, dictionaries.range.dictionary, &pool));
    source.shift_counts[0] += 1;
    source.shift_counts[16] -= 1;
    var poles = ch();
    poles.function = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    try std.testing.expectError(error.DivisionByZero, G.generate(&source, poles, dictionaries.table.dictionary, dictionaries.range.dictionary, &pool));
    for ([_]usize{ 0, 1 }) |which| for ([_]usize{ 0, 2 }) |after| {
        try std.testing.expectError(error.InjectedNativePrefixSubmissionFailure, G.testing.failSubmission(&source, ch(), dictionaries.table.dictionary, dictionaries.range.dictionary, &pool, which, after));
        try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
        try std.testing.expectEqual(source.size(), source.metadata.len);
        try std.testing.expectEqual(@as(usize, 4), pool.availableWorkers());
    };
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    source.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, G.generate(&source, ch(), dictionaries.table.dictionary, dictionaries.range.dictionary, &pool));
    source.allocator = a;
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    _ = try G.generate(&source, ch(), dictionaries.table.dictionary, dictionaries.range.dictionary, &pool);
    try expectSame(oracle.interaction, source.interaction);
}
