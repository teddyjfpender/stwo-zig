const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const L = @import("layout.zig");
const A = @import("equations.zig");
const P = @import("lookup.zig");
const S = @import("source.zig");
const physical = @import("../../../program/provider.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
const requests = [_]S.Request{
    .{ .opcode = .DIVU, .a = 15, .b = 4, .result = 3 },
    .{ .opcode = .REMU, .a = 15, .b = 4, .result = 3 },
    .{ .opcode = .DIV, .a = @bitCast(@as(i64, -15)), .b = 4, .result = @bitCast(@as(i64, -3)) },
    .{ .opcode = .DIVW, .a = 0x1234567880000000, .b = 0xabcdef01ffffffff, .result = 0xffffffff80000000 },
    .{ .opcode = .REMW, .a = 0x1234567880000000, .b = 0xffffffff, .result = 0 },
    .{ .opcode = .DIVUW, .a = 0xffffffff, .b = 2, .result = 0x7fffffff },
    .{ .opcode = .DIV, .a = 0x8000000000000000, .b = 0xffffffffffffffff, .result = 0x8000000000000000 },
    .{ .opcode = .REMUW, .a = 0xdeadbeefffffffff, .b = 0x100000000, .result = 0xffffffffffffffff },
};
fn challenges() P.Challenges {
    var out = P.Challenges{ .function = .{ .offset = Q.fromM31Array(.{ M.fromCanonical(12345), M.one(), M.zero(), M.zero() }), .coefficients = undefined }, .range16 = .{ .offset = Q.fromM31Array(.{ M.fromCanonical(101), M.fromCanonical(2), M.zero(), M.zero() }), .coefficient = E.q(7) } };
    for (&out.function.coefficients, 0..) |*v, i| v.* = E.q(@intCast(i + 3));
    return out;
}
fn mainRow(source: *const S.Source, pos: usize) [L.MAIN]Q {
    var result: [L.MAIN]Q = undefined;
    for (&result, 0..) |*v, c| v.* = Q.fromBase(source.main[c * source.domainSize() + pos]);
    return result;
}
test "DIV query metadata and all physical interactions match the committed authority including padding" {
    for ([_]usize{ 0, requests.len }) |count| {
        var source = try S.Source.initWithLog(a, requests[0..count], 5);
        defer source.deinit();
        const n = source.domainSize();
        var mass: u64 = 0;
        for (source.counts16) |v| mass += v;
        try std.testing.expectEqual(@as(u64, L.RANGE_QUERIES * 32), mass);
        for (0..n) |i| {
            const main = mainRow(&source, physical(i, 5));
            const metadata = source.metadata[i].queryRow();
            try std.testing.expectEqualDeep(A.rangeValuesFor(Q, &main), A.rangeValuesFor(Q, &metadata));
            for ([_]?bool{ null, false, true }) |support| try std.testing.expectEqualDeep(A.tupleFor(Q, &main, support), A.tupleFor(Q, &metadata, support));
        }
        const ch = challenges();
        const claim = try source.generateInteraction(ch);
        try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
        for (0..n) |i| {
            const pos = physical(i, 5);
            const prev = physical((i + n - 1) % n, 5);
            const main = mainRow(&source, pos);
            const pm = mainRow(&source, prev);
            var fixed: [L.FIXED]Q = undefined;
            var inter: [L.INTERACTION]Q = undefined;
            var previous: [4]Q = undefined;
            for (&fixed, 0..) |*v, c| v.* = Q.fromBase(source.fixed[c * n + pos]);
            for (&inter, 0..) |*v, c| v.* = Q.fromBase(source.interaction[c * n + pos]);
            for (&previous, 0..) |*v, c| v.* = Q.fromBase(source.interaction[(L.PREFIX + c) * n + prev]);
            var residuals: [L.CONSTRAINTS]Q = undefined;
            var sink = E.Sink{ .values = &residuals };
            P.emitFor(Q, &fixed, &main, pm[L.COUNT], E.q(@intCast(count)), &inter, Q.fromPartialEvals(previous), claim, ch, &sink);
            try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), sink.count);
            for (residuals) |v| try std.testing.expect(v.isZero());
        }
    }
}
test "DIV owned and borrowed rows and interaction metadata survive destruction of MAIN" {
    var owned = try S.Source.initWithLog(a, &requests, 5);
    defer owned.deinit();
    const main = try a.alloc(M, L.MAIN * 32);
    defer a.free(main);
    var borrowed = try S.Source.initWithBorrowedMain(a, &requests, 5, main);
    defer borrowed.deinit();
    try std.testing.expectEqualSlices(M, owned.main, borrowed.main);
    try std.testing.expectEqualSlices(u64, owned.counts16, borrowed.counts16);
    var other = try S.Source.initWithLog(a, requests[0..1], 5);
    defer other.deinit();
    try std.testing.expectEqualSlices(M, owned.fixed, other.fixed);
    try owned.releaseMain();
    try borrowed.releaseMain();
    @memset(main, M.fromCanonical(99));
    const x = try owned.generateInteraction(challenges());
    const y = try borrowed.generateInteraction(challenges());
    try std.testing.expectEqual(x, y);
    try std.testing.expectEqualSlices(M, owned.interaction, borrowed.interaction);
    for (main) |v| try std.testing.expectEqual(M.fromCanonical(99), v);
}
test "DIV strict function and range poles preserve advice and allow a clean retry" {
    var source = try S.Source.initWithLog(a, &requests, 5);
    defer source.deinit();
    try source.releaseMain();
    var pole = challenges();
    pole.function.offset = Q.zero();
    pole.function.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, source.generateInteraction(pole));
    try std.testing.expectEqual(@as(usize, 32), source.metadata.len);
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    pole = challenges();
    pole.range16.offset = Q.zero();
    try std.testing.expectError(error.DivisionByZero, source.generateInteraction(pole));
    try std.testing.expectEqual(@as(usize, 32), source.metadata.len);
    _ = try source.generateInteraction(challenges());
    try std.testing.expectError(error.InvalidRv64DivisionPhase, source.generateInteraction(challenges()));
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    var source = try S.Source.initWithLog(allocator, &requests, 5);
    defer source.deinit();
    try source.releaseMain();
    _ = try source.generateInteraction(challenges());
}
fn borrowedAllocationCase(allocator: std.mem.Allocator, main: []M) !void {
    var source = try S.Source.initWithBorrowedMain(allocator, &requests, 5, main);
    defer source.deinit();
    try source.releaseMain();
    _ = try source.generateInteraction(challenges());
}
test "DIV source owned and borrowed allocation failures release every private owner" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    const main = try a.alloc(M, L.MAIN * 32);
    defer a.free(main);
    try std.testing.checkAllAllocationFailures(a, borrowedAllocationCase, .{main});
}
test "DIV source rejects malformed geometry opcode and aliased MAIN before writes" {
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidRv64DivisionShape, S.Source.initWithLog(failing.allocator(), &requests, 23));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    const bad = [_]S.Request{.{ .opcode = .ADD, .a = 1, .b = 2, .result = 3 }};
    try std.testing.expectError(error.InvalidProductDivisionOpcode, S.Source.initWithLog(failing.allocator(), &bad, 5));
    const main = try a.alignedAlloc(M, comptime std.mem.Alignment.fromByteUnits(@alignOf(S.Request)), L.MAIN * 32);
    defer a.free(main);
    @memset(main, M.fromCanonical(99));
    try std.testing.expectError(error.InvalidCryptoMainBuffers, S.Source.initWithBorrowedMain(a, &requests, 5, main[1..]));
    for (main) |v| try std.testing.expectEqual(M.fromCanonical(99), v);
    const alias = std.mem.bytesAsSlice(S.Request, @as([]align(@alignOf(S.Request)) u8, @alignCast(std.mem.sliceAsBytes(main)[0..@sizeOf(S.Request)])));
    alias[0] = requests[0];
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, S.Source.initWithBorrowedMain(a, alias, 5, main));
    try std.testing.expectEqual(requests[0].a, alias[0].a);
    for (main[@sizeOf(S.Request) / @sizeOf(M) ..]) |v| try std.testing.expectEqual(M.fromCanonical(99), v);
}
