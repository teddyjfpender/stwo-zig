const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = front.rv64_air.word16_v1;
const X = B.shift_word_packed_experiment;
const S = X.source;
const U = B.alu_experiment.range_source;
const P = X.lookup;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn inputs(n: usize) ![]S.Fact {
    const out = try a.alloc(S.Fact, n);
    for (out, 0..) |*f, i| {
        const x = @as(u64, @intCast(i)) *% 0x9e3779b97f4a7c15;
        const y = ~x ^ (x << 13);
        const op: B.operations.Shift = @enumFromInt(i % 6);
        f.* = .{ .op = op, .a = x, .b = y, .c = X.equations.nativeResult(op, x, y) };
    }
    return out;
}
fn challenges() P.Challenges {
    const Q = front.rv64_air.evaluation.Q;
    const q = front.rv64_air.evaluation.q;
    return .{ .shift = .{ .offset = Q.fromU32Unchecked(5, 7, 11, 13), .coefficients = .{ q(3), q(7), q(11), q(13), q(17), q(19) } }, .range16 = .{ .offset = Q.fromU32Unchecked(23, 29, 31, 37), .coefficient = q(41) }, .function = .{ .offset = Q.fromU32Unchecked(43, 47, 53, 59), .coefficients = .{ q(2), q(3), q(5), q(7), q(11), q(13), q(17), q(19), q(23), q(29), q(31), q(37), q(41) } } };
}
const Dictionaries = struct {
    table_setup: X.table.Setup,
    table: X.table.Request,
    range_setup: U.Setup,
    range: U.Source,
    fn init(source: *const S.Source) !Dictionaries {
        var ts = try X.table.Setup.init(a);
        errdefer ts.deinit();
        var tr = try X.table.Request.init(a, &ts, source.shift_counts);
        errdefer tr.deinit();
        var rs = try U.Setup.init(a);
        errdefer rs.deinit();
        var rr = try U.Source.init(a, &rs, source.range16_counts);
        errdefer rr.deinit();
        _ = try tr.generateInteraction(challenges().shift);
        _ = try rr.generate(challenges().range16);
        return .{ .table_setup = ts, .table = tr, .range_setup = rs, .range = rr };
    }
    fn deinit(self: *Dictionaries) void {
        self.table.deinit();
        self.table_setup.deinit();
        self.range.deinit();
        self.range_setup.deinit();
    }
};
test "SHIFT native1 3 16worker physical rows metadata histograms interactions and claims equal serial" {
    const facts = try inputs(40001);
    defer a.free(facts);
    var reference = try S.Source.testing.initSerial(a, facts, 16);
    defer reference.deinit();
    const meta = try a.dupe(S.Metadata, reference.metadata);
    defer a.free(meta);
    var dictionaries = try Dictionaries.init(&reference);
    defer dictionaries.deinit();
    const expected = try reference.generate(challenges(), dictionaries.table.dictionary, dictionaries.range.dictionary);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var actual = try S.Source.init(a, facts, 16);
        defer actual.deinit();
        try std.testing.expectEqualSlices(M, reference.main, actual.main);
        try std.testing.expectEqualDeep(meta, actual.metadata);
        try std.testing.expectEqualSlices(u64, reference.shift_counts, actual.shift_counts);
        try std.testing.expectEqualSlices(u64, reference.range16_counts, actual.range16_counts);
        actual.releaseMain();
        try std.testing.expectEqualDeep(expected, try actual.generate(challenges(), dictionaries.table.dictionary, dictionaries.range.dictionary));
        try std.testing.expectEqualSlices(M, reference.interaction, actual.interaction);
    }
}
fn allocationFailure(allocator: std.mem.Allocator, facts: []const S.Fact, pool: *engine.work_pool.WorkPool, borrowed: bool) !void {
    const buf: []M = if (borrowed) try a.alloc(M, P.MAIN * 8192) else &.{};
    defer if (borrowed) a.free(buf);
    if (borrowed) @memset(buf, M.fromCanonical(99));
    var binding = try engine.work_pool.ScopedPoolBinding.init(pool);
    defer binding.deinit();
    var source = (if (borrowed) S.Source.initWithMainBuffers(allocator, facts, 13, .{ .main = buf }) else S.Source.init(allocator, facts, 13)) catch |err| {
        if (borrowed) for (buf) |v| try std.testing.expectEqual(@as(u32, 99), v.v);
        return err;
    };
    defer source.deinit();
}
test "SHIFT native partial submissions and allocations preserve borrowed main drain pool and retry" {
    const facts = try inputs(19);
    defer a.free(facts);
    const buf = try a.alloc(M, P.MAIN * 16384);
    defer a.free(buf);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    for ([_]usize{ 0, 1 }) |after| {
        @memset(buf, M.fromCanonical(91));
        try std.testing.expectError(error.InjectedShiftNativeFillSubmissionFailure, S.Source.testing.failSubmission(a, facts, 14, .{ .main = buf }, &pool, after));
        for (buf) |v| try std.testing.expectEqual(@as(u32, 91), v.v);
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var reused = try S.Source.initWithMainBuffers(a, facts, 14, .{ .main = buf });
        defer reused.deinit();
    }
    try std.testing.checkAllAllocationFailures(a, allocationFailure, .{ facts, &pool, false });
    try std.testing.checkAllAllocationFailures(a, allocationFailure, .{ facts, &pool, true });
    var small: engine.work_pool.WorkPool = .{};
    try small.initInPlaceWithOptions(.{ .worker_count = 1, .stack_size = 64 * 1024, .backing_allocator = a });
    defer small.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&small);
    defer binding.deinit();
    @memset(buf, M.fromCanonical(93));
    try std.testing.expectError(error.InvalidShiftNativeFillStack, S.Source.initWithMainBuffers(a, facts, 14, .{ .main = buf }));
    for (buf) |v| try std.testing.expectEqual(@as(u32, 93), v.v);
}
test "SHIFT native full joined proof bytes at1 3 16workers and fresh independent receivers" {
    const Fixture = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
    const Setup = @import("setup.zig");
    const Execution = @import("execution.zig");
    const Driver = @import("driver.zig");
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var setup = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 14, .shift_log = 16, .ls_log = 14, .boundary_log = 14 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var expected = try Execution.prove(a, &setup, admission, fixture.boundary, &fixture.tape, null);
    defer expected.deinit(a);
    for ([_]usize{ 1, 3, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var actual = try Execution.prove(a, &setup, admission, fixture.boundary, &fixture.tape, null);
        defer actual.deinit(a);
        try std.testing.expectEqualSlices(u8, expected.bytes, actual.bytes);
        try std.testing.expectEqualDeep(expected.claims, actual.claims);
        var fresh = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, setup.materials.geometry);
        defer fresh.deinit();
        try Execution.verify(a, &fresh, admission, actual);
    }
}
