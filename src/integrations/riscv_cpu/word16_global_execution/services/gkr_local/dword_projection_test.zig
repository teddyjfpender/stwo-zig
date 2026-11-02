const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const P = @import("dword_projection.zig");
const F = @import("fractions.zig");
const Sink = struct {
    relations: [9]u8 = @splat(0),
    tuples: [9][30]M = @splat(@splat(M.zero())),
    weights: [9]M = @splat(M.zero()),
    n: usize = 0,
    pub fn emit(self: *@This(), relation: F.Relation, tuple: anytype, weight: M) void {
        self.relations[self.n] = @intFromEnum(relation);
        self.tuples[self.n] = @splat(M.zero());
        @memcpy(self.tuples[self.n][0..tuple.len], &tuple);
        self.weights[self.n] = weight;
        self.n += 1;
    }
    pub fn emitBase(self: *@This(), relation: F.Relation, tuple: anytype, weight: M) void {
        self.emit(relation, tuple, weight);
    }
};
test "V3 dword retained projections exactly match committed MAIN on active and padding" {
    const D = A.memory.load_store_dword;
    const before = A.memory.closed_ram.types.State{ .value = 17, .rights = 3, .epoch = 0, .tick = 0 };
    var source = try D.source.Source.init(std.testing.allocator, &.{.{ .opcode = .LD, .a = 0x1000, .immediate = 0, .c = 17, .epoch = 1, .tick = 4, .before = before, .after = .{ .value = 17, .rights = 3, .epoch = 1, .tick = 4 } }}, 5);
    defer source.deinit();
    var saved: [32]Sink = undefined;
    for (0..32) |i| {
        const physical = A.memory.closed_ram.trace.physical(i, 5);
        var row: [D.layout.MAIN]M = undefined;
        for (&row, 0..) |*v, c| v.* = source.main[c * 32 + physical];
        var direct = Sink{};
        P.emitLocalFor(M, &row, &direct);
        var retained = Sink{};
        P.emitMetadata(source.metadata[i], &retained);
        try std.testing.expectEqualDeep(direct, retained);
        try std.testing.expectEqual(7, retained.n);
        saved[i] = retained;
    }
    source.releaseMain();
    for (0..32) |i| {
        var retained = Sink{};
        P.emitMetadata(source.metadata[i], &retained);
        try std.testing.expectEqualDeep(saved[i], retained);
    }
}
test "V3 paired CPU and AND source terms retain V2 authority by mode" {
    const z = M.zero();
    const fixed = [_]M{z} ** 64;
    const row = [_]M{z} ** 256;
    const Counter = struct {
        n: usize = 0,
        pub fn emit(self: *@This(), _: F.Relation, _: anytype, _: M) void {
            self.n += 1;
        }
    };
    var sink = Counter{};
    F.cpuModeFor(M, &fixed, &row, z, false, &sink);
    try std.testing.expectEqual(F.cpuTerms(false), sink.n);
    sink.n = 0;
    F.cpuModeFor(M, &fixed, &row, z, true, &sink);
    try std.testing.expectEqual(F.cpuTerms(true), sink.n);
    sink.n = 0;
    F.andTableModeFor(M, &fixed, &row, true, &sink);
    try std.testing.expectEqual(F.andTableTerms(true), sink.n);
}
test "V3 byte pair challenges preserve legacy nine namespace transcript for bulk only children" {
    const O = core.fields.om31.OM31;
    const Ch = core.channel.raw_mod_m31.Om31Channel;
    const Challenges = @import("challenges.zig").For(O);
    var legacy = Ch.init();
    var replay = Ch.init();
    const got = Challenges.draw(&legacy);
    replay.mixU32s(&.{ 0x4c474b31, 8, 9 });
    for (std.enums.values(F.Relation)[0..9]) |relation| {
        const i = @intFromEnum(relation);
        replay.mixU32s(&.{ @intCast(i), @intCast(relation.arity()) });
        try std.testing.expectEqualDeep(got.offsets[i], replay.drawSecureFelt());
        for (0..relation.arity()) |j| try std.testing.expectEqualDeep(got.coefficients[i][j], if (relation == .range8) O.one() else replay.drawSecureFelt());
    }
    try std.testing.expectEqualDeep(legacy, replay);
    var bulk = Ch.init();
    const bulk_instance = @import("frame.zig").Instance{ .origin = .{ .bulk = .set }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 };
    _ = Challenges.drawForInstances(&bulk, &.{bulk_instance});
    try std.testing.expectEqualDeep(legacy, bulk);
    var paired = Ch.init();
    const cpu = @import("frame.zig").Instance{ .origin = .{ .core = .cpu }, .row_log = 5, .terms = 14, .fixed_offset = 0, .main_offset = 0 };
    const v3 = Challenges.drawForInstances(&paired, &.{cpu});
    try std.testing.expect(!v3.offsets[@intFromEnum(F.Relation.byte_pair)].isZero());
    try std.testing.expect(!std.meta.eql(legacy, paired));
}
fn pairRequestAllocation(a: std.mem.Allocator) !void {
    const T = A.providers.tables;
    var setup = try T.Setup.init(a, .byte_and);
    defer setup.deinit();
    const counts = try a.alloc(u64, 65536);
    defer a.free(counts);
    @memset(counts, 0);
    counts[257] = 3;
    var request = try T.Request.initWithPairs(a, &setup, counts, counts);
    defer request.deinit();
    try std.testing.expectEqual(@as(u32, 3), request.pair_counts[257]);
    a.free(request.main);
    request.main = &.{};
    var retained = Sink{};
    try @import("pair_projection.zig").emitAndMetadata(257, 3, request.pair_counts, true, &retained);
    try std.testing.expectEqual(@as(usize, 2), retained.n);
    try std.testing.expectEqual(M.fromCanonical(3).neg().v, retained.weights[1].v);
    try std.testing.expectEqual(@as(u32, 1), retained.tuples[1][0].v);
    try std.testing.expectEqual(@as(u32, 1), retained.tuples[1][1].v);
    try std.testing.expectEqual(@as(u32, 1), retained.tuples[1][3].v);
}
test "V3 pair request retained metadata survives MAIN transfer and all allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pairRequestAllocation, .{});
}
