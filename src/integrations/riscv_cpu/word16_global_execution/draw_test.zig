//! Frozen pre-refactor core sequence and global authority regression tests.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.word16_execution;
const B = A.word16_v1;
const P = @import("../word16_execution/protocol.zig");
const G = @import("protocol.zig");
const K = @import("keccak/shared/protocol.zig");
const S = @import("secp/protocol.zig");
const Services = @import("services/protocol.zig");
const Q = core.fields.qm31.QM31;
const Ram = @FieldType(A.memory.load_store_v2.types.Challenges, "ram");
const a = std.testing.allocator;
fn frozenOracle(channel: *P.T.P.Channel, shared: ?Ram, discard_unused: bool) P.Draw {
    if (shared != null) channel.mixU32s(&.{ 0x57535244, 1, 14 });
    channel.mixU32s(&.{ 0x57465247, 6 });
    const register = frozenRelation(@FieldType(X.types.Challenges, "register"), channel);
    channel.mixU32s(&.{ 0x5746464e, 13 });
    const function = frozenRelation(@FieldType(X.types.Challenges, "function"), channel);
    channel.mixU32s(&.{ 0x5746524f, 30 });
    const rom = frozenRelation(@FieldType(X.types.Challenges, "rom"), channel);
    channel.mixU32s(&.{ 0x57464f57, 19 });
    const owner = frozenRelation(X.types.OwnerChallenges, channel);
    channel.mixU32s(&.{ 0x57465231, 16 });
    const range16 = @FieldType(X.types.Challenges, "range16"){ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x57465238, 1 });
    const range8 = @FieldType(X.types.Challenges, "range8"){ .offset = channel.drawSecureFelt(), .coefficient = Q.one() };
    channel.mixU32s(&.{ 0x5746414e, 3 });
    const and_ = A.providers.tables.Challenges.draw(channel);
    channel.mixU32s(&.{ 0x57465348, 6, B.shift_word_packed_experiment.table.SEMANTIC_TAG });
    const shift_ = A.providers.tables.Challenges.draw(channel);
    const ram = if (shared) |value| selected: {
        if (discard_unused) {
            channel.mixU32s(&.{ 0x57465241, 14 });
            _ = frozenRelation(Ram, channel);
        }
        break :selected value;
    } else local: {
        channel.mixU32s(&.{ 0x57465241, 14 });
        break :local frozenRelation(Ram, channel);
    };
    channel.mixU32s(&.{ 0x57465345, 5 });
    const selection = frozenRelation(@FieldType(A.memory.load_store_v2.types.Challenges, "selection"), channel);
    return .{ .cpu = .{ .register = register, .function = function, .rom = rom, .owner = owner, .range16 = range16, .range8 = range8 }, .and_ = and_, .shift_ = shift_, .memory = .{ .ram = ram, .owner = owner, .range16 = .{ .offset = range16.offset, .coefficient = range16.coefficient }, .range8 = .{ .offset = range8.offset, .coefficient = range8.coefficient }, .selection = selection } };
}
fn frozenRelation(comptime R: type, channel: *P.T.P.Channel) R {
    var r: R = undefined;
    r.offset = channel.drawSecureFelt();
    for (&r.coefficients) |*c| c.* = channel.drawSecureFelt();
    return r;
}
fn expectSameStream(initial: P.T.P.Channel, actual: P.T.P.Channel) !void {
    var before = initial;
    var after = actual;
    for (0..8) |_| try std.testing.expect(before.drawSecureFelt().eql(after.drawSecureFelt()));
}
fn seed(channel: *P.T.P.Channel, value: u64) void {
    channel.mixU64(value);
    channel.mixU32s(&.{ 0x46524f5a, 1 });
}
test "closed core draw preserves frozen historical fields and complete following channel sequence" {
    for ([_]u64{ 0, 1, 0x8000000000000000, std.math.maxInt(u64) }) |value| {
        var expected = P.T.P.Channel{};
        seed(&expected, value);
        var actual = expected;
        try std.testing.expectEqualDeep(frozenOracle(&expected, null, false), P.draw(&actual));
        for (0..16) |_| try std.testing.expect(expected.drawSecureFelt().eql(actual.drawSecureFelt()));
    }
}
test "shared core draw omits exactly the unused local RAM relation and pins explicit revision" {
    var ram_channel = P.T.P.Channel{};
    seed(&ram_channel, 173);
    const ram = frozenRelation(Ram, &ram_channel);
    var expected = P.T.P.Channel{};
    seed(&expected, 771);
    var actual = expected;
    var discarded = expected;
    const wanted = frozenOracle(&expected, ram, false);
    const got = P.drawWithSharedRam(&actual, ram);
    const wasted = frozenOracle(&discarded, ram, true);
    try std.testing.expectEqual(@as(u32, 0x57535244), P.SHARED_RAM_DRAW_TAG);
    try std.testing.expectEqual(@as(u32, 1), P.SHARED_RAM_DRAW_REVISION);
    try std.testing.expectEqualDeep(wanted, got);
    try std.testing.expectEqualDeep(ram, got.memory.ram);
    try std.testing.expect(!std.meta.eql(got.memory.selection, wasted.memory.selection));
    for (0..16) |_| try std.testing.expect(expected.drawSecureFelt().eql(actual.drawSecureFelt()));
}
fn bounded(ch: *P.T.P.Channel, manifest: *const G.Manifest, index: usize) !P.Draw {
    return K.drawCpuFor(.bounded_v3, ch, manifest, index);
}
fn baseRam(manifest: *const G.Manifest) !Ram {
    return manifest.ram();
}
fn kRam(manifest: *const G.Manifest) !Ram {
    return (try K.shared(manifest)).ram;
}
fn boundedRam(manifest: *const G.Manifest) !Ram {
    return (try K.sharedBounded(manifest)).ram;
}
fn sRam(manifest: *const G.Manifest) !Ram {
    return (try S.shared(manifest)).ram;
}
fn serviceRam(manifest: *const G.Manifest) !Ram {
    return (try Services.shared(manifest)).ram;
}
test "every global authority derives shared RAM from complete manifest before core draw and rejects mutation" {
    const specs = [_][32]u8{ @splat(3), @splat(7) };
    const roots = [_]G.Receipt{ .{ .fixed = .{ .bytes = @splat(11) }, .main = .{ .bytes = @splat(13) } }, .{ .fixed = .{ .bytes = @splat(17) }, .main = .{ .bytes = @splat(19) } } };
    var manifest = try G.Manifest.init(a, &specs, &roots);
    defer manifest.deinit();
    const Case = struct {
        draw: *const fn (*P.T.P.Channel, *const G.Manifest, usize) anyerror!P.Draw,
        ram: *const fn (*const G.Manifest) anyerror!Ram,
        tag: []const u32,
    };
    const cases = [_]Case{
        .{ .draw = G.draw, .ram = baseRam, .tag = &.{ 0x57475332, 1, 1 } },
        .{ .draw = K.drawCpu, .ram = kRam, .tag = &.{ 0x574b5453, 2, 0, 1 } },
        .{ .draw = bounded, .ram = boundedRam, .tag = &.{ 0x574b5453, 3, 0, 1 } },
        .{ .draw = S.drawCpu, .ram = sRam, .tag = &.{ 0x57534532, 1, 0, 1 } },
        .{ .draw = Services.drawCpu, .ram = serviceRam, .tag = &.{ 0x57534332, 1, 0, 1 } },
    };
    for (cases) |case| {
        var expected = P.T.P.Channel{};
        seed(&expected, 312);
        var actual = expected;
        expected.mixU32s(case.tag);
        P.digest(&expected, manifest.digest);
        const wanted = frozenOracle(&expected, try case.ram(&manifest), false);
        const got = try case.draw(&actual, &manifest, 1);
        try std.testing.expectEqualDeep(wanted, got);
        try std.testing.expect(expected.drawSecureFelt().eql(actual.drawSecureFelt()));
        var bad = manifest;
        bad.digest[0] ^= 1;
        var rejected = P.T.P.Channel{};
        const initial = rejected;
        if (case.draw(&rejected, &bad, 1)) |_| return error.AcceptedChangedManifest else |_| {}
        try expectSameStream(initial, rejected);
        bad = manifest;
        bad.roots = manifest.roots[0..1];
        if (case.draw(&rejected, &bad, 1)) |_| return error.AcceptedIncompleteManifest else |_| {}
        try expectSameStream(initial, rejected);
    }
}
