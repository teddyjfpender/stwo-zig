//! Native storage equivalence; mathematical proofs remain with each AIR fixture.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const Arena = @import("../rv64_main_arena.zig");
const K = @import("../delegations/keccak/sources.zig");
const S = @import("../delegations/secp256k1/sources.zig");
const KF = @import("rv64_keccak_proof_test.zig");
const SF = @import("../delegations/secp256k1/bridge_fixture.zig");
const a = std.testing.allocator;
fn kCalls() [3]rv.crypto.keccak.bridge.trace.Call {
    var result: [3]rv.crypto.keccak.bridge.trace.Call = undefined;
    var before = KF.inputState(17);
    for (&result, 0..) |*call, i| {
        const after = KF.reference(before);
        call.* = .{ .call_id = i + 1, .clock = 3 + 8 * i, .pointer = 0x1ff8, .before = before, .after = after, .previous_clocks = @splat(if (i == 0) 0 else @intCast(4 * (3 + 8 * (i - 1)))) };
        before = after;
    }
    return result;
}
fn kArena(allocator: std.mem.Allocator) !Arena.Arena {
    return Arena.Arena.init(allocator, &.{ .{ .role = .keccak, .log_size = 6, .width = rv.crypto.keccak.layout.MAIN }, .{ .role = .chi, .log_size = 13, .width = 1 }, .{ .role = .xor5, .log_size = 10, .width = 1 }, .{ .role = .keccak_bridge, .log_size = 7, .width = rv.crypto.keccak.bridge.layout.MAIN } });
}
fn kBuffers(arena: *Arena.Arena) !K.MainBuffers {
    return .{ .permutation = (try arena.matrix(.keccak)).values, .chi = (try arena.matrix(.chi)).values, .xor5 = (try arena.matrix(.xor5)).values, .bridge = (try arena.matrix(.keccak_bridge)).values };
}
fn kChallenges() struct { k: rv.crypto.keccak.equations.Challenges, b: rv.crypto.keccak.bridge.equations.Challenges } {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x424f5252, 37 });
    const k = rv.crypto.keccak.equations.Challenges.draw(&channel);
    return .{ .k = k, .b = .{ .io = k.io, .call = rv.crypto.keccak.bridge.equations.CallChallenges.draw(&channel), .ram = rv.relations.Challenges.draw(&channel), .bytes = channel.drawSecureFelt() } };
}
test "Keccak explicit borrowed arena matches all owned columns and interaction bytes after arena death" {
    const calls = kCalls();
    var owned = try K.Trace.init(a, &calls, 1, 6, 7);
    defer owned.deinit();
    var arena = try kArena(a);
    defer arena.deinit();
    const buffers = try kBuffers(&arena);
    var borrowed = try K.Trace.initWithMainBuffers(a, &calls, 1, 6, 7, buffers);
    defer borrowed.deinit();
    try std.testing.expect(!borrowed.permutation.owns_main and !borrowed.chi.owns_main and !borrowed.xor5.owns_main and !borrowed.bridge.owns_main);
    try std.testing.expectError(error.BorrowedCryptoMain, borrowed.takeMain());
    try std.testing.expectError(error.BorrowedCryptoMain, borrowed.permutation.takeMain());
    try std.testing.expectError(error.BorrowedCryptoMain, borrowed.chi.takeMain());
    try std.testing.expectError(error.BorrowedCryptoMain, borrowed.bridge.takeMain());
    inline for (.{ "permutation", "chi", "xor5", "bridge" }) |name| {
        try std.testing.expectEqualSlices(M, @field(owned, name).main, @field(borrowed, name).main);
        try std.testing.expectEqualSlices(M, @field(owned, name).fixed, @field(borrowed, name).fixed);
    }
    try std.testing.expect(borrowed.permutation.main.ptr == buffers.permutation.ptr);
    try borrowed.releaseMain();
    arena.deinit();
    const ch = kChallenges();
    const expected = try owned.generate(ch.k, ch.b);
    const actual = try borrowed.generate(ch.k, ch.b);
    inline for (.{ "permutation", "chi", "xor5", "bridge" }) |name| {
        try std.testing.expect(@field(expected, name).eql(@field(actual, name)));
        try std.testing.expectEqualSlices(M, @field(owned, name).interaction, @field(borrowed, name).interaction);
    }
}
fn kAllocationRun(allocator: std.mem.Allocator) !void {
    const calls = kCalls();
    var arena = try kArena(allocator);
    defer arena.deinit();
    var trace = try K.Trace.initWithMainBuffers(allocator, &calls, 1, 6, 7, try kBuffers(&arena));
    defer trace.deinit();
    try trace.releaseMain();
    arena.deinit();
    const ch = kChallenges();
    _ = try trace.generate(ch.k, ch.b);
}
test "Keccak borrowed main every allocation failure retains caller allocation ownership" {
    try std.testing.checkAllAllocationFailures(a, kAllocationRun, .{});
}
fn sChallenges() S.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x53424f52, 37 });
    return S.Challenges.draw(&channel, channel.drawSecureFelt(), rv.relations.Challenges.draw(&channel));
}
const sg = S.Geometry{ .product_log = 8, .linear_log = 7, .bridge_log = 6 };
fn sArena(allocator: std.mem.Allocator) !Arena.Arena {
    return Arena.Arena.init(allocator, &.{ .{ .role = .secp_add_product, .log_size = sg.product_log, .width = S.S.layout.main(.product) }, .{ .role = .secp_add_linear, .log_size = sg.linear_log, .width = S.S.layout.main(.linear) }, .{ .role = .secp_add_bridge, .log_size = sg.bridge_log, .width = S.S.bridge.layout.MAIN } });
}
fn sBuffers(arena: *Arena.Arena) !S.MainBuffers {
    return .{ .product = (try arena.matrix(.secp_add_product)).values, .linear = (try arena.matrix(.secp_add_linear)).values, .bridge = (try arena.matrix(.secp_add_bridge)).values };
}
test "secp borrowed native height matrices match owned source counts claims and interaction bytes" {
    for ([_]S.Kind{ .add, .double }) |kind| for ([_]S.Format{ .big_endian_bytes_v1, .little_endian_words_v2 }) |format| {
        const calls = try SF.makeCallsWithFormat(a, S.S.program.get(kind), 3, format);
        defer a.free(calls);
        var materials = try S.Materials.init(a, kind, sg);
        defer materials.deinit();
        var owned = try S.Trace.initPrepared(a, &materials, calls, 1, format);
        defer owned.deinit();
        var arena = try sArena(a);
        defer arena.deinit();
        const buffers = try sBuffers(&arena);
        var borrowed = try S.Trace.initPreparedWithMainBuffers(a, &materials, calls, 1, format, buffers);
        defer borrowed.deinit();
        try std.testing.expect(!borrowed.product.owns_main and !borrowed.linear.owns_main and !borrowed.bridge.owns_main);
        try std.testing.expectError(error.BorrowedCryptoMain, borrowed.takeMain());
        try std.testing.expectError(error.BorrowedCryptoMain, borrowed.product.takeMain());
        try std.testing.expectError(error.BorrowedCryptoMain, borrowed.bridge.takeMain());
        try std.testing.expectEqualSlices(u64, &owned.byte_counts, &borrowed.byte_counts);
        inline for (.{ "product", "linear", "bridge" }) |name| try std.testing.expectEqualSlices(M, @field(owned, name).main, @field(borrowed, name).main);
        try borrowed.releaseMain();
        arena.deinit();
        const ch = sChallenges();
        const expected = try owned.generate(ch);
        const actual = try borrowed.generate(ch);
        inline for (.{ "product", "linear", "bridge" }) |name| {
            try std.testing.expect(@field(expected, name).eql(@field(actual, name)));
            try std.testing.expectEqualSlices(M, @field(owned, name).interaction, @field(borrowed, name).interaction);
        }
    };
}
fn sAllocationRun(allocator: std.mem.Allocator) !void {
    const calls = try SF.makeCallsWithFormat(allocator, S.S.program.get(.add), 1, .little_endian_words_v2);
    defer allocator.free(calls);
    var materials = try S.Materials.init(allocator, .add, sg);
    defer materials.deinit();
    var arena = try sArena(allocator);
    defer arena.deinit();
    var trace = try S.Trace.initPreparedWithMainBuffers(allocator, &materials, calls, 1, .little_endian_words_v2, try sBuffers(&arena));
    defer trace.deinit();
    try trace.releaseMain();
    arena.deinit();
    _ = try trace.generate(sChallenges());
}
test "secp borrowed main every allocation failure retains caller backing and narrow metadata" {
    try std.testing.checkAllAllocationFailures(a, sAllocationRun, .{});
}
test "borrowed crypto rejects wrong lengths overlapping roles or fixed input before allocation or writes" {
    var arena = try kArena(a);
    defer arena.deinit();
    const buffers = try kBuffers(&arena);
    @memset(arena.raw, M.fromCanonical(123));
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var wrong = buffers;
    wrong.permutation = buffers.permutation[1..];
    const calls = kCalls();
    try std.testing.expectError(error.InvalidCryptoMainBuffers, K.Trace.initWithMainBuffers(fail.allocator(), &calls, 1, 6, 7, wrong));
    wrong = buffers;
    wrong.xor5 = buffers.chi[0..1024];
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, K.Trace.initWithMainBuffers(fail.allocator(), &calls, 1, 6, 7, wrong));
    for (arena.raw) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
    var material = try S.Materials.init(a, .add, sg);
    defer material.deinit();
    var sa = try sArena(a);
    defer sa.deinit();
    const sb = try sBuffers(&sa);
    @memset(sa.raw, M.fromCanonical(123));
    var sw = sb;
    sw.bridge = sb.product[0..sb.bridge.len];
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, S.Trace.initPreparedWithMainBuffers(fail.allocator(), &material, &.{}, 1, .little_endian_words_v2, sw));
    sw = sb;
    sw.product = sb.product[1..];
    try std.testing.expectError(error.InvalidCryptoMainBuffers, S.Trace.initPreparedWithMainBuffers(fail.allocator(), &material, &.{}, 1, .little_endian_words_v2, sw));
    const saved = material.product_fixed;
    material.product_fixed = sb.product[0..material.product_fixed.len];
    defer material.product_fixed = saved;
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, S.Trace.initPreparedWithMainBuffers(fail.allocator(), &material, &.{}, 1, .little_endian_words_v2, sb));
    for (sa.raw) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
}

test "secp two-kind context rejects cross-kind aliases before writes and preserves global counts and claims" {
    const Context = @import("../delegations/secp256k1/context.zig");
    const meta = Context.Metadata{ .add = .{ .roster = .present, .calls = 1, .geometry = sg }, .double = .{ .roster = .present, .calls = 1, .geometry = sg } };
    var material = try Context.Materials.init(a, meta);
    defer material.deinit();
    const adds = try SF.makeCallsWithFormat(a, S.S.program.get(.add), 1, .little_endian_words_v2);
    defer a.free(adds);
    const doubles = try SF.makeCallsWithFormat(a, S.S.program.get(.double), 1, .little_endian_words_v2);
    defer a.free(doubles);
    doubles[0].clock = 7;
    doubles[0].pointer = 0x2fe0;
    const calls = [2][]const S.Call{ adds, doubles };
    var arena = try Arena.Arena.init(a, &.{
        .{ .role = .secp_add_product, .log_size = sg.product_log, .width = S.S.layout.main(.product) },
        .{ .role = .secp_add_linear, .log_size = sg.linear_log, .width = S.S.layout.main(.linear) },
        .{ .role = .secp_add_bridge, .log_size = sg.bridge_log, .width = S.S.bridge.layout.MAIN },
        .{ .role = .secp_double_product, .log_size = sg.product_log, .width = S.S.layout.main(.product) },
        .{ .role = .secp_double_linear, .log_size = sg.linear_log, .width = S.S.layout.main(.linear) },
        .{ .role = .secp_double_bridge, .log_size = sg.bridge_log, .width = S.S.bridge.layout.MAIN },
    });
    defer arena.deinit();
    const main = Context.MainBuffers{
        try sBuffers(&arena),
        .{ .product = (try arena.matrix(.secp_double_product)).values, .linear = (try arena.matrix(.secp_double_linear)).values, .bridge = (try arena.matrix(.secp_double_bridge)).values },
    };
    @memset(arena.raw, M.fromCanonical(123));
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var alias = main;
    alias[1] = main[0];
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, Context.Trace.initPreparedWithMainBuffers(fail.allocator(), &material, calls, meta, .ethereum_services_v2, alias));
    for (arena.raw) |v| try std.testing.expectEqual(@as(u32, 123), v.v);
    var owned = try Context.Trace.initPrepared(a, &material, calls, meta, .ethereum_services_v2);
    defer owned.deinit();
    var borrowed = try Context.Trace.initPreparedWithMainBuffers(a, &material, calls, meta, .ethereum_services_v2, main);
    defer borrowed.deinit();
    try std.testing.expectEqualSlices(u64, &owned.byte_counts, &borrowed.byte_counts);
    for (&owned.groups, &borrowed.groups) |*left, *right| inline for (.{ "product", "linear", "bridge" }) |name| {
        try std.testing.expectEqualSlices(M, @field(left.*.?, name).main, @field(right.*.?, name).main);
    };
    try borrowed.releaseMain();
    arena.deinit();
    const ch = sChallenges();
    const expected = try owned.generate(ch);
    const actual = try borrowed.generate(ch);
    for (expected, actual) |left, right| inline for (.{ "product", "linear", "bridge" }) |name| {
        try std.testing.expect(@field(left, name).eql(@field(right, name)));
    };
}
