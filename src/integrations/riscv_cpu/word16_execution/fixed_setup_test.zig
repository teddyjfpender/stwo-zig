const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixed = @import("fixed_setup.zig");
const Key = @import("../word16_global_execution/keccak/shared/key.zig").Key;
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const QScheme = engine.pcs.CommitmentSchemeProver(cpu, H, MC);
const OmScheme = @import("../word16_global_execution/services/gkr_local/worker_protocol.zig").Scheme;
fn profile(beta: u32) Fixed.Profile {
    return .{ .protocol = @splat(3), .log_blowup = beta };
}
fn cfg(beta: u32) core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = core.fri.FriConfig.init(0, beta, 12) catch unreachable };
}
const Fixture = struct {
    first: [32]M,
    second: [64]M,
    fn init() Fixture {
        var f: Fixture = undefined;
        for (&f.first, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * 7 + 3) % 101));
        for (&f.second, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * i + 11) % 103));
        return f;
    }
    fn columns(self: *Fixture) [2]engine.pcs.ColumnEvaluation {
        return .{ .{ .log_size = 5, .values = &self.first }, .{ .log_size = 6, .values = &self.second } };
    }
};
fn allocationCase(a: std.mem.Allocator) !void {
    var f = Fixture.init();
    const columns = f.columns();
    var source = try Key.seal(a, &columns);
    defer source.deinit();
    var cache = try Fixed.Cache.init(a, 1 << 20);
    var cache_alive = true;
    defer if (cache_alive) cache.deinit();
    var lease = try cache.acquireFromKey(&source, profile(2));
    var lease_alive = true;
    defer if (lease_alive) lease.deinit();
    var hit = try cache.acquireFromKey(&source, profile(2));
    var hit_alive = true;
    defer if (hit_alive) hit.deinit();
    try std.testing.expect(lease.key == hit.key);
    var scheme = try OmScheme.init(a, cfg(2));
    defer scheme.deinit(a);
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    try lease.key.append(a, &scheme, &ch, profile(2), lease.key.identity, lease.key.root);
    const expected = lease.key.root;
    hit.deinit();
    hit_alive = false;
    cache.deinit();
    cache_alive = false;
    lease.deinit();
    lease_alive = false;
    try std.testing.expectEqualDeep(expected, scheme.trees.items[0].root());
}
test "wide fixed cache OM append owns its allocator after cache teardown and all OOM exits" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
test "wide fixed beta1 control root unchanged and beta2 rejects stale authority" {
    const a = std.testing.allocator;
    var f = Fixture.init();
    const columns = f.columns();
    var source = try Key.seal(a, &columns);
    defer source.deinit();
    var cache = try Fixed.Cache.init(a, 1 << 20);
    defer cache.deinit();
    var b1 = try cache.acquireFromKey(&source, profile(1));
    defer b1.deinit();
    var b2 = try cache.acquireFromKey(&source, profile(2));
    defer b2.deinit();
    try std.testing.expectEqualDeep(source.root, b1.key.root);
    var old_control = try QScheme.init(a, source.suite.config());
    defer old_control.deinit(a);
    var new_control = try QScheme.init(a, source.suite.config());
    defer new_control.deinit(a);
    var old_ch: core.channel.blake2s.Blake2sChannel = .{};
    var new_ch: core.channel.blake2s.Blake2sChannel = .{};
    try source.append(a, &old_control, &old_ch);
    try b1.key.append(a, &new_control, &new_ch, profile(1), b1.key.identity, b1.key.root);
    try std.testing.expectEqualDeep(old_ch.digestBytes(), new_ch.digestBytes());
    std.debug.print("WIDE_FIXED_SETUP beta1={x} beta2={x}\n", .{ b1.key.root, b2.key.root });

    try std.testing.expect(!std.mem.eql(u8, &b1.key.root, &b2.key.root));
    var wide = try OmScheme.init(a, cfg(2));
    defer wide.deinit(a);
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    try std.testing.expectError(error.FixedSetupRootMismatch, b2.key.append(a, &wide, &ch, profile(2), b2.key.identity, source.root));
    try std.testing.expectError(error.FixedSetupIdentityMismatch, b2.key.append(a, &wide, &ch, profile(1), b2.key.identity, b2.key.root));
    var wrong = b2.key.identity;
    wrong[0] ^= 1;
    try std.testing.expectError(error.FixedSetupIdentityMismatch, b2.key.append(a, &wide, &ch, profile(2), wrong, b2.key.root));
    try std.testing.expectEqual(@as(usize, 0), wide.trees.items.len);
    var old = try OmScheme.init(a, cfg(1));
    defer old.deinit(a);
    try std.testing.expectError(error.InvalidWideFixedSetupPhase, b2.key.append(a, &old, &ch, profile(2), b2.key.identity, b2.key.root));
    var same = try cache.acquireFromKey(&source, profile(2));
    defer same.deinit();
    try std.testing.expect(same.key == b2.key);
    try std.testing.expectEqual(@as(u64, 2), cache.snapshot().seals);
    try std.testing.expectEqual(@as(u64, 1), cache.snapshot().hits);
}
test "wide fixed cache keys protocol and ordered coefficient content and survives source release" {
    const a = std.testing.allocator;
    var f = Fixture.init();
    const columns = f.columns();
    var source = try Key.seal(a, &columns);
    var source_alive = true;
    defer if (source_alive) source.deinit();
    var duplicate = try Key.seal(a, &columns);
    defer duplicate.deinit();
    var cache = try Fixed.Cache.init(a, 1 << 20);
    defer cache.deinit();
    var first = try cache.acquireFromKey(&source, profile(2));
    defer first.deinit();
    var hit = try cache.acquireFromKey(&duplicate, profile(2));
    defer hit.deinit();
    try std.testing.expect(first.key == hit.key);
    var independent = try Fixed.Cache.init(a, 1 << 20);
    defer independent.deinit();
    var independently_sealed = try independent.acquireFromKey(&duplicate, profile(2));
    defer independently_sealed.deinit();
    try std.testing.expect(independently_sealed.key != first.key);
    try std.testing.expectEqualDeep(independently_sealed.key.root, first.key.root);
    try std.testing.expectEqualDeep(independently_sealed.key.identity, first.key.identity);

    var p = profile(2);
    p.protocol[0] ^= 1;
    var changed = try cache.acquireFromKey(&source, p);
    defer changed.deinit();
    try std.testing.expect(changed.key != first.key);
    try std.testing.expect(!std.mem.eql(u8, &changed.key.identity, &first.key.identity));
    const co = source.tree.coefficients.?;
    const swapped = [_]engine.poly.circle.CircleCoefficients{ co[1], co[0] };
    var ordered = try cache.acquireCoefficients(&swapped, profile(2));
    defer ordered.deinit();
    try std.testing.expect(ordered.key != first.key);
    const expected = first.key.root;
    source.deinit();
    source_alive = false;
    var scheme = try OmScheme.init(a, cfg(2));
    defer scheme.deinit(a);
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    try first.key.append(a, &scheme, &ch, profile(2), first.key.identity, expected);
}
test "wide fixed cache hard cap and malformed profiles fail closed" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidFixedSetupBudget, Fixed.Cache.init(a, 0));
    var tiny = try Fixed.Cache.init(a, 8192);
    defer tiny.deinit();
    var values = [_]M{M.one()} ** 64;
    const c = [_]engine.poly.circle.CircleCoefficients{try engine.poly.circle.CircleCoefficients.initBorrowed(&values)};
    try std.testing.expectError(error.OutOfMemory, tiny.acquireCoefficients(&c, profile(2)));
    try std.testing.expect(tiny.snapshot().refused);
    try std.testing.expectEqual(@as(usize, 0), tiny.snapshot().keys);
    try std.testing.expectError(error.UnsupportedFixedSetupRate, tiny.acquireCoefficients(&c, profile(3)));
    try std.testing.expectError(error.MissingFixedSetupProtocol, tiny.acquireCoefficients(&c, .{ .protocol = @splat(0), .log_blowup = 2 }));
    try std.testing.expectError(error.EmptyFixedSetup, tiny.acquireCoefficients(&.{}, profile(2)));
}
