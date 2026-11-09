const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const SetupCache = @import("setup_cache.zig");
const KeyModule = @import("../../../../../../integrations/riscv_cpu/word16_global_execution/keccak/shared/key.zig");
const Key = KeyModule.Key;
const Fixed = @import("../../../../../../integrations/riscv_cpu/word16_execution/fixed_setup.zig");
const OmScheme = @import("../../../../../../integrations/riscv_cpu/word16_global_execution/services/gkr_local/worker_protocol.zig").Scheme;
const M = core.fields.m31.M31;

const Fixture = struct {
    first: [32]M,
    second: [64]M,
    third: [256]M,
    fn init(seed: u32) Fixture {
        var f: Fixture = undefined;
        for (&f.first, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * 7 + 3 + seed) % 101));
        for (&f.second, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * i + 11 + seed) % 103));
        for (&f.third, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * 31 + seed * 17) % 2147483647));
        return f;
    }
    fn columns(self: *Fixture) [3]engine.pcs.ColumnEvaluation {
        return .{ .{ .log_size = 5, .values = &self.first }, .{ .log_size = 6, .values = &self.second }, .{ .log_size = 8, .values = &self.third } };
    }
};
const Component = struct {
    key: Key,
    pub fn deinit(self: *Component) void {
        self.key.deinit();
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    columns: []const engine.pcs.ColumnEvaluation,
    pub fn build(b: @This()) !Component {
        return .{ .key = try Key.sealWithSuite(b.a, b.columns, Key.Suite.experimentalFold4()) };
    }
};
const DoubleSeal = struct {
    a: std.mem.Allocator,
    columns: []const engine.pcs.ColumnEvaluation,
    pub fn build(b: @This()) !Component {
        var first = try Key.sealWithSuite(b.a, b.columns, Key.Suite.experimentalFold4());
        defer first.deinit();
        return .{ .key = try Key.sealWithSuite(b.a, b.columns, Key.Suite.experimentalFold4()) };
    }
};
const BETA = Fixed.CommitmentDescriptor{ .log_blowup = 1 };
fn omConfig() core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = core.fri.FriConfig.init(0, 1, 12) catch unreachable };
}
/// Root mixed into a fresh OM channel by appending the candidate key.
fn appendDigest(a: std.mem.Allocator, key: *const Fixed.WideFixedKey) ![32]u8 {
    var scheme = try OmScheme.init(a, omConfig());
    defer scheme.deinit(a);
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    try key.append(a, &scheme, &ch, BETA, key.identity, key.root, omConfig());
    return ch.digestBytes();
}

test "identity-only source has the committed polynomials and the same candidate key" {
    const a = std.testing.allocator;
    var f = Fixture.init(1);
    const columns = f.columns();
    const suite = Key.Suite.experimentalFold4();
    var sealed = try Key.sealWithSuite(a, &columns, suite);
    defer sealed.deinit();
    var identity = try Key.identityOnly(a, &columns, suite, null);
    defer identity.deinit();
    const x = sealed.tree.coefficients.?;
    const y = identity.tree.coefficients.?;
    try std.testing.expectEqual(x.len, y.len);
    for (x, y, sealed.tree.columns, identity.tree.columns) |p, q, cp, cq| {
        try std.testing.expectEqual(p.log_size, q.log_size);
        try std.testing.expectEqualSlices(M, p.coeffs, q.coeffs);
        try std.testing.expectEqual(cp.log_size, cq.log_size);
    }
    try std.testing.expect(!std.mem.eql(u8, &sealed.root, &identity.root));
    try std.testing.expectError(error.RootOnlySharedTruthKey, identity.append(a, undefined, undefined));
    var cache = try Fixed.Cache.init(a, 1 << 22);
    defer cache.deinit();
    var from_sealed = try cache.acquireFromKey(&sealed, BETA);
    defer from_sealed.deinit();
    var other = try Fixed.Cache.init(a, 1 << 22);
    defer other.deinit();
    var from_identity = try other.acquireFromKey(&identity, BETA);
    defer from_identity.deinit();
    try std.testing.expectEqualSlices(u8, &from_sealed.key.identity, &from_identity.key.identity);
    try std.testing.expectEqualSlices(u8, &from_sealed.key.root, &from_identity.key.root);
    try std.testing.expectEqualSlices(u8, &(try appendDigest(a, from_sealed.key)), &(try appendDigest(a, from_identity.key)));
    // Distinct content gives a distinct identity-only source root.
    var g = Fixture.init(2);
    const other_columns = g.columns();
    var distinct = try Key.identityOnly(a, &other_columns, suite, null);
    defer distinct.deinit();
    try std.testing.expect(!std.mem.eql(u8, &distinct.root, &identity.root));
}

const Expected = struct { identity: [32]u8, root: [32]u8, source_root: [32]u8, digest: [32]u8, cells: usize };

fn cold(a: std.mem.Allocator, dir: []const u8, columns: []const engine.pcs.ColumnEvaluation) !Expected {
    var cache = try SetupCache.Cache.init(a, BETA, .{ .mode = .prover, .directory = dir, .fixed_setup_bytes = 1 << 24 });
    defer cache.deinit();
    const c = try cache.obtain(Component, "test-component", .{ .n = 1 }, false, Builder{ .a = a, .columns = columns });
    try std.testing.expectEqual(@as(u64, 1), cache.stats.misses);
    var lease = try cache.fixed.acquireFromKey(&c.key, BETA);
    defer lease.deinit();
    try cache.persist();
    try std.testing.expectEqual(@as(u64, 1), cache.stats.stores);
    // Resident: a second obtain returns the same component without a build.
    const again = try cache.obtain(Component, "test-component", .{ .n = 1 }, false, Builder{ .a = a, .columns = columns });
    try std.testing.expect(again == c);
    try std.testing.expectEqual(@as(u64, 1), cache.stats.resident_hits);
    return .{ .identity = lease.key.identity, .root = lease.key.root, .source_root = c.key.root, .digest = try appendDigest(a, lease.key), .cells = lease.key.cells };
}

fn warm(a: std.mem.Allocator, dir: []const u8, mode: SetupCache.Mode, columns: []const engine.pcs.ColumnEvaluation, expected: Expected) !void {
    var cache = try SetupCache.Cache.init(a, BETA, .{ .mode = mode, .directory = dir, .fixed_setup_bytes = 1 << 24 });
    defer cache.deinit();
    const c = try cache.obtain(Component, "test-component", .{ .n = 1 }, false, Builder{ .a = a, .columns = columns });
    try std.testing.expectEqual(@as(u64, 1), cache.stats.disk_hits);
    try std.testing.expect(c.key.root_only);
    try std.testing.expectEqualSlices(u8, &expected.source_root, &c.key.root);
    var lease = try cache.fixed.acquireFromKey(&c.key, BETA);
    defer lease.deinit();
    const snap = cache.fixed.snapshot();
    try std.testing.expectEqual(@as(u64, 0), snap.seals);
    try std.testing.expectEqual(@as(u64, 1), snap.loads);
    try std.testing.expectEqualSlices(u8, &expected.identity, &lease.key.identity);
    try std.testing.expectEqualSlices(u8, &expected.root, &lease.key.root);
    try std.testing.expectEqual(expected.cells, lease.key.cells);
    switch (mode) {
        .prover => try std.testing.expectEqualSlices(u8, &expected.digest, &(try appendDigest(a, lease.key))),
        .verifier => {
            try std.testing.expect(lease.key.root_only);
            try std.testing.expectError(error.RootOnlyFixedSetupKey, appendDigest(a, lease.key));
        },
    }
}

fn artifactFile(a: std.mem.Allocator, dir: []const u8) ![]u8 {
    var d = try std.fs.cwd().openDir(dir, .{ .iterate = true });
    defer d.close();
    var it = d.iterate();
    while (try it.next()) |entry| if (std.mem.endsWith(u8, entry.name, ".rv64-setup")) return std.fs.path.join(a, &.{ dir, entry.name });
    return error.FileNotFound;
}

fn flipByte(path: []const u8, offset: u64) !void {
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    var b: [1]u8 = undefined;
    _ = try file.preadAll(&b, offset);
    b[0] ^= 0x10;
    try file.pwriteAll(&b, offset);
}

test "setup artifact round-trips for prover and verifier and every tamper is rejected" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir);
    var f = Fixture.init(3);
    const columns = f.columns();
    const expected = try cold(a, dir, &columns);
    try warm(a, dir, .prover, &columns, expected);
    try warm(a, dir, .verifier, &columns, expected);

    const path = try artifactFile(a, dir);
    defer a.free(path);
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 26);
    defer a.free(bytes);
    const vk_len = std.mem.readInt(u64, bytes[80..88], .little);
    // header, VK and bulk bytes; a bulk flip passes VK-only (verifier) reads
    // by design, because the verifier never uses bulk bytes.
    const cases = [_]struct { offset: u64, prover: bool, verifier: bool }{
        .{ .offset = 20, .prover = true, .verifier = true }, // component key
        .{ .offset = 100, .prover = true, .verifier = true }, // payload length
        .{ .offset = 256 + 40, .prover = true, .verifier = true }, // VK source root
        .{ .offset = 256 + vk_len + 3, .prover = true, .verifier = false }, // structure
        .{ .offset = bytes.len - 5, .prover = true, .verifier = false }, // Merkle nodes
        .{ .offset = 256 + vk_len + 200, .prover = true, .verifier = false }, // coefficients
    };
    for (cases) |case| {
        try flipByte(path, case.offset);
        for ([_]SetupCache.Mode{ .prover, .verifier }) |mode| {
            const reject = if (mode == .prover) case.prover else case.verifier;
            var cache = try SetupCache.Cache.init(a, BETA, .{ .mode = mode, .directory = dir, .fixed_setup_bytes = 1 << 24 });
            defer cache.deinit();
            const result = cache.obtain(Component, "test-component", .{ .n = 1 }, false, Builder{ .a = a, .columns = &columns });
            if (reject) try std.testing.expectError(error.SetupCacheArtifactRejected, result) else _ = try result;
        }
        try flipByte(path, case.offset);
    }
    // Truncation is rejected; the restored original loads again.
    {
        const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        defer file.close();
        try file.setEndPos(bytes.len - 1);
    }
    {
        var cache = try SetupCache.Cache.init(a, BETA, .{ .mode = .verifier, .directory = dir, .fixed_setup_bytes = 1 << 24 });
        defer cache.deinit();
        try std.testing.expectError(error.SetupCacheArtifactRejected, cache.obtain(Component, "test-component", .{ .n = 1 }, false, Builder{ .a = a, .columns = &columns }));
    }
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = bytes });
    try warm(a, dir, .prover, &columns, expected);
    // A different component key (geometry rung) is a miss, never a load.
    {
        var cache = try SetupCache.Cache.init(a, BETA, .{ .mode = .prover, .directory = dir, .fixed_setup_bytes = 1 << 24 });
        defer cache.deinit();
        _ = try cache.obtain(Component, "test-component", .{ .n = 2 }, false, Builder{ .a = a, .columns = &columns });
        try std.testing.expectEqual(@as(u64, 1), cache.stats.misses);
    }
    // An artifact copied under another component's name is rejected (the
    // header binds its own key).
    {
        var cache = try SetupCache.Cache.init(a, BETA, .{ .mode = .verifier, .directory = dir, .fixed_setup_bytes = 1 << 24 });
        defer cache.deinit();
        const other = try cache.componentKey("test-component", .{ .n = 3 }, false);
        const name = try std.fmt.allocPrint(a, "{s}/{s}.rv64-setup", .{ dir, std.fmt.bytesToHex(other, .lower) });
        defer a.free(name);
        try std.fs.cwd().writeFile(.{ .sub_path = name, .data = bytes });
        try std.testing.expectError(error.SetupCacheArtifactRejected, cache.obtain(Component, "test-component", .{ .n = 3 }, false, Builder{ .a = a, .columns = &columns }));
    }
}

test "setup seam admits exactly one seal per component" {
    const a = std.testing.allocator;
    var f = Fixture.init(4);
    const columns = f.columns();
    var cache = try SetupCache.Cache.init(a, BETA, .{ .mode = .prover, .directory = null, .fixed_setup_bytes = 1 << 24 });
    defer cache.deinit();
    try std.testing.expectError(error.SetupCacheUnexpectedSeal, cache.obtain(Component, "double", .{ .n = 1 }, false, DoubleSeal{ .a = a, .columns = &columns }));
    // The failed key is not resident; the seam is disarmed afterwards.
    var plain = try Key.sealWithSuite(a, &columns, Key.Suite.experimentalFold4());
    defer plain.deinit();
    try std.testing.expect(!plain.root_only);
}
