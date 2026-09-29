const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const Tree = @import("../vcs_lifted/prover.zig").MerkleProverLifted(H);
const seam = @import("merkle_layer_cache.zig");
const cached = @import("merkle_cached_tree.zig");
const commitment = @import("commitment_tree.zig");

const Fixture = struct {
    bytes: [8192]u8 = undefined,
    size: usize = 0,
    stores: usize = 0,
    loads: usize = 0,
    corrupt: bool = false,
    decline: bool = false,
    payload_limit: u64 = std.math.maxInt(u64),
    refuse_store: bool = false,

    fn arm(self: *@This()) void {
        seam.arm(.{ .ctx = self, .load = load, .store = store, .max_payload_bytes = self.payload_limit });
    }
    fn load(raw: *anyopaque, _: seam.Request, layers: []const []u8) bool {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.loads += 1;
        if (self.decline or self.size == 0) return false;
        var at: usize = 0;
        for (layers) |layer| {
            if (layer.len > self.size - at) return false;
            @memcpy(layer, self.bytes[at..][0..layer.len]);
            at += layer.len;
        }
        if (at != self.size) return false;
        if (self.corrupt) layers[0][0] ^= 1;
        return true;
    }
    fn store(raw: *anyopaque, _: seam.Request, layers: []const []const u8) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.refuse_store) return;
        self.size = 0;
        for (layers) |layer| {
            @memcpy(self.bytes[self.size..][0..layer.len], layer);
            self.size += layer.len;
        }
        self.stores += 1;
    }
};

fn values() [32]M31 {
    var result: [32]M31 = undefined;
    for (&result, 0..) |*v, i| v.* = M31.fromCanonical(@intCast(i * i + 9));
    return result;
}

test "cached owned Merkle trees retain exact roots and queried openings" {
    const allocator = std.testing.allocator;
    var fixture = Fixture{};
    fixture.arm();
    defer seam.disarm();
    const data = values();
    const columns = [_][]const M31{ &data, data[0..16] };
    var original = try Tree.commit(allocator, &columns);
    defer original.deinit(allocator);
    try std.testing.expect(cached.loadColumns(H, allocator, &columns) == null);
    cached.storeReader(H, allocator, &columns, original);
    try std.testing.expectEqual(@as(usize, 1), fixture.stores);
    var loaded = cached.loadColumns(H, allocator, &columns) orelse
        return error.ExpectedCacheHit;
    defer loaded.deinit(allocator);
    try std.testing.expectEqual(original.root(), loaded.root());
    for (0..6) |log| {
        const indices = [_]u32{0};
        const a = try original.readHashes(allocator, @intCast(log), &indices);
        defer allocator.free(a);
        const b = try loaded.readHashes(allocator, @intCast(log), &indices);
        defer allocator.free(b);
        try std.testing.expectEqualSlices(H.Hash, a, b);
    }
    fixture.corrupt = true;
    try std.testing.expect(cached.loadColumns(H, allocator, &columns) == null);
    fixture.corrupt = false;
    fixture.decline = true;
    try std.testing.expect(cached.loadColumns(H, allocator, &columns) == null);
}

const CountingBackend = struct {
    var commits: usize = 0;
    pub const reuses_constant_merkle_parents = true;
    pub fn MerkleTree(comptime Hasher: type) type {
        return @import("../vcs_lifted/prover.zig").MerkleProverLifted(Hasher);
    }
    pub fn commitMerkle(comptime Hasher: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(Hasher) {
        commits += 1;
        return MerkleTree(Hasher).commit(allocator, columns);
    }
};

fn ownedColumns(allocator: std.mem.Allocator) ![]commitment.ColumnEvaluation {
    const columns = try allocator.alloc(commitment.ColumnEvaluation, 1);
    errdefer allocator.free(columns);
    const data = values();
    columns[0] = .{ .log_size = 5, .values = try allocator.dupe(M31, &data) };
    return columns;
}

test "cached owned Merkle commit skips hashing only after a valid cache hit" {
    const allocator = std.testing.allocator;
    const Commitment = commitment.CommitmentTreeProverForBackend(CountingBackend, H);
    var fixture = Fixture{};
    fixture.arm();
    defer seam.disarm();
    CountingBackend.commits = 0;
    var first = try Commitment.initOwned(allocator, try ownedColumns(allocator));
    defer first.deinit(allocator);
    var second = try Commitment.initOwned(allocator, try ownedColumns(allocator));
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), CountingBackend.commits);
    try std.testing.expectEqual(first.root(), second.root());
    fixture.corrupt = true;
    var third = try Commitment.initOwned(allocator, try ownedColumns(allocator));
    defer third.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), CountingBackend.commits);
    try std.testing.expectEqual(first.root(), third.root());
}

test "cached owned Merkle deferred commit carries the coordinator source" {
    const allocator = std.testing.allocator;
    const MC = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Scheme = @import("scheme.zig").CommitmentSchemeProver(CountingBackend, H, MC);
    const deferred = @import("deferred_commit.zig");
    const config: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        .fold_step = 1,
    } };
    var fixture = Fixture{};
    fixture.arm();
    defer seam.disarm();
    var first = try Scheme.init(allocator, config);
    defer first.deinit(allocator);
    var first_channel = core.channel.blake2s.Blake2sChannel{};
    try std.testing.expect(deferred.trySpawn(CountingBackend, Scheme.CommittedTree, &first, allocator, try ownedColumns(allocator), null));
    try deferred.resolve(MC, &first, allocator, &first_channel);
    try std.testing.expectEqual(@as(usize, 1), fixture.stores);
    try std.testing.expectEqual(@as(usize, 1), fixture.loads);

    var second = try Scheme.init(allocator, config);
    defer second.deinit(allocator);
    var second_channel = core.channel.blake2s.Blake2sChannel{};
    try std.testing.expect(deferred.trySpawn(CountingBackend, Scheme.CommittedTree, &second, allocator, try ownedColumns(allocator), null));
    try deferred.resolve(MC, &second, allocator, &second_channel);
    try std.testing.expectEqual(@as(usize, 1), fixture.stores);
    try std.testing.expectEqual(@as(usize, 2), fixture.loads);
    try std.testing.expectEqual(first.trees.items[0].root(), second.trees.items[0].root());
    try std.testing.expectEqual(first_channel.digest, second_channel.digest);
}

test "cached owned Merkle load releases partial allocations on every refusal" {
    const allocator = std.testing.allocator;
    var fixture = Fixture{};
    fixture.arm();
    defer seam.disarm();
    const data = values();
    const columns = [_][]const M31{&data};
    var tree = try Tree.commit(allocator, &columns);
    defer tree.deinit(allocator);
    cached.storeReader(H, allocator, &columns, tree);
    var successes: usize = 0;
    for (0..16) |failure| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = failure });
        if (cached.loadColumns(H, failing.allocator(), &columns)) |hit| {
            var owned = hit;
            owned.deinit(failing.allocator());
            successes += 1;
        }
    }
    try std.testing.expect(successes != 0);
}

const DeviceReader = struct {
    tree: Tree,
    calls: *usize,
    fail_at: ?usize = null,

    pub fn maxLogSize(self: @This()) u32 {
        return self.tree.maxLogSize();
    }
    pub fn readHashes(self: @This(), allocator: std.mem.Allocator, log: u32, indices: []const u32) ![]H.Hash {
        const call = self.calls.*;
        self.calls.* += 1;
        if (self.fail_at == call) return error.InjectedReadFailure;
        return self.tree.readHashes(allocator, log, indices);
    }
};

test "cached owned Merkle fresh capture remains owned when artifact publication fails" {
    const allocator = std.testing.allocator;
    var fixture = Fixture{ .refuse_store = true };
    fixture.arm();
    defer seam.disarm();
    const data = values();
    const columns = [_][]const M31{&data};
    var original = try Tree.commit(allocator, &columns);
    defer original.deinit(allocator);
    var calls: usize = 0;
    var captured = cached.captureAndStoreReader(H, allocator, &columns, DeviceReader{ .tree = original, .calls = &calls }) orelse
        return error.ExpectedFreshCapture;
    defer captured.deinit(allocator);
    try std.testing.expectEqual(original.root(), captured.root());
    try std.testing.expectEqual(@as(usize, 0), fixture.stores);
    try std.testing.expectEqual(@as(usize, 6), calls);
}

test "cached owned Merkle admission refuses oversized payload before reading or allocating layers" {
    const allocator = std.testing.allocator;
    var fixture = Fixture{ .payload_limit = 128 };
    fixture.arm();
    defer seam.disarm();
    const data = values();
    const columns = [_][]const M31{&data};
    var original = try Tree.commit(allocator, &columns);
    defer original.deinit(allocator);
    var calls: usize = 0;
    try std.testing.expect(cached.loadColumns(H, allocator, &columns) == null);
    try std.testing.expect(cached.captureAndStoreReader(H, allocator, &columns, DeviceReader{ .tree = original, .calls = &calls }) == null);
    try std.testing.expectEqual(@as(usize, 0), calls);
    try std.testing.expectEqual(@as(usize, 0), fixture.loads);
    try std.testing.expectEqual(@as(usize, 0), fixture.stores);
}

test "cached owned Merkle fresh capture releases partial reads and allocation failures" {
    const allocator = std.testing.allocator;
    var fixture = Fixture{};
    fixture.arm();
    defer seam.disarm();
    const data = values();
    const columns = [_][]const M31{&data};
    var original = try Tree.commit(allocator, &columns);
    defer original.deinit(allocator);
    for (0..6) |failure| {
        var calls: usize = 0;
        try std.testing.expect(cached.captureAndStoreReader(H, allocator, &columns, DeviceReader{ .tree = original, .calls = &calls, .fail_at = failure }) == null);
    }
    try std.testing.expectEqual(@as(usize, 0), fixture.stores);
    var successes: usize = 0;
    for (0..20) |failure| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = failure });
        var calls: usize = 0;
        if (cached.captureAndStoreReader(H, failing.allocator(), &columns, DeviceReader{ .tree = original, .calls = &calls })) |tree| {
            var owned = tree;
            owned.deinit(failing.allocator());
            successes += 1;
        }
    }
    try std.testing.expect(successes != 0);
}
