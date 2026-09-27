//! Bounded content-addressed decoded-ROM root computation and validation.
//! Every lookup hashes all current leaf bytes and checks any claimed root. No caller
//! flag, pointer identity, or proof-supplied receipt can bypass validation.
//! This changes host work only: commitments and protocol identities are intact.
const std = @import("std");
const tree = @import("../memory_commitment/blake3_state_tree.zig");
const Hash = @import("stwo_core").vcs.blake3_hash.Blake3Hasher;
const capacity = 8;
var shared: Cache = .{};
pub fn validate(leaves: []const tree.Leaf, root: tree.Digest) !void {
    return shared.validate(leaves, root);
}
pub fn computeRoot(leaves: []const tree.Leaf) !tree.Digest {
    // Research control for same-binary proof/latency comparison. Validation
    // remains mandatory and unchanged when computation caching is disabled.
    if (std.process.hasEnvVarConstant("STWO_RISCV_UNCACHED_PROGRAM_ROOT"))
        return tree.TreeHasher.init(.program).root(leaves);
    return shared.compute(leaves, null);
}
const Cache = struct {
    mutex: std.Thread.Mutex = .{},
    entries: [capacity]?struct { key: [32]u8, root: tree.Digest } = @splat(null),
    next: usize = 0,
    hits: usize = 0,
    validations: usize = 0,

    pub fn validate(self: *Cache, leaves: []const tree.Leaf, root: tree.Digest) !void {
        _ = try self.compute(leaves, root);
    }
    fn compute(self: *Cache, leaves: []const tree.Leaf, expected: ?tree.Digest) !tree.Digest {
        const key = identity(leaves);
        self.mutex.lock();
        for (self.entries) |entry| if (entry) |cached| {
            if (std.mem.eql(u8, &cached.key, &key)) {
                if (expected) |claimed| if (!std.meta.eql(cached.root, claimed)) {
                    self.mutex.unlock();
                    return error.ProgramRootMismatch;
                };
                self.hits +|= 1;
                self.mutex.unlock();
                return cached.root;
            }
        };
        self.mutex.unlock();
        // Do expensive work outside the lock. Concurrent duplicate misses are
        // harmless; only independently successful validations are published.
        const hasher = tree.TreeHasher.init(.program);
        const computed = try hasher.root(leaves);
        if (expected) |claimed| if (!std.meta.eql(computed, claimed)) return error.ProgramRootMismatch;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries[self.next] = .{ .key = key, .root = computed };
        self.next = (self.next + 1) % capacity;
        self.validations +|= 1;
        return computed;
    }
};
fn identity(leaves: []const tree.Leaf) [32]u8 {
    var hash = Hash.init();
    hash.update("stwo.riscv.program-root-cache.v2");
    hash.update(tree.DOMAIN);
    var count: [8]u8 = undefined;
    std.mem.writeInt(u64, &count, @intCast(leaves.len), .little);
    hash.update(&count);
    // Cache entries never leave this process. Leaf is precisely two u32 words
    // with no padding, so native byte order is a complete local content key.
    comptime std.debug.assert(@sizeOf(tree.Leaf) == 8);
    hash.update(std.mem.sliceAsBytes(leaves));
    return hash.finalize();
}

test "program validation cache admits exact content and rejects mutations" {
    var cache: Cache = .{};
    var leaves = [_]tree.Leaf{ .{ .index = 0, .value = 42 }, .{ .index = 1, .value = 7 } };
    const hasher = tree.TreeHasher.init(.program);
    const root = try hasher.root(&leaves);
    try cache.validate(&leaves, root);
    try cache.validate(&leaves, root);
    try std.testing.expectEqual(@as(usize, 1), cache.validations);
    try std.testing.expectEqual(@as(usize, 1), cache.hits);
    leaves[1].value ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, cache.validate(&leaves, root));
    leaves[1].value ^= 1;
    leaves[1].index = 2;
    try std.testing.expectError(error.ProgramRootMismatch, cache.validate(&leaves, root));
    leaves[1].index = 1;
    var changed = root;
    changed.bytes[31] ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, cache.validate(&leaves, changed));
    try std.testing.expectEqual(@as(usize, 1), cache.validations);
    try cache.validate(&leaves, root);
    try std.testing.expectEqual(@as(usize, 2), cache.hits);
}
test "program validation cache eviction preserves validation" {
    var cache: Cache = .{};
    const hasher = tree.TreeHasher.init(.program);
    for (0..capacity + 1) |i| {
        const leaves = [_]tree.Leaf{.{ .index = 0, .value = @intCast(i + 1) }};
        try cache.validate(&leaves, try hasher.root(&leaves));
    }
    const first = [_]tree.Leaf{.{ .index = 0, .value = 1 }};
    try cache.validate(&first, try hasher.root(&first));
    try std.testing.expectEqual(@as(usize, capacity + 2), cache.validations);
}

test "program validation cache shares computed roots without trusting claimed roots" {
    var cache: Cache = .{};
    var leaves = [_]tree.Leaf{.{ .index = 4, .value = 17 }};
    const first = try cache.compute(&leaves, null);
    try cache.validate(&leaves, first);
    try std.testing.expectEqual(@as(usize, 1), cache.validations);
    try std.testing.expectEqual(@as(usize, 1), cache.hits);
    var wrong = first;
    wrong.bytes[0] ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, cache.validate(&leaves, wrong));
    leaves[0].value = 18;
    const second = try cache.compute(&leaves, null);
    try std.testing.expect(!std.meta.eql(first, second));
    try std.testing.expectEqualDeep(try tree.TreeHasher.init(.program).root(&leaves), second);
    try std.testing.expectEqual(@as(usize, 2), cache.validations);
}
