const std = @import("std");
const values = @import("values.zig");
const policy = @import("policy.zig");
const Memory = @import("../../memory.zig").Memory;
const a = std.testing.allocator;

fn singlePatch(cache: *const values.Cache, index: u64, digest: values.Digest) ![values.MAX_DEPTH + 1]values.Patch {
    var result: [values.MAX_DEPTH + 1]values.Patch = undefined;
    var current = digest;
    for (0..@as(usize, cache.geometry.depth()) + 1) |height| {
        const at = index >> @intCast(height);
        result[height] = .{ .height = @intCast(height), .index = at, .before = try cache.get(@intCast(height), at), .after = current };
        if (height != cache.geometry.depth()) {
            const sibling = try cache.get(@intCast(height), at ^ 1);
            current = try values.hashNode(cache.geometry, @intCast(height), if (at & 1 == 0) current else sibling, if (at & 1 == 0) sibling else current, null);
        }
    }
    return result;
}

test "RV64 value-only root: mapped zero heap has no value-tree leaves and policy remains independent" {
    var native = Memory.init(a, .{});
    defer native.deinit();
    try native.map(.{ .start = 0x1_0000_0000, .size = 224 * 1024 * 1024, .permissions = .{ .read = true, .write = true } });
    var empty = try values.Cache.empty(a, .chunk512);
    defer empty.deinit();
    var mapped = try values.Cache.fromMemory(a, .chunk512, &native);
    defer mapped.deinit();
    try std.testing.expect(values.equal(empty.root(), mapped.root()));
    try std.testing.expectEqual(@as(usize, 0), mapped.count());
    var mapped_policy = try policy.Policy.fromMemory(a, &native);
    defer mapped_policy.deinit();
    var empty_policy = try policy.Policy.init(a, &.{});
    defer empty_policy.deinit();
    try std.testing.expect(!std.meta.eql(mapped_policy.identity, empty_policy.identity));
}

test "RV64 value-only root: lazy chunk insertion and deletion match an independently read native image" {
    var native = Memory.init(a, .{});
    defer native.deinit();
    const address: u64 = 0x1_0000_0e08;
    try native.map(.{ .start = address & ~@as(u64, 4095), .size = 4096, .permissions = .{ .read = true, .write = true } });
    var cache = try values.Cache.fromMemory(a, .chunk512, &native);
    defer cache.deinit();
    const before = cache.root();
    try native.store(address, 8, 17);
    var words: [64]u64 = @splat(0);
    words[(address & 511) >> 3] = 17;
    const patch = try singlePatch(&cache, address >> 9, try values.hashValues(.chunk512, &words, null));
    try cache.applyPatch(patch[0..56]);
    var expected = try values.Cache.fromMemory(a, .chunk512, &native);
    defer expected.deinit();
    try std.testing.expect(values.equal(expected.root(), cache.root()));
    var reverse = patch;
    for (reverse[0..56], patch[0..56]) |*entry, original| entry.* = .{ .height = original.height, .index = original.index, .before = original.after, .after = original.before };
    try cache.applyPatch(reverse[0..56]);
    try std.testing.expect(values.equal(before, cache.root()));
    try std.testing.expectEqual(@as(usize, 0), cache.count());
}

test "RV64 value-only root: geometry domains and full u64 values do not alias" {
    var words: [512]u64 = @splat(0);
    words[0] = std.math.maxInt(u64);
    var recorder = values.Recorder{ .allocator = a };
    defer recorder.deinit();
    const small = try values.hashValues(.chunk512, words[0..64], &recorder);
    try std.testing.expectEqual(@as(usize, 38), recorder.calls.items.len);
    const large = try values.hashValues(.page4096, &words, null);
    try std.testing.expect(!values.equal(small, large));
    words[0] -= 0x7fff_ffff;
    try std.testing.expect(!values.equal(small, try values.hashValues(.chunk512, words[0..64], null)));
    const low = [_]values.Entry{.{ .index = 1, .digest = small }};
    const high = [_]values.Entry{.{ .index = 1 + (@as(u64, 1) << 23), .digest = small }};
    var left = try values.Cache.fromEntries(a, .chunk512, &low);
    defer left.deinit();
    var right = try values.Cache.fromEntries(a, .chunk512, &high);
    defer right.deinit();
    try std.testing.expect(!values.equal(left.root(), right.root()));
}

fn patchFailure(allocator: std.mem.Allocator, patch: []const values.Patch) !void {
    var cache = try values.Cache.empty(allocator, .chunk512);
    defer cache.deinit();
    const root = cache.root();
    cache.applyPatch(patch) catch |err| {
        try std.testing.expect(values.equal(root, cache.root()));
        try std.testing.expectEqual(@as(usize, 0), cache.count());
        return err;
    };
}

test "RV64 value-only root: all-level reservation failures preserve the complete previous root" {
    var cache = try values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var words: [64]u64 = @splat(0);
    words[0] = 7;
    const patch = try singlePatch(&cache, 19, try values.hashValues(.chunk512, &words, null));
    try std.testing.checkAllAllocationFailures(a, patchFailure, .{patch[0..56]});
}

test "RV64 value-only root: one-pass provider writer matches native sponge and all qualified permutation rows" {
    const provider = @import("../../../air/memory_commitment/poseidon2_universal_degree3_v1.zig");
    const Q = @import("stwo_core").fields.qm31.QM31;
    const M = @import("stwo_core").fields.m31.M31;
    const physical = @import("../witness.zig").physical;
    const storage = try a.alloc(M, provider.N_MAIN_COLUMNS * 64);
    defer a.free(storage);
    var writer = try values.ProviderWriter.init(storage, 6);
    var recorder = values.Recorder{ .allocator = a, .writer = &writer };
    defer recorder.deinit();
    try recorder.calls.ensureTotalCapacity(a, 42);
    var words: [64]u64 = undefined;
    for (&words, 0..) |*word, i| word.* = @as(u64, @intCast(i)) *% 0x0123_4567_89ab_cdef;
    const digest = try values.hashValues(.chunk512, &words, &recorder);
    try std.testing.expect(values.equal(digest, try values.hashValues(.chunk512, &words, null)));
    const node_digest = try values.hashNode(.chunk512, 54, digest, digest, &recorder);
    try std.testing.expect(values.equal(node_digest, try values.hashNode(.chunk512, 54, digest, digest, null)));
    try writer.finishPadding();
    try std.testing.expectEqual(@as(usize, 42), writer.used);
    for (0..64) |logical| {
        const row = physical(logical, 6);
        var secure: [provider.N_MAIN_COLUMNS]Q = undefined;
        for (&secure, 0..) |*field, column| field.* = Q.fromBase(storage[column * 64 + row]);
        for (provider.evaluateGeneric(Q, secure)) |constraint| try std.testing.expect(constraint.isZero());
        if (logical < writer.used) {
            const output = provider.outputGeneric(Q, secure);
            for (output, recorder.calls.items[logical].output) |actual, expected| try std.testing.expectEqualDeep(Q.fromBase(expected), actual);
        }
    }
}
