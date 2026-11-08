//! Small digest/tree parity only: no execution segments or STARK proving.
const std = @import("std");
const core = @import("stwo_core");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const Compact = @import("vcs_lifted/compact_blake3_leaf.zig").Hasher;
const Layer = @import("vcs_lifted/layers.zig").Operations(H);
const CompactLayer = @import("vcs_lifted/layers.zig").Operations(Compact);
const Frame = core.channel.blake3.Frame;
const batch = core.crypto.blake3_compression_batch;
const scalar = core.crypto.blake3_compression;
const benchmark = @import("blake3_frame_batch_benchmark.zig");

// Tests inside stwo_core are a separate module's tests. Keep these checks in
// this root explicitly, rather than relying on importing its declarations.
test "BLAKE3 root integration compress4 matches all scalar output words" {
    var rng = std.Random.DefaultPrng.init(0x20260926);
    const counters: [4]u64 = .{ 0, 0xffffffff, 0x100000000, 0xffffffffffffffff };
    const lengths: [4]u32 = .{ 0, 1, 63, 64 };
    const flags: [4]u32 = .{ 1, 2 | 8, 1 | 2 | 8, 4 };
    for (0..32) |_| {
        var cvs: [4][8]u32 = undefined;
        var blocks: [4][16]u32 = undefined;
        rng.random().bytes(std.mem.asBytes(&cvs));
        rng.random().bytes(std.mem.asBytes(&blocks));
        const actual = try batch.compress4(cvs, blocks, counters, lengths, flags);
        for (0..4) |lane| {
            const expected = try scalar.compress(cvs[lane], blocks[lane], counters[lane], lengths[lane], flags[lane]);
            try std.testing.expectEqualSlices(u32, &expected, &actual[lane]);
        }
    }
    try std.testing.expectError(error.InvalidBlake3BlockLength, batch.compress4(@splat(scalar.IV), @splat(@splat(0)), counters, .{ 0, 1, 65, 64 }, flags));
}

test "BLAKE3 root integration hashChunk4 matches independent std boundaries and caps" {
    var bytes: [1025]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0x20260927);
    rng.random().bytes(&bytes);
    const lengths = [_][4]usize{ .{ 0, 1, 63, 64 }, .{ 65, 68, 72, 92 }, .{ 127, 128, 129, 1024 }, .{ 1024, 0, 512, 64 } };
    for (lengths) |group| {
        var messages: [4][]const u8 = undefined;
        for (group, &messages) |length, *message| message.* = bytes[0..length];
        const actual = try batch.hashChunk4(messages);
        for (messages, actual) |message, digest| {
            var expected: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(message, &expected, .{});
            try std.testing.expectEqualSlices(u8, &expected, &digest);
        }
    }
    for (0..4) |oversized_lane| {
        var messages: [4][]const u8 = @splat(bytes[0..64]);
        messages[oversized_lane] = &bytes;
        try std.testing.expectError(error.Blake3BatchMessageTooLarge, batch.hashChunk4(messages));
    }
}

test "BLAKE3 root integration mixed Frame hash4 preserves canonical std digests" {
    const M = core.fields.m31.M31;
    const values = [_]M{ M.fromCanonical(1), M.fromCanonical(0x7ffffffe) };
    const words = [_]u32{ 0, 0xffffffff, 0x10000000 };
    const groups = [_][4]Frame{
        .{ .{ .init = {} }, .{ .integer = .{ .state = @splat(1), .value = 0xffffffffffffffff } }, .{ .root = .{ .state = @splat(2), .value = @splat(3) } }, .{ .draw = .{ .state = @splat(4), .index = 0x100000000 } } },
        .{ .{ .pow = .{ .state = @splat(5), .bits = 26, .nonce = 0xffffffffffffffff } }, .{ .node = .{ .left = @splat(6), .right = @splat(7) } }, .{ .init = {} }, .{ .integer = .{ .state = @splat(8), .value = 0 } } },
        .{ .{ .node = .{ .left = @splat(9), .right = @splat(10) } }, .{ .leaf = &values }, .{ .words = .{ .state = @splat(11), .values = &words } }, .{ .felts = .{ .state = @splat(12), .values = &.{} } } },
    };
    for (groups) |frames| {
        const actual = Frame.hash4(frames);
        for (frames, actual) |frame, digest| {
            const encoded = try frame.encode(std.testing.allocator);
            defer std.testing.allocator.free(encoded);
            var expected: H.Hash = undefined;
            std.crypto.hash.Blake3.hash(encoded, &expected, .{});
            try std.testing.expectEqualSlices(u8, &expected, &digest);
            try std.testing.expectEqualSlices(u8, &frame.hash(), &digest);
        }
    }
}

test "BLAKE3 optional diagnostic rejects limits before starting timed work" {
    try std.testing.expectError(error.InvalidBlake3BenchmarkIterations, benchmark.run(0));
    try std.testing.expectError(error.InvalidBlake3BenchmarkIterations, benchmark.run(benchmark.max_iterations + 1));
}

test "BLAKE3 bounded node and PoW kernel diagnostic" {
    const report = try benchmark.run(4096);
    for (report.samples, 0..) |sample, i| {
        std.debug.print("BLAKE3_BATCH_KERNEL sample={d} operations={d} batch_first={} node_scalar_ns={d} node_batch4_ns={d} pow_scalar_ns={d} pow_batch4_ns={d}\n", .{
            i,                                report.operations_per_sample,     sample.batch_first, sample.node_scalar_ns, sample.node_batch4_ns,
            sample.pow_final_block_scalar_ns, sample.pow_final_block_batch4_ns,
        });
    }
}

fn independentNode(left: H.Hash, right: H.Hash) !H.Hash {
    const encoded = try (Frame{ .node = .{ .left = left, .right = right } }).encode(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    var digest: H.Hash = undefined;
    std.crypto.hash.Blake3.hash(encoded, &digest, .{});
    return digest;
}

test "BLAKE3 batched tree layers and compact alias preserve scalar upper tails" {
    const a = std.testing.allocator;
    var leaves: [32]H.Hash = undefined;
    var rng = std.Random.DefaultPrng.init(0x20260929);
    rng.random().bytes(std.mem.asBytes(&leaves));
    var executor = Layer.Executor{};
    defer executor.deinit();
    var compact_executor = CompactLayer.Executor{};
    defer compact_executor.deinit();
    var allocated = std.ArrayList([]H.Hash).empty;
    defer {
        for (allocated.items) |layer| a.free(layer);
        allocated.deinit(a);
    }
    var previous: []const H.Hash = &leaves;
    while (previous.len > 1) {
        const actual = try Layer.buildNextLayer(a, previous, &executor, 1);
        errdefer a.free(actual);
        const compact = try CompactLayer.buildNextLayer(a, previous, &compact_executor, 1);
        defer a.free(compact);
        for (actual, compact, 0..) |digest, compact_digest, index| {
            const expected = try independentNode(previous[2 * index], previous[2 * index + 1]);
            try std.testing.expectEqualSlices(u8, &expected, &digest);
            try std.testing.expectEqualSlices(u8, &expected, &compact_digest);
        }
        try allocated.append(a, actual);
        previous = actual;
    }
    // The first levels use four-lane batches; the final two levels contain
    // two and one nodes respectively, exercising the unchanged scalar tails.
    var subtree = std.ArrayList([]H.Hash).empty;
    defer {
        for (subtree.items) |layer| a.free(layer);
        subtree.deinit(a);
    }
    try Layer.buildUpperLayersSubtree(a, a, &leaves, &executor, 1, &subtree);
    try std.testing.expectEqual(allocated.items.len, subtree.items.len);
    for (allocated.items, subtree.items) |expected, actual| try std.testing.expectEqualSlices(H.Hash, expected, actual);
}

comptime {
    _ = core.crypto.blake3_compression_batch;
    _ = core.channel.blake3.framing;
    _ = @import("pcs/blake3_pow_batch.zig");
}
