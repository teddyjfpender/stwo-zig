const std = @import("std");
const core = @import("stwo_core");
const runtime_mod = @import("runtime.zig");
const domain = @import("hash_domain.zig");
const M31 = core.fields.m31.M31;

test "Metal typed FRI trees preserve packed leaves every parent and arena guards" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    inline for (.{ core.vcs_lifted.blake3_merkle.MerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher }) |H| {
        const params = comptime domain.parameters(H);
        const family: domain.FamilyV1 = if (params) |p| p.family else .blake3;
        const leaf_seed: [8]u32 = if (params) |p| p.leaf_seed else .{0} ** 8;
        const node_seed: [8]u32 = if (params) |p| p.node_seed else .{0} ** 8;
        const prefix: u32 = if (params) |p| p.domain_prefix_bytes else 0;
        for (0..3) |packing| {
            const size: u32 = 128;
            const stride = 137;
            const base = 64;
            const leaves = size >> @as(u5, @intCast(packing));
            const levels: usize = 8 - packing;
            var offsets: [8]u32 = undefined;
            var cursor: u32 = 64;
            // Root-first storage exercises nonmonotonic bottom-up offsets.
            for (0..levels) |i| {
                const level = levels - 1 - i;
                offsets[level] = cursor;
                cursor = std.mem.alignForward(u32, cursor + (@as(u32, @intCast(leaves)) >> @intCast(level)) * 8, 64) + 64;
            }
            const evaluation_base = cursor + base;
            const words = evaluation_base + stride * 3 + size + 64;
            var arena = try runtime.allocateResidentBuffer(@as(usize, words) * 4);
            defer arena.deinit();
            const actual = @as([*]u32, @ptrCast(@alignCast(arena.contents)))[0..words];
            const expected = try allocator.alloc(u32, words);
            defer allocator.free(expected);
            var plan = try runtime.prepareFriTreeForFamily(evaluation_base, stride, size, @intCast(packing), offsets[0..levels], leaf_seed, node_seed, prefix, family);
            defer plan.deinit();
            for (0..2) |iteration| {
                @memset(actual, 0xa5a5a5a5);
                for (0..4) |coordinate| for (0..size) |row| {
                    actual[evaluation_base + coordinate * stride + row] = (@as(u32, @intCast(coordinate * 1000 + row + iteration)) *% 0x9e3779b9) % 0x7fffffff;
                };
                @memcpy(expected, actual);
                const rows: usize = @as(usize, 1) << @intCast(packing);
                for (0..leaves) |leaf| {
                    var hasher = H.defaultWithInitialState();
                    for (0..rows) |offset| for (0..4) |coordinate| {
                        hasher.updateLeaf(&.{M31.fromCanonical(actual[evaluation_base + coordinate * stride + leaf * rows + offset])});
                    };
                    const digest = hasher.finalize();
                    for (expected[offsets[0] + leaf * 8 ..][0..8], 0..) |*word, i|
                        word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
                }
                for (1..levels) |level| for (0..leaves >> @intCast(level)) |parent| {
                    const source = offsets[level - 1] + parent * 16;
                    const digest = H.hashChildren(.{ .left = std.mem.toBytes(expected[source..][0..8].*), .right = std.mem.toBytes(expected[source + 8 ..][0..8].*) });
                    for (expected[offsets[level] + parent * 8 ..][0..8], 0..) |*word, i|
                        word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
                };
                const gpu_ms = try runtime.friTreePrepared(arena, plan);
                try std.testing.expectEqualSlices(u32, expected, actual);
                std.debug.print("METAL_FRI_TREE family={s} prefix={d} packing={d} reuse={d} gpu_ms={d}\n", .{ @tagName(family), prefix, packing, iteration, gpu_ms });
            }
        }
    }
}

test "Metal typed FRI plans reject invalid domains overlapping layouts and truncated parents" {
    const ffi = @import("runtime/bindings.zig");
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    var message: [1024]u8 = @splat(0);
    const Case = struct { stride: u32 = 128, size: u32 = 128, packing: u32 = 0, layers: [2]u32 = .{ 2048, 4096 }, seed: [8]u32 = .{0} ** 8, prefix: u32 = 0, family: u32 = 3 };
    for ([_]Case{
        .{ .family = 99 },                   .{ .seed = .{1} ** 8 },                         .{ .prefix = 64 },
        .{ .stride = 127 },                  .{ .size = 3 },                                 .{ .packing = 3 },
        .{ .layers = .{ 64, 4096 } },        .{ .layers = .{ 2048, 2056 } },                 .{ .size = 1 },
        .{ .stride = std.math.maxInt(u32) }, .{ .layers = .{ std.math.maxInt(u32), 4096 } },
    }) |case| {
        const handle = ffi.stwo_zig_metal_fri_tree_prepare_v2(runtime.handle, 64, case.stride, case.size, case.packing, &case.layers, 2, &case.seed, &case.seed, case.prefix, case.family, &message, message.len);
        if (handle) |unexpected| {
            var invalid_plan: runtime_mod.FriTreePlan = .{ .handle = unexpected };
            invalid_plan.deinit();
            return error.InvalidFriPlanAccepted;
        }
    }
    var plan = try runtime.prepareFriTreeForFamily(64, 128, 128, 0, &.{ 2048, 4096 }, .{0} ** 8, .{0} ** 8, 0, .blake3);
    defer plan.deinit();
    var arena = try runtime.allocateResidentBuffer(4096 * 4);
    defer arena.deinit();
    const words = @as([*]u32, @ptrCast(@alignCast(arena.contents)))[0..4096];
    @memset(words, 0x12345678);
    var gpu_ms: f64 = 0;
    try std.testing.expect(!ffi.stwo_zig_metal_fri_tree_prepared(runtime.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len));
    for (words) |word| try std.testing.expectEqual(@as(u32, 0x12345678), word);
}
