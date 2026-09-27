const std = @import("std");
const core = @import("stwo_core");
const runtime_mod = @import("runtime.zig");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M31 = core.fields.m31.M31;
const ffi = @import("runtime/bindings.zig");

test "Metal staged BLAKE3 trees reuse plans with one submission and no intermediate waits" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    for ([_]u32{ 17, 250, 762, 2042 }) |width| {
        const stride = runtime_mod.Runtime.blake3LeafStateWords(width);
        const offsets = try allocator.alloc(u32, width);
        defer allocator.free(offsets);
        const logs = try allocator.alloc(u32, width);
        defer allocator.free(logs);
        var cursor: u32 = 64;
        for (offsets, logs, 0..) |*offset, *log, i| {
            log.* = 1 + @as(u32, @intCast(i * 4 / width));
            offset.* = cursor;
            cursor += (@as(u32, 1) << @intCast(log.*)) + 3;
        }
        const states = [2]u32{ std.mem.alignForward(u32, cursor, 64) + 64, std.mem.alignForward(u32, cursor, 64) + 128 + 16 * stride };
        cursor = states[1] + 16 * stride + 64;
        var layers: [5]u32 = undefined;
        // Retain root first, as the proving arena does.
        for (0..5) |i| {
            const level = 4 - i;
            layers[level] = cursor;
            cursor = std.mem.alignForward(u32, cursor + (@as(u32, 16) >> @intCast(level)) * 8, 64) + 64;
        }
        var arena = try runtime.allocateResidentBuffer(@as(usize, cursor) * 4);
        defer arena.deinit();
        const actual = @as([*]u32, @ptrCast(@alignCast(arena.contents)))[0..cursor];
        const expected = try allocator.alloc(u32, cursor);
        defer allocator.free(expected);
        var plan = try runtime.prepareStagedBlake3ResidentMerkle(offsets, logs, 4, &layers, states);
        defer plan.deinit();
        var stage_count: u64 = 0;
        var first: usize = 0;
        while (first < width) {
            var end = first + 1;
            while (end < width and end - first < 16 and logs[end] == logs[first]) : (end += 1) {}
            first = end;
            stage_count += 1;
        }
        for (0..2) |iteration| {
            @memset(actual, 0xa5a5a5a5);
            for (offsets, logs, 0..) |offset, log, column| {
                for (actual[offset..][0 .. @as(usize, 1) << @intCast(log)], 0..) |*word, row|
                    word.* = (@as(u32, @intCast(column * 37 + row + iteration)) *% 0x9e3779b9) % 0x7fffffff;
            }
            @memcpy(expected, actual);
            for (0..16) |row| {
                var hasher = H.defaultWithInitialState();
                for (offsets, logs) |offset, log| {
                    const shift = 4 - log;
                    const index = if (shift == 0) row else ((row >> @intCast(shift + 1)) << 1) | (row & 1);
                    hasher.updateLeaf(&.{M31.fromCanonical(actual[offset + index])});
                }
                const digest = hasher.finalize();
                for (expected[layers[0] + row * 8 ..][0..8], 0..) |*word, i|
                    word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            }
            for (1..5) |level| for (0..@as(usize, 16) >> @intCast(level)) |parent| {
                const source = layers[level - 1] + parent * 16;
                const digest = H.hashChildren(.{ .left = std.mem.toBytes(expected[source..][0..8].*), .right = std.mem.toBytes(expected[source + 8 ..][0..8].*) });
                for (expected[layers[level] + parent * 8 ..][0..8], 0..) |*word, i|
                    word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            };
            var epoch = try runtime.beginCommandEpoch(arena);
            defer epoch.deinit();
            try expectAdoptionRejected(&runtime, arena, plan, &epoch);
            try epoch.encodeResidentMerkle(plan);
            try expectAdoptionRejected(&runtime, arena, plan, &epoch);
            try epoch.submit();
            const stats = try epoch.wait();
            try std.testing.expectEqual(@as(u64, 1), stats.command_buffers);
            try std.testing.expectEqual(@as(u64, 1), stats.wait_count);
            try std.testing.expectEqual(@as(u64, 0), stats.intermediate_wait_count);
            try std.testing.expectEqual(stage_count + 4, stats.dispatches);
            var other_plan = try runtime.prepareStagedBlake3ResidentMerkle(offsets, logs, 4, &layers, states);
            defer other_plan.deinit();
            try expectAdoptionRejected(&runtime, arena, other_plan, &epoch);
            var other_arena = try runtime.allocateResidentBuffer(@as(usize, cursor) * 4);
            defer other_arena.deinit();
            try expectAdoptionRejected(&runtime, other_arena, plan, &epoch);
            var tree = try runtime.residentMerkleTreeFromCompletedArena(arena, plan, &epoch);
            defer tree.deinit();
            const root = try tree.root();
            try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected[layers[4]..][0..8]), &root.hash);
            try expectAdoptionRejected(&runtime, arena, plan, &epoch);

            for (states) |state| @memcpy(expected[state..][0 .. 16 * stride], actual[state..][0 .. 16 * stride]);
            try std.testing.expectEqualSlices(u32, expected, actual);
            std.debug.print("BLAKE3_STAGED_TREE columns={d} reuse={d} stages={d} dispatches={d} gpu_ms={d}\n", .{ width, iteration, stage_count, stats.dispatches, stats.gpu_milliseconds });
        }
    }
}

fn expectAdoptionRejected(runtime: *runtime_mod.Runtime, arena: runtime_mod.ResidentBuffer, plan: runtime_mod.ResidentMerklePlan, epoch: *@import("command_epoch.zig").CommandEpoch) !void {
    var message: [1024]u8 = @splat(0);
    const handle = ffi.stwo_zig_metal_resident_merkle_tree_from_completed_arena(runtime.handle, epoch.handle, arena.handle, plan.handle, &message, message.len);
    if (handle) |unexpected| {
        var tree: runtime_mod.Tree = .{ .handle = unexpected, .runtime_handle = runtime.handle, .log_size = plan.lifting_log_size };
        tree.deinit();
        return error.UnqualifiedTreeAdoption;
    }
}
