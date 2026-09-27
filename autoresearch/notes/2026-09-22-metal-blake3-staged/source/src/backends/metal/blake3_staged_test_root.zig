const std = @import("std");
const core = @import("stwo_core");
const runtime_mod = @import("runtime.zig");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M31 = core.fields.m31.M31;

test "Metal BLAKE3 compact stages preserve chunk state across lifting and arbitrary splits" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    for ([_]u32{ 17, 249, 250, 505, 762, 2042 }) |width| {
        const state_words = runtime_mod.Runtime.blake3LeafStateWords(width);
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
        const state0 = std.mem.alignForward(u32, cursor, 64) + 64;
        const state1 = state0 + 16 * state_words + 64;
        const digest_at = state1 + 16 * state_words + 64;
        const arena_words = digest_at + 16 * 8 + 64;
        var arena = try runtime.allocateResidentBuffer(@as(usize, arena_words) * 4);
        defer arena.deinit();
        const actual = @as([*]u32, @ptrCast(@alignCast(arena.contents)))[0..arena_words];
        const expected = try allocator.alloc(u32, arena_words);
        defer allocator.free(expected);
        @memset(actual, 0xa5a5a5a5);
        for (offsets, logs, 0..) |offset, log, column| {
            const rows = @as(usize, 1) << @intCast(log);
            for (actual[offset..][0..rows], 0..) |*word, row|
                word.* = (@as(u32, @intCast(column * 37 + row)) *% 0x9e3779b9) % 0x7fffffff;
        }
        @memcpy(expected, actual);
        var first: u32 = 0;
        var source = state0;
        var destination = state1;
        var source_log: u32 = 0;
        var stage: usize = 0;
        const splits = [_]u32{ 1, 8, 16, 7, 15 };
        while (first < width) : (stage += 1) {
            const count = @min(width - first, splits[stage % splits.len]);
            const end = first + count;
            const log = logs[end - 1];
            const rows = @as(usize, 1) << @intCast(log);
            // Finish the current prefix independently, then retain the same
            // stage for continuation. This checks every possible final block.
            _ = try runtime.blake3LeafAbsorbCompact(arena, offsets[first..end], logs[first..end], source, source_log, digest_at, log, first, true, state_words);
            for (0..rows) |row| {
                var hasher = H.defaultWithInitialState();
                for (offsets[0..end], logs[0..end]) |offset, column_log| {
                    const shift = log - column_log;
                    const index = if (shift == 0) row else ((row >> @intCast(shift + 1)) << 1) | (row & 1);
                    hasher.updateLeaf(&.{M31.fromCanonical(actual[offset + index])});
                }
                const digest = hasher.finalize();
                for (expected[digest_at + row * 8 ..][0..8], 0..) |*word, i|
                    word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            }
            try std.testing.expectEqualSlices(u32, expected, actual);
            if (end < width) {
                _ = try runtime.blake3LeafAbsorbCompact(arena, offsets[first..end], logs[first..end], source, source_log, destination, log, first, false, state_words);
                const live = 24 + 8 * @as(usize, @popCount((@as(u64, end) + 6) / 256));
                for (0..rows) |row| {
                    const base = destination + row * state_words;
                    @memcpy(expected[base..][0..live], actual[base..][0..live]);
                }
                try std.testing.expectEqualSlices(u32, expected, actual);
                std.mem.swap(u32, &source, &destination);
            }
            first = end;
            source_log = log;
        }
        try std.testing.expectError(error.CommitmentFailed, runtime.blake3LeafAbsorbCompact(arena, offsets[0..1], logs[0..1], state0, 4, state0, 4, 1, false, state_words));
        try std.testing.expectError(error.CommitmentFailed, runtime.blake3LeafAbsorbCompact(arena, offsets[0..1], logs[0..1], state0, 4, state1, 4, 0, false, 23));
        try std.testing.expectError(error.CommitmentFailed, runtime.blake3LeafAbsorbCompact(arena, offsets[0..1], logs[0..1], state0, 4, arena_words - 1, 4, 0, true, state_words));
        std.debug.print("BLAKE3_STAGED columns={d} stages={d} state_words={d}\n", .{ width, stage, state_words });
    }
}
