//! Ownership regression against the actual circle-domain permutation.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("stwo_riscv_frontend").rv64_air.providers.prefix_waves;

fn physical(logical: usize, log: u32) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log), log);
}

test "native prefix groups partition segments and own complete relative128 byte blocks" {
    const a = std.testing.allocator;
    var cases: usize = 0;
    for ([_]u32{ 10, 12 }) |max_log| {
        const min_log = max_log - P.GROUP_LOG_ROWS;
        for (5..24) |log_usize| {
            const log: u32 = @intCast(log_usize);
            for ([_]usize{ 1, 2, 3, 5, 8, 16, 32 }) |workers| {
                const segment_log = P.lineSegmentLog(log, max_log, min_log, workers) orelse continue;
                const size = @as(usize, 1) << @intCast(segment_log);
                const groups = P.lineGroupCount(log, segment_log);
                const segments = @as(usize, 1) << @intCast(log - segment_log);
                const seen = try a.alloc(bool, segments);
                defer a.free(seen);
                @memset(seen, false);
                const owners = try a.alloc(usize, (@as(usize, 1) << @intCast(log)) / P.GROUP_ROWS);
                defer a.free(owners);
                @memset(owners, std.math.maxInt(usize));
                try std.testing.expect(size >= @as(usize, 1) << @intCast(min_log));
                try std.testing.expectEqual(@as(usize, 0), size % (@as(usize, 1) << @intCast(min_log)));
                for (0..groups) |g| {
                    const ss = P.lineGroupSegments(log, segment_log, g);
                    for (ss) |s| {
                        try std.testing.expect(s < segments);
                        try std.testing.expect(!seen[s]);
                        seen[s] = true;
                    }
                    // Whole rows for small domains; 32 reproducible offsets
                    // plus endpoints for large domains avoid a huge fixture.
                    const samples = if (log <= 14) size else 34;
                    for (0..samples) |sample| {
                        const r = if (log <= 14) sample else if (sample == 0) 0 else if (sample == 1) size - 1 else (sample *% 0x9e3779b97f4a7c15) % size;
                        var lanes: [P.GROUP_ROWS]bool = @splat(false);
                        var block: ?usize = null;
                        for (ss, 0..) |s, t| {
                            const paired = if (t < P.GROUP_ROWS / 2) r else size - 1 - r;
                            const pos = physical(s * size + paired, log);
                            const current = pos / P.GROUP_ROWS;
                            if (block) |b| try std.testing.expectEqual(b, current) else block = current;
                            try std.testing.expect(!lanes[pos % P.GROUP_ROWS]);
                            lanes[pos % P.GROUP_ROWS] = true;
                            if (owners[current] != std.math.maxInt(usize)) try std.testing.expectEqual(g, owners[current]);
                            owners[current] = g;
                        }
                        for (lanes) |present| try std.testing.expect(present);
                    }
                }
                for (seen) |present| try std.testing.expect(present);
                cases += 1;
            }
        }
    }
    try std.testing.expect(cases > 100);
}
