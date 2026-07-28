//! Parallel replication of the streaming committer's hasher-state array.
//!
//! The streaming committer keeps one hasher state per leaf and climbs the
//! column log-size ladder: when a group arrives at a larger domain, the whole
//! array is replicated onto that domain before the group is absorbed. For a
//! `2^22` leaf domain a 136-byte BLAKE2s state is 570 MiB, so a single
//! replication moves 855 MiB (285 read, 570 written) and performs no hashing
//! at all.
//!
//! Two properties make that pass much cheaper than a scalar gather.
//!
//! First, the lifting map `dst[i] = src[((i >> shift) << 1) + (i & 1)]` is
//! constant across each aligned run of `1 << shift` destinations: the whole
//! run alternates between exactly two source hashers. Reading them once per
//! run turns a strided gather over a multi-hundred-MiB array into a streaming
//! write from two registers.
//!
//! Second, the runs are independent and cover disjoint destination ranges, so
//! the pass splits across the shared work pool — which is what the rest of the
//! leaf pipeline (absorb, finalize, parent layers) already does.
//!
//! Output is bit-identical to the scalar gather: this is pure replication, no
//! value is computed and no absorbed byte moves.

const std = @import("std");
const work_pool_mod = @import("../work_pool.zig");
const parameters = @import("parameters.zig");

pub fn Operations(comptime H: type) type {
    return struct {
        const WaitGroup = std.Thread.WaitGroup;
        const parallel_min_nodes_per_worker = parameters.parallel_min_nodes_per_worker;
        const max_parallel_workers = parameters.max_parallel_workers;

        const ExpandRangeCtx = struct {
            src: []const H,
            dst: []H,
            shift: std.math.Log2Int(usize),
            start: usize,
            end: usize,
        };

        fn expandRange(ctx: *const ExpandRangeCtx) void {
            var idx = ctx.start;
            while (idx < ctx.end) {
                const run = idx >> ctx.shift;
                const even = ctx.src[2 * run];
                const odd = ctx.src[2 * run + 1];
                const run_end = @min(ctx.end, (run + 1) << ctx.shift);
                var at = idx;
                while (at < run_end) : (at += 1) {
                    ctx.dst[at] = if ((at & 1) == 0) even else odd;
                }
                idx = run_end;
            }
        }

        /// Replicates `src` onto the larger destination domain `dst`.
        ///
        /// Preconditions, established structurally by the caller's log-size
        /// ladder: `shift >= 1`, `dst.len == src.len << (shift - 1)`, and
        /// `dst.len` is a power of two. Every destination index is written
        /// exactly once, by exactly one worker.
        pub fn expandHashers(
            dst: []H,
            src: []const H,
            shift: std.math.Log2Int(usize),
        ) void {
            std.debug.assert(shift >= 1);
            std.debug.assert(dst.len == src.len << @intCast(shift - 1));

            const pool = work_pool_mod.getGlobalPool();
            const worker_capacity = dst.len / parallel_min_nodes_per_worker;
            const worker_count = if (pool) |active_pool|
                @max(@as(usize, 1), @min(active_pool.workerCount(), worker_capacity))
            else
                1;

            if (worker_count <= 1) {
                const ctx: ExpandRangeCtx = .{
                    .src = src,
                    .dst = dst,
                    .shift = shift,
                    .start = 0,
                    .end = dst.len,
                };
                expandRange(&ctx);
                return;
            }

            var contexts: [max_parallel_workers]ExpandRangeCtx = undefined;
            for (0..worker_count) |worker| {
                contexts[worker] = .{
                    .src = src,
                    .dst = dst,
                    .shift = shift,
                    .start = dst.len * worker / worker_count,
                    .end = dst.len * (worker + 1) / worker_count,
                };
            }
            var wait_group: WaitGroup = .{};
            for (contexts[1..worker_count]) |*ctx| {
                pool.?.spawnWg(&wait_group, expandRange, .{@as(*const ExpandRangeCtx, ctx)});
            }
            expandRange(&contexts[0]);
            wait_group.wait();
        }
    };
}

test "run-broadcast replication equals the scalar lifting gather" {
    const Ops = Operations(u64);
    var src_buf: [64]u64 = undefined;
    var dst_buf: [4096]u64 = undefined;
    var expected: [4096]u64 = undefined;

    for (&src_buf, 0..) |*value, index| value.* = @as(u64, index) * 0x9e3779b97f4a7c15;

    var log_src: std.math.Log2Int(usize) = 1;
    while (log_src <= 6) : (log_src += 1) {
        const src_len = @as(usize, 1) << log_src;
        var shift: std.math.Log2Int(usize) = 1;
        while (shift <= 6) : (shift += 1) {
            const dst_len = src_len << @intCast(shift - 1);
            if (dst_len > dst_buf.len) continue;
            const src = src_buf[0..src_len];
            const dst = dst_buf[0..dst_len];

            for (0..dst_len) |idx| {
                expected[idx] = src[((idx >> shift) << 1) + (idx & 1)];
            }
            @memset(dst, 0);
            Ops.expandHashers(dst, src, shift);
            try std.testing.expectEqualSlices(u64, expected[0..dst_len], dst);
        }
    }
}
