//! Fused finalization of the trailing Merkle leaf group.
//!
//! The streaming committer builds leaf hashes by keeping one hasher state per
//! leaf and replicating that array upward as larger column groups arrive. At
//! the largest domain the array dominates the commitment: for `2^22` leaves a
//! 136-byte BLAKE2s state is 570 MiB, written by the replication, read and
//! written by the absorb, and read once more by finalization.
//!
//! This module removes that materialization for the trailing group and makes
//! the replications that remain parallel streaming writes.

const std = @import("std");
const work_pool_mod = @import("../work_pool.zig");
const columns_mod = @import("columns.zig");
const parameters = @import("parameters.zig");
const blake2_stream4 = @import("blake2_stream4.zig");
const audit = @import("audit.zig");

pub fn Operations(comptime H: type) type {
    return struct {
        const ColumnRef = columns_mod.ColumnRef;
        const WaitGroup = std.Thread.WaitGroup;
        const parallel_min_nodes_per_worker = parameters.parallel_min_nodes_per_worker;
        const max_parallel_workers = parameters.max_parallel_workers;

        /// Replicates a hasher layer onto a larger leaf domain.
        ///
        /// The lifting map `dst[i] = src[((i >> shift) << 1) + (i & 1)]` is
        /// constant across each aligned run of `1 << shift` destinations: that
        /// whole run alternates between exactly two source hashers. Reading
        /// them once per run turns a strided gather over a multi-hundred-MiB
        /// array into a streaming write from two registers, and the runs are
        /// independent, so the pass parallelises over the destination range.
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

        pub fn expandHashers(
            dst: []H,
            src: []const H,
            shift: std.math.Log2Int(usize),
        ) void {
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

        /// Fused finalization for a trailing column group that already lives
        /// at the final leaf domain.
        ///
        /// The predecessor shape materialized the expanded hasher array for
        /// the final domain (one `H` per leaf), absorbed the group into it,
        /// and finalized it in a third pass. Every hasher in that array is
        /// written once, read once by the absorb pass, written again, and
        /// read a third time by finalization — for a `2^22` domain with a
        /// 136-byte `H` that is 570 MiB touched four times to produce a
        /// 134 MiB digest layer.
        ///
        /// The expanded array carries no information the base array does not
        /// already hold: `expanded[idx] = base[((idx >> shift) << 1) + (idx & 1)]`
        /// is a pure replication. So the absorb and the finalization can read
        /// the base state directly, keep the working hasher in registers, and
        /// emit the digest — one pass, no expanded array, and byte-identical
        /// output because the absorbed values and their order are unchanged.
        ///
        /// Unlike `finalizeLiftedTail`, the group may be arbitrarily wide: the
        /// four-lane continuation compresses whole blocks as they fill instead
        /// of requiring the tail to land in the already-open terminal block.
        const DirectTailRangeCtx = struct {
            base_hashers: []const H,
            base_shift: std.math.Log2Int(usize),
            tail_columns: []const ColumnRef,
            out: []H.Hash,
            start: usize,
            end: usize,
        };

        fn directTailBaseIndex(ctx: *const DirectTailRangeCtx, position: usize) usize {
            return ((position >> ctx.base_shift) << 1) + (position & 1);
        }

        fn finalizeDirectTailOne(ctx: *const DirectTailRangeCtx, position: usize) void {
            var hasher = ctx.base_hashers[directTailBaseIndex(ctx, position)];
            for (ctx.tail_columns) |column| {
                hasher.updateLeaf(column.values[position .. position + 1]);
            }
            ctx.out[position] = hasher.finalize();
        }

        fn finalizeDirectTailRange(ctx: *const DirectTailRangeCtx) void {
            var position = ctx.start;

            if (comptime blake2_stream4.supports(H)) {
                while (position < ctx.end and (position & 3) != 0) : (position += 1) {
                    finalizeDirectTailOne(ctx, position);
                }
                while (position + 4 <= ctx.end) : (position += 4) {
                    var hashers: [4]H = undefined;
                    inline for (0..4) |lane| {
                        hashers[lane] = ctx.base_hashers[directTailBaseIndex(ctx, position + lane)];
                    }
                    const hashes = blake2_stream4.finalizeM31Columns4(
                        &hashers,
                        ctx.tail_columns,
                        position,
                    );
                    inline for (0..4) |lane| ctx.out[position + lane] = hashes[lane];
                }
            }

            while (position < ctx.end) : (position += 1) {
                finalizeDirectTailOne(ctx, position);
            }
        }

        /// Finalizes the leaf layer by fusing the trailing same-log-size group
        /// into the finalization pass.
        ///
        /// Preconditions (the caller establishes them structurally):
        /// - every column in `tail_columns` has `log_size == final_log_size`;
        /// - `final_log_size > base_log_size`;
        /// - every hasher in `base_hashers` has absorbed the same byte count,
        ///   which the group-at-a-time absorb guarantees.
        pub fn finalizeDirectTail(
            base_hashers: []const H,
            base_log_size: u32,
            tail_columns: []const ColumnRef,
            final_log_size: u32,
            out: []H.Hash,
        ) void {
            std.debug.assert(tail_columns.len > 0);
            std.debug.assert(final_log_size > base_log_size);
            std.debug.assert(out.len == @as(usize, 1) << @intCast(final_log_size));
            std.debug.assert(base_hashers.len == @as(usize, 1) << @intCast(base_log_size));

            const base_shift: std.math.Log2Int(usize) = @intCast(
                final_log_size - base_log_size + 1,
            );

            const pool = work_pool_mod.getGlobalPool();
            const worker_capacity = out.len / parallel_min_nodes_per_worker;
            const worker_count = if (pool) |active_pool|
                @max(@as(usize, 1), @min(active_pool.workerCount(), worker_capacity))
            else
                1;

            var contexts: [max_parallel_workers]DirectTailRangeCtx = undefined;
            // Four-aligned boundaries keep every worker on the four-lane path.
            for (0..worker_count) |worker| {
                const start = (out.len * worker / worker_count) & ~@as(usize, 3);
                const end = if (worker + 1 == worker_count)
                    out.len
                else
                    (out.len * (worker + 1) / worker_count) & ~@as(usize, 3);
                contexts[worker] = .{
                    .base_hashers = base_hashers,
                    .base_shift = base_shift,
                    .tail_columns = tail_columns,
                    .out = out,
                    .start = start,
                    .end = end,
                };
            }

            audit.note("direct_tail_workers pool={any} workers={d} cap={d}", .{ pool != null, worker_count, worker_capacity });
            if (worker_count > 1) {
                var wait_group: WaitGroup = .{};
                for (contexts[1..worker_count]) |*ctx| {
                    pool.?.spawnWg(&wait_group, finalizeDirectTailRange, .{
                        @as(*const DirectTailRangeCtx, ctx),
                    });
                }
                finalizeDirectTailRange(&contexts[0]);
                wait_group.wait();
            } else {
                finalizeDirectTailRange(&contexts[0]);
            }
        }
    };
}
