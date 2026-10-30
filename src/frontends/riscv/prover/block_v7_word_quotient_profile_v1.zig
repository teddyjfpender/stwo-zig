//! Optional phase attribution for the canonical coefficient-to-coset tiles.
//! CPU times sum disjoint worker job clocks; load/row times are wall time.
const std = @import("std");
const Blocks = @import("stwo_prover_engine").poly.circle.coset_blocks;
pub const Load = struct {
    prepare_ns: u64 = 0,
    jobs_ns: u64 = 0,
    block_fold_cpu_ns: u64 = 0,
    block_fft_cpu_ns: u64 = 0,
    group_changes: u64 = 0,
    prefold_elements_read: u64 = 0,
    block_elements_read: u64 = 0,
    fft_elements: u64 = 0,
    jobs: u64 = 0,
};
pub const Stats = struct {
    recovery_ns: u64 = 0,
    mapping_ns: u64 = 0,
    rows_ns: u64 = 0,
    current: Load = .{},
    previous: Load = .{},
    group_logs: [3]u32 = @splat(0),
};
const MeasuredJob = struct {
    job: Blocks.BlockJob,
    timing: Blocks.BlockJob.Timing = .{},
    pub fn run(self: *@This()) void {
        self.job.runProfiled(&self.timing);
    }
};
pub fn load(tiles: *Blocks.Tiles, tile: usize, stats: *Load) !void {
    var clock = try std.time.Timer.start();
    const group = tile >> @intCast(tiles.group_log);
    if (tiles.group_log != 0 and tiles.loaded_group != group) {
        stats.group_changes += 1;
        for (tiles.sources, tiles.group_offsets) |source, offset| if (offset != Blocks.Tiles.ungrouped) {
            stats.prefold_elements_read += source.coefficients.len;
        };
    }
    var shapes = Blocks.Shapes.init(tiles.allocator);
    defer shapes.deinit();
    var jobs: std.ArrayList(Blocks.BlockJob) = .empty;
    defer jobs.deinit(tiles.allocator);
    try tiles.prepare(&shapes, tile, &jobs);
    stats.prepare_ns += clock.lap();
    const measured = try tiles.allocator.alloc(MeasuredJob, jobs.items.len);
    defer tiles.allocator.free(measured);
    for (measured, jobs.items) |*out, job| {
        out.* = .{ .job = job };
        stats.block_elements_read += job.coefficients.len;
        stats.fft_elements += job.values.len;
    }
    Blocks.runJobs(MeasuredJob, measured);
    stats.jobs_ns += clock.lap();
    stats.jobs += measured.len;
    for (measured) |job| {
        if (job.job.failure) |err| return err;
        stats.block_fold_cpu_ns += job.timing.fold_ns;
        stats.block_fft_cpu_ns += job.timing.fft_ns;
    }
}
