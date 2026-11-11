//! Bounded two-wave final LogUp prefix in the existing physical column layout.
//! No whole-column permutation buffers are retained: each logical chunk owns
//! its local prefix, then a physical-order pass adds its exclusive chunk sum.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Col = @import("../pcs/mod.zig").ColumnEvaluation;
const work = @import("../work_pool.zig");
const CHUNK: usize = 4096;

/// Returns false without mutation when the caller should use its serial path.
/// Allocation failure also leaves the columns unchanged.
pub fn tryParallel(a: std.mem.Allocator, columns: []const Col, shift: []const M) !bool {
    const pool = work.getGlobalPool() orelse return false;
    if (columns.len != shift.len or columns.len == 0 or columns.len > 8)
        return error.InvalidLogupPrefixWidth;
    const n = columns[0].values.len;
    if (n < 2 * CHUNK or pool.workerCount() < 2) return false;
    if (!std.math.isPowerOfTwo(n)) return error.InvalidLogupPrefixLength;
    for (columns) |column| if (column.values.len != n) return error.InvalidLogupPrefixLength;
    const chunks = n / CHUNK;
    const workers = @min(pool.workerCount(), chunks);
    const summaries = try a.alloc(M, chunks * columns.len);
    defer a.free(summaries);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{
        .columns = columns,
        .shift = shift,
        .summaries = summaries,
        .log = @intCast(std.math.log2_int(usize, n)),
        .worker = i,
        .workers = workers,
    };
    run(pool, jobs[0..workers]);
    var totals: [8]M = @splat(M.zero());
    for (0..chunks) |chunk| {
        for (0..columns.len) |c| {
            const at = chunk * columns.len + c;
            const local = summaries[at];
            summaries[at] = totals[c];
            totals[c] = totals[c].add(local);
        }
    }
    for (jobs[0..workers]) |*job| job.correct = true;
    run(pool, jobs[0..workers]);
    return true;
}

fn run(pool: *work.WorkPool, jobs: []Job) void {
    var group = std.Thread.WaitGroup{};
    for (jobs[1..]) |*job| pool.spawnWg(&group, Job.run, .{job});
    Job.run(&jobs[0]);
    group.wait();
}

const Job = struct {
    columns: []const Col,
    shift: []const M,
    summaries: []M,
    log: u32,
    worker: usize,
    workers: usize,
    correct: bool = false,

    fn run(self: *Job) void {
        const n = self.columns[0].values.len;
        if (self.correct) {
            // Contiguous physical writes avoid repeating the random logical
            // traversal when applying offsets. Every physical row has one owner.
            const begin = n * self.worker / self.workers;
            const end = n * (self.worker + 1) / self.workers;
            for (begin..end) |p| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, self.log), self.log);
                const base = (logical / CHUNK) * self.columns.len;
                for (self.columns, 0..) |column, c| {
                    const values = @constCast(column.values);
                    values[p] = values[p].add(self.summaries[base + c]);
                }
            }
            return;
        }
        var chunk = self.worker;
        while (chunk < n / CHUNK) : (chunk += self.workers) {
            var sum: [8]M = @splat(M.zero());
            const begin = chunk * CHUNK;
            for (begin..begin + CHUNK) |logical| {
                const p = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, self.log), self.log);
                for (self.columns, self.shift, 0..) |column, shift, c| {
                    const values = @constCast(column.values);
                    sum[c] = sum[c].add(values[p].sub(shift));
                    values[p] = sum[c];
                }
            }
            @memcpy(self.summaries[chunk * self.columns.len ..][0..self.columns.len], sum[0..self.columns.len]);
        }
    }
};

test "two-wave LogUp prefix preserves shifted coset order and fails before mutation" {
    const a = std.testing.allocator;
    for ([_]usize{ 4, 8 }) |width| for ([_]u32{ 13, 15 }) |log| {
        const n = @as(usize, 1) << @intCast(log);
        var source: [8]Col = undefined;
        var expected: [8][]M = undefined;
        var shift: [8]M = undefined;
        var ready: usize = 0;
        defer for (0..ready) |c| {
            a.free(source[c].values);
            a.free(expected[c]);
        };
        for (0..width) |c| {
            const input = try a.alloc(M, n);
            errdefer a.free(input);
            for (input, 0..) |*v, p| v.* = M.fromU64(p * (c + 31) + (p % 13) * 991 + c);
            source[c] = .{ .log_size = log, .values = input };
            expected[c] = try a.dupe(M, input);
            ready += 1;
            shift[c] = M.fromU64(71 * (c + 1));
            // Independent retained algorithm: physical -> circle -> coset,
            // serial prefix, inverse permutations. No new index arithmetic.
            for (expected[c]) |*v| v.* = v.sub(shift[c]);
            core.utils.bitReverse(M, expected[c]);
            const coset = try core.utils.circleDomainOrderToCosetOrder(M, a, expected[c]);
            defer a.free(coset);
            var sum = M.zero();
            for (coset) |*v| {
                sum = sum.add(v.*);
                v.* = sum;
            }
            const circle = try core.utils.cosetOrderToCircleDomainOrder(M, a, coset);
            defer a.free(circle);
            core.utils.bitReverse(M, circle);
            @memcpy(expected[c], circle);
        }
        for ([_]usize{ 2, 3, 5 }) |workers| {
            var pool: work.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = workers });
            defer pool.deinit();
            var binding = try work.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
            try std.testing.expectError(error.OutOfMemory, tryParallel(failing.allocator(), source[0..width], shift[0..width]));
            for (source[0..width], 0..) |column, c| for (column.values, 0..) |v, p|
                try std.testing.expectEqual(M.fromU64(p * (c + 31) + (p % 13) * 991 + c), v);
            try std.testing.expect(try tryParallel(a, source[0..width], shift[0..width]));
            for (source[0..width], 0..) |column, c| {
                try std.testing.expectEqualSlices(M, expected[c], column.values);
                for (@constCast(column.values), 0..) |*v, p| v.* = M.fromU64(p * (c + 31) + (p % 13) * 991 + c);
            }
        }
    };
}
