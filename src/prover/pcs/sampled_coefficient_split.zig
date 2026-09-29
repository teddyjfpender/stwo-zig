//! Bound sampled basis storage by factoring low and high coefficient indices.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const width = core.fields.m31.PACK_WIDTH;
const polynomial = @import("../poly/circle/mod.zig");
const points = @import("../poly/circle/point_evaluation.zig");
const pools = @import("../work_pool.zig");

/// This threshold retains the existing small-plan schedule. A split basis at
/// log 24 uses 272 KiB per point instead of a 256 MiB full product basis.
pub const low_log_limit: usize = 10;
pub const minimum_log: u32 = 12;

pub fn evaluate(coefficients: []const polynomial.CircleCoefficients, factors: []const QM31, out: []const []QM31, allow_parallel: bool) bool {
    if (coefficients.len == 0 or coefficients.len != out.len) return false;
    const log = coefficients[0].log_size;
    if (log < minimum_log or log >= @bitSizeOf(usize)) return false;
    const rows = @as(usize, 1) << @intCast(log);
    const point_count = out[0].len;
    if (point_count == 0 or factors.len != std.math.mul(usize, point_count, log) catch return false) return false;
    for (coefficients, out) |column, output| {
        if (column.log_size != log or column.coeffs.len != rows or output.len != point_count) return false;
    }
    const low_log = @min(@as(usize, log), low_log_limit);
    const low_rows = @as(usize, 1) << @intCast(low_log);
    const high_rows = rows / low_rows;
    const scratch = std.heap.page_allocator.alloc(QM31, low_rows + high_rows) catch return false;
    defer std.heap.page_allocator.free(scratch);
    const low = scratch[0..low_rows];
    const high = scratch[low_rows..];
    const pool = if (allow_parallel) pools.getGlobalPool() else null;
    const worker_count = if (pool) |ready| @max(@as(usize, 1), @min(ready.workerCount(), coefficients.len / @max(@as(usize, 4), width))) else 1;
    var work: [pools.MAX_WORKERS]Work = undefined;
    for (0..point_count) |point_index| {
        const point_factors = factors[point_index * log ..][0..log];
        points.fillSubsetProductBasis(point_factors[0..low_log], low);
        points.fillSubsetProductBasis(point_factors[low_log..], high);
        var cursor = std.atomic.Value(usize).init(0);
        for (work[0..worker_count]) |*worker| worker.* = .{
            .coefficients = coefficients,
            .out = out,
            .low = low,
            .high = high,
            .point = point_index,
            .cursor = &cursor,
        };
        var wait: std.Thread.WaitGroup = .{};
        for (work[1..worker_count]) |*worker| pool.?.spawnWg(&wait, Work.run, .{@as(*const Work, worker)});
        work[0].run();
        wait.wait();
    }
    return true;
}

const Work = struct {
    coefficients: []const polynomial.CircleCoefficients,
    out: []const []QM31,
    low: []const QM31,
    high: []const QM31,
    point: usize,
    cursor: *std.atomic.Value(usize),

    pub fn run(self: *const Work) void {
        while (true) {
            const start = self.cursor.fetchAdd(width, .monotonic);
            if (start >= self.coefficients.len) return;
            const end = @min(start + width, self.coefficients.len);
            if (end - start == width) {
                var batch: [width][]const M31 = undefined;
                for (&batch, self.coefficients[start..end]) |*column, coefficients| column.* = coefficients.coeffs;
                const values = points.evalBatchWithSplitProductBasis(batch, self.low, self.high);
                for (values, self.out[start..end]) |value, output| output[self.point] = value;
            } else {
                for (self.coefficients[start..end], self.out[start..end]) |coefficients, output|
                    output[self.point] = points.evalWithSplitProductBasis(coefficients.coeffs, self.low, self.high);
            }
        }
    }
};

test "sampled split bases match independent polynomial evaluation with ragged column batches" {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0x96202665);
    const random = rng.random();
    for ([_]u32{ 12, 14 }) |log| {
        const rows = @as(usize, 1) << @intCast(log);
        const storage = try allocator.alloc(M31, rows * 11);
        defer allocator.free(storage);
        for (storage) |*value| value.* = M31.fromCanonical(random.uintLessThan(u32, core.fields.m31.Modulus));
        var factors: [28]QM31 = undefined;
        for (factors[0 .. 2 * log]) |*factor| factor.* = QM31.fromU32Unchecked(
            random.uintLessThan(u32, core.fields.m31.Modulus),
            random.uintLessThan(u32, core.fields.m31.Modulus),
            random.uintLessThan(u32, core.fields.m31.Modulus),
            random.uintLessThan(u32, core.fields.m31.Modulus),
        );
        var coefficients: [11]polynomial.CircleCoefficients = undefined;
        var values: [11][2]QM31 = undefined;
        var outputs: [11][]QM31 = undefined;
        for (&coefficients, &outputs, 0..) |*column, *output, index| {
            column.* = try polynomial.CircleCoefficients.initBorrowed(storage[index * rows ..][0..rows]);
            output.* = &values[index];
        }
        for ([_]usize{ 1, 2, 7 }) |workers| {
            var pool: pools.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = workers });
            defer pool.deinit();
            var binding = try pools.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            for ([_]usize{ 1, 2, 3, 4, 7, 11 }) |count| {
                try std.testing.expect(evaluate(coefficients[0..count], factors[0 .. 2 * log], outputs[0..count], true));
                for (coefficients[0..count], values[0..count]) |column, actual| {
                    for (actual, 0..) |value, point_index|
                        try std.testing.expect(value.eql(column.evalAtPointWithFactors(factors[point_index * log ..][0..log])));
                }
            }
        }
    }
}
