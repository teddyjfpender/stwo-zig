//! Bounded CPU quotient scratch: n values per column and n extra values only
//! for columns sampled at the preceding trace row. Four disjoint n-point
//! conjugate cosets cover the canonical 4n quotient domain exactly.
//!
//! A trace predecessor crosses to the paired coset: it does not stay in one
//! n-point circle domain. Its exact position is obtained from the core index
//! authority. Source coefficients are borrowed; evaluation scratch is reusable.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Poly = engine.air.component_prover.Poly;
const CircleDomain = core.poly.circle.domain.CircleDomain;
const partition = engine.poly.circle.coset_partition;
const work = engine.work_pool;
pub const PARTS = 4;
const MIN_FFT_CELLS_PER_WORKER = 8192;

pub const Evaluation = struct {
    allocator: std.mem.Allocator,
    sources: []const Poly,
    previous_columns: []const bool,
    trace_log: u32,
    size: usize,
    current_values: [][]const M,
    previous_values: [][]const M,
    buffers: [][]M,
    scratch: []M,

    /// Allocates n*(columns + previous columns) M31 values once. Metadata and
    /// coefficient sources remain borrowed until deinit. Missing coefficients
    /// fail closed; this operation never interpolates or silently allocates 4n.
    pub fn init(a: std.mem.Allocator, polys: []const Poly, trace_log: u32, previous_columns: []const bool) !Evaluation {
        if (trace_log < 2 or trace_log > 26 or polys.len == 0 or previous_columns.len != polys.len) return error.InvalidRv64CosetGeometry;
        const size = @as(usize, 1) << @intCast(trace_log);
        var previous_count: usize = 0;
        for (polys, previous_columns) |poly, previous| {
            try poly.validate();
            const coefficients = poly.coefficients orelse return error.MissingRv64CosetCoefficients;
            if (coefficients.logSize() > trace_log or coefficients.coefficients().len > size) return error.InvalidRv64CosetGeometry;
            previous_count += @intFromBool(previous);
        }
        const count = std.math.add(usize, polys.len, previous_count) catch return error.InvalidRv64CosetGeometry;
        const cells = std.math.mul(usize, count, size) catch return error.InvalidRv64CosetGeometry;
        const current = try a.alloc([]const M, polys.len);
        errdefer a.free(current);
        const previous = try a.alloc([]const M, polys.len);
        errdefer a.free(previous);
        const buffers = try a.alloc([]M, count);
        errdefer a.free(buffers);
        const scratch = try a.alloc(M, cells);
        errdefer a.free(scratch);
        for (buffers, 0..) |*buffer, i| buffer.* = scratch[i * size ..][0..size];
        var cursor = polys.len;
        for (current, previous, previous_columns, 0..) |*cur, *prior, needs_previous, i| {
            cur.* = buffers[i];
            prior.* = if (needs_previous) buffers[cursor] else &.{};
            cursor += @intFromBool(needs_previous);
        }
        return .{ .allocator = a, .sources = polys, .previous_columns = previous_columns, .trace_log = trace_log, .size = size, .current_values = current, .previous_values = previous, .buffers = buffers, .scratch = scratch };
    }
    pub fn deinit(self: *Evaluation) void {
        self.allocator.free(self.current_values);
        self.allocator.free(self.previous_values);
        self.allocator.free(self.buffers);
        self.allocator.free(self.scratch);
        self.* = undefined;
    }
    pub fn domain(self: *const Evaluation, part: usize) !CircleDomain {
        return partition.domain(core.poly.circle.canonic.CanonicCoset.new(self.trace_log + 2).circleDomain(), 2, part);
    }
    /// Replaces all current/previous views. No field-value allocation occurs;
    /// each FFT owns only its n-point twiddle tree during that batch.
    pub fn evaluatePart(self: *Evaluation, part: usize) !void {
        return self.evaluatePartWithPool(part, null);
    }
    pub fn evaluatePartWithPool(self: *Evaluation, part: usize, pool: ?*work.WorkPool) !void {
        const current_domain = try self.domain(part);
        for (self.sources, self.buffers[0..self.sources.len]) |poly, buffer| copyCoefficients(poly, buffer);
        try self.transform(self.buffers[0..self.sources.len], current_domain, pool);
        if (self.buffers.len == self.sources.len) return;
        var cursor = self.sources.len;
        for (self.sources, self.previous_columns) |poly, previous| {
            if (!previous) continue;
            copyCoefficients(poly, self.buffers[cursor]);
            cursor += 1;
        }
        try self.transform(self.buffers[self.sources.len..], try self.domain(part ^ 1), pool);
    }
    pub fn globalRow(self: *const Evaluation, part: usize, row: usize) usize {
        std.debug.assert(part < PARTS and row < self.size);
        return part * self.size + row;
    }
    pub fn previousRow(self: *const Evaluation, part: usize, row: usize) usize {
        const previous = core.utils.previousBitReversedCircleDomainIndex(self.globalRow(part, row), self.trace_log, self.trace_log + 2);
        // The quotient domain's natural half-coset predecessor shifts by two.
        // In four-way bit-reversed partition order this changes part xor 1.
        std.debug.assert(previous / self.size == part ^ 1);
        return previous % self.size;
    }
    pub fn denominatorInverse(self: *const Evaluation, part: usize) !M {
        return (try core.constraints.cosetVanishing(M, core.poly.circle.canonic.CanonicCoset.new(self.trace_log).coset(), (try self.domain(part)).at(0)).inv());
    }
    fn transform(self: *Evaluation, buffers: [][]M, target: CircleDomain, pool: ?*work.WorkPool) !void {
        var twiddles = try engine.poly.twiddles.precomputeM31(self.allocator, target.half_coset);
        defer engine.poly.twiddles.deinitM31(self.allocator, &twiddles);
        const tree = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
        const workers = if (pool) |active| @min(active.workerCount(), @min(buffers.len, @max(1, buffers.len * self.size / MIN_FFT_CELLS_PER_WORKER))) else 1;
        if (workers <= 1) return engine.poly.circle.poly.evaluateBuffersWithTwiddles(buffers, target, tree);
        var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
        defer lease.deinit();
        var jobs: [work.MAX_WORKERS]TransformJob = undefined;
        for (jobs[0..workers], 0..) |*job, i| job.* = .{ .buffers = buffers[buffers.len * i / workers .. buffers.len * (i + 1) / workers], .target = target, .twiddles = tree };
        {
            var group = std.Thread.WaitGroup{};
            defer {
                group.wait();
                lease.completeWave();
            }
            for (jobs[1..workers]) |*job| try lease.spawnWg(&group, TransformJob.run, .{job});
            jobs[0].run();
        }
        for (jobs[0..workers]) |job| if (job.failure) |failure| return failure;
    }
};
fn copyCoefficients(poly: Poly, buffer: []M) void {
    const source = poly.coefficients.?.coefficients();
    @memcpy(buffer[0..source.len], source);
    @memset(buffer[source.len..], M.zero());
}

const TransformJob = struct {
    buffers: [][]M,
    target: CircleDomain,
    twiddles: engine.poly.twiddles.TwiddleTree([]const M),
    failure: ?anyerror = null,
    fn run(self: *TransformJob) void {
        engine.poly.circle.poly.evaluateBuffersWithTwiddles(self.buffers, self.target, self.twiddles) catch |err| {
            self.failure = err;
        };
    }
};
