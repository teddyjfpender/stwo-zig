//! Owned quotient-domain views for prepared RISC-V AIR evaluators.
//!
//! A committed polynomial is normally retained on the PCS LDE domain.  That
//! domain happens to equal the degree-one quotient domain in the frozen V1
//! profile, but it is not an AIR invariant.  Higher PCS blowup factors retain
//! a wider LDE while the quotient still needs only `trace_log + 1` points.
//!
//! `Owner` preserves the zero-copy V1 fast path and evaluates retained
//! coefficients only for sources whose committed domain differs.  Its buffers
//! are prepared once, before task publication, and remain immutable while
//! parallel row evaluators borrow them.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const core_utils = @import("stwo_core").utils;
const M31 = @import("stwo_core").fields.m31.M31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const work_pool = @import("stwo_prover_engine").work_pool;

pub const Error = error{
    InvalidProofShape,
    ResourceReservationOverflow,
};

/// How a committed source reaches a wider quotient domain.
///
/// `committed_lde` is the coefficient-retention `.never` path: the PCS LDE is
/// interpolated in place before the buffer is zero-padded and evaluated on the
/// quotient domain.  Equal-domain sources remain borrowed and allocate no
/// storage.
pub const ExtensionSource = enum {
    borrowed,
    retained_coefficients,
    committed_lde,
};

pub const ExtensionCounts = struct {
    owned: usize = 0,
    retained_coefficients: usize = 0,
    committed_lde: usize = 0,

    pub fn add(self: *ExtensionCounts, source: ExtensionSource) Error!void {
        switch (source) {
            .borrowed => {},
            .retained_coefficients => {
                self.owned = std.math.add(usize, self.owned, 1) catch
                    return error.ResourceReservationOverflow;
                self.retained_coefficients = std.math.add(
                    usize,
                    self.retained_coefficients,
                    1,
                ) catch return error.ResourceReservationOverflow;
            },
            .committed_lde => {
                self.owned = std.math.add(usize, self.owned, 1) catch
                    return error.ResourceReservationOverflow;
                self.committed_lde = std.math.add(
                    usize,
                    self.committed_lde,
                    1,
                ) catch return error.ResourceReservationOverflow;
            },
        }
    }

    pub fn validate(self: ExtensionCounts) Error!void {
        const classified = std.math.add(
            usize,
            self.retained_coefficients,
            self.committed_lde,
        ) catch return error.ResourceReservationOverflow;
        if (classified != self.owned) return error.InvalidProofShape;
    }
};

/// Classifies one source without allocating.  Discarded coefficients are
/// admitted only when the committed LDE is at least as wide as the trace and
/// no wider than the requested quotient domain.
pub fn extensionSource(
    poly: prover_component.Poly,
    trace_log_size: u32,
    evaluation_log_size: u32,
) !ExtensionSource {
    try poly.validate();
    if (poly.log_size == evaluation_log_size) return .borrowed;
    if (poly.log_size > evaluation_log_size) return error.InvalidProofShape;
    if (poly.coefficients) |coefficients| {
        if (coefficients.logSize() != trace_log_size)
            return error.InvalidProofShape;
        return .retained_coefficients;
    }
    if (poly.log_size < trace_log_size) return error.InvalidProofShape;
    return .committed_lde;
}

pub fn needsOwned(
    poly: prover_component.Poly,
    trace_log_size: u32,
    evaluation_log_size: u32,
) !bool {
    try validateSource(poly, trace_log_size, evaluation_log_size);
    return poly.log_size != evaluation_log_size;
}

pub const Owner = struct {
    allocator: std.mem.Allocator,
    buffers: [][]M31,
    initialized: usize = 0,

    pub fn init(allocator: std.mem.Allocator, owned_count: usize) !Owner {
        return .{
            .allocator = allocator,
            .buffers = try allocator.alloc([]M31, owned_count),
        };
    }

    pub fn deinit(self: *Owner) void {
        for (self.buffers[0..self.initialized]) |buffer| {
            self.allocator.free(buffer);
        }
        self.allocator.free(self.buffers);
        self.* = undefined;
    }

    /// Returns a stable quotient-domain view.  Equal-domain sources remain
    /// borrowed; mismatched sources are staged as zero-padded coefficients and
    /// evaluated together by `finish`.
    pub fn value(
        self: *Owner,
        poly: prover_component.Poly,
        trace_log_size: u32,
        evaluation_log_size: u32,
        evaluation_size: usize,
    ) ![]const M31 {
        try validateSource(poly, trace_log_size, evaluation_log_size);
        if (poly.log_size == evaluation_log_size) return poly.values;
        if (self.initialized == self.buffers.len)
            return error.InvalidProofShape;

        const coefficients = poly.coefficients.?;
        const source = coefficients.coefficients();
        if (source.len > evaluation_size) return error.InvalidProofShape;
        const buffer = try self.allocator.alloc(M31, evaluation_size);
        errdefer self.allocator.free(buffer);
        @memcpy(buffer[0..source.len], source);
        @memset(buffer[source.len..], M31.zero());
        self.buffers[self.initialized] = buffer;
        self.initialized += 1;
        return buffer;
    }

    /// Converts every staged coefficient buffer to evaluations in one batched
    /// transform setup.  No work or twiddle allocation occurs on the V1 path.
    pub fn finish(self: *Owner, evaluation_domain: anytype) !void {
        if (self.initialized != self.buffers.len)
            return error.InvalidProofShape;
        if (self.buffers.len == 0) return;

        var twiddles = try prover_twiddles.precomputeM31(
            self.allocator,
            evaluation_domain.half_coset,
        );
        defer prover_twiddles.deinitM31(self.allocator, &twiddles);
        try prover_poly.evaluateBuffersWithTwiddles(
            self.buffers,
            evaluation_domain,
            prover_twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            ),
        );
    }
};

/// Quotient-domain owner for a mixed coefficient-retention proof.
///
/// The owner uses one quotient-sized M31 buffer per mismatched source.  A
/// retained coefficient source is copied into the prefix and evaluated.  A
/// coefficient-discarded source first copies its committed LDE into the same
/// prefix, interpolates that prefix in place, then evaluates the zero-padded
/// full buffer.  There is no second M31 scratch buffer and no row-time
/// allocation.
pub const RetainedLdeOwner = struct {
    allocator: std.mem.Allocator,
    buffers: [][]M31,
    retained_extensions: [][]M31,
    interpolation_coefficients: [][]M31,
    interpolation_extensions: [][]M31,
    initialized: usize = 0,
    retained_initialized: usize = 0,
    interpolation_initialized: usize = 0,
    interpolation_log_size: ?u32 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        counts: ExtensionCounts,
    ) !RetainedLdeOwner {
        try counts.validate();
        const buffers = try allocator.alloc([]M31, counts.owned);
        errdefer allocator.free(buffers);
        const retained_extensions = try allocator.alloc(
            []M31,
            counts.retained_coefficients,
        );
        errdefer allocator.free(retained_extensions);
        const interpolation_coefficients = try allocator.alloc(
            []M31,
            counts.committed_lde,
        );
        errdefer allocator.free(interpolation_coefficients);
        const interpolation_extensions = try allocator.alloc(
            []M31,
            counts.committed_lde,
        );
        return .{
            .allocator = allocator,
            .buffers = buffers,
            .retained_extensions = retained_extensions,
            .interpolation_coefficients = interpolation_coefficients,
            .interpolation_extensions = interpolation_extensions,
        };
    }

    pub fn deinit(self: *RetainedLdeOwner) void {
        for (self.buffers[0..self.initialized]) |buffer| {
            self.allocator.free(buffer);
        }
        self.allocator.free(self.interpolation_extensions);
        self.allocator.free(self.interpolation_coefficients);
        self.allocator.free(self.retained_extensions);
        self.allocator.free(self.buffers);
        self.* = undefined;
    }

    pub fn value(
        self: *RetainedLdeOwner,
        poly: prover_component.Poly,
        trace_log_size: u32,
        evaluation_log_size: u32,
        evaluation_size: usize,
    ) ![]const M31 {
        const source = try extensionSource(
            poly,
            trace_log_size,
            evaluation_log_size,
        );
        if (source == .borrowed) return poly.values;
        if (self.initialized == self.buffers.len)
            return error.InvalidProofShape;
        switch (source) {
            .borrowed => unreachable,
            .retained_coefficients => {
                if (self.retained_initialized == self.retained_extensions.len)
                    return error.InvalidProofShape;
            },
            .committed_lde => {
                if (self.interpolation_initialized ==
                    self.interpolation_coefficients.len)
                {
                    return error.InvalidProofShape;
                }
                if (self.interpolation_log_size) |expected| {
                    if (expected != poly.log_size)
                        return error.InvalidProofShape;
                } else {
                    self.interpolation_log_size = poly.log_size;
                }
            },
        }

        const values = try self.allocator.alloc(M31, evaluation_size);
        errdefer self.allocator.free(values);
        const source_values: []const M31 = switch (source) {
            .borrowed => unreachable,
            .retained_coefficients => poly.coefficients.?.coefficients(),
            .committed_lde => poly.values,
        };
        if (source_values.len > values.len) return error.InvalidProofShape;
        @memcpy(values[0..source_values.len], source_values);
        @memset(values[source_values.len..], M31.zero());
        self.buffers[self.initialized] = values;
        self.initialized += 1;
        switch (source) {
            .borrowed => unreachable,
            .retained_coefficients => {
                self.retained_extensions[self.retained_initialized] = values;
                self.retained_initialized += 1;
            },
            .committed_lde => {
                self.interpolation_coefficients[self.interpolation_initialized] =
                    values[0..source_values.len];
                self.interpolation_extensions[self.interpolation_initialized] = values;
                self.interpolation_initialized += 1;
            },
        }
        return values;
    }

    /// Finalizes all staged sources in two bounded batched pipelines.  The
    /// committed-LDE batch interpolates and then evaluates; the retained batch
    /// only evaluates.  Both paths finish with immutable quotient-domain
    /// buffers of identical shape.
    pub fn finish(self: *RetainedLdeOwner, evaluation_domain: anytype) !void {
        if (self.initialized != self.buffers.len or
            self.retained_initialized != self.retained_extensions.len or
            self.interpolation_initialized != self.interpolation_coefficients.len or
            self.interpolation_initialized != self.interpolation_extensions.len)
        {
            return error.InvalidProofShape;
        }
        if (self.buffers.len == 0) return;

        var evaluation_twiddles = try prover_twiddles.precomputeM31(
            self.allocator,
            evaluation_domain.half_coset,
        );
        defer prover_twiddles.deinitM31(self.allocator, &evaluation_twiddles);
        const evaluation_tree = prover_twiddles.TwiddleTree([]const M31).init(
            evaluation_twiddles.root_coset,
            evaluation_twiddles.twiddles,
            evaluation_twiddles.itwiddles,
        );
        if (self.interpolation_extensions.len != 0) {
            const committed_log_size = self.interpolation_log_size orelse
                return error.InvalidProofShape;
            const committed_domain = canonic.CanonicCoset.new(
                committed_log_size,
            ).circleDomain();
            var committed_twiddles = try prover_twiddles.precomputeM31(
                self.allocator,
                committed_domain.half_coset,
            );
            defer prover_twiddles.deinitM31(self.allocator, &committed_twiddles);
            try interpolateAndEvaluateBuffersBounded(
                self.interpolation_coefficients,
                self.interpolation_extensions,
                committed_domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    committed_twiddles.root_coset,
                    committed_twiddles.twiddles,
                    committed_twiddles.itwiddles,
                ),
                evaluation_domain,
                evaluation_tree,
            );
        }
        try evaluateBuffersBounded(
            self.retained_extensions,
            evaluation_domain,
            evaluation_tree,
        );
    }
};

/// Resident bytes added by an owner, excluding allocator metadata.
pub fn residentBytes(owned_count: usize, evaluation_size: usize) Error!usize {
    const views = std.math.mul(usize, owned_count, @sizeOf([]M31)) catch
        return error.ResourceReservationOverflow;
    const values = std.math.mul(usize, owned_count, evaluation_size) catch
        return error.ResourceReservationOverflow;
    const value_bytes = std.math.mul(usize, values, @sizeOf(M31)) catch
        return error.ResourceReservationOverflow;
    return std.math.add(usize, views, value_bytes) catch
        error.ResourceReservationOverflow;
}

/// Resident bytes owned by `RetainedLdeOwner`, excluding allocator metadata.
/// The interpolation and retained view arrays are included; interpolation is
/// in place, so the quotient-sized `buffers` are the only M31 storage.
pub fn retainedLdeResidentBytes(
    counts: ExtensionCounts,
    evaluation_size: usize,
) Error!usize {
    try counts.validate();
    const base = try residentBytes(counts.owned, evaluation_size);
    const interpolation_views = std.math.mul(
        usize,
        counts.committed_lde,
        2,
    ) catch return error.ResourceReservationOverflow;
    const additional_views = std.math.add(
        usize,
        counts.retained_coefficients,
        interpolation_views,
    ) catch return error.ResourceReservationOverflow;
    const additional_bytes = std.math.mul(
        usize,
        additional_views,
        @sizeOf([]M31),
    ) catch return error.ResourceReservationOverflow;
    return std.math.add(usize, base, additional_bytes) catch
        error.ResourceReservationOverflow;
}

/// View metadata beyond the original one-buffer-array reservation.  This lets
/// existing prepared components extend their exact resource calculation
/// without double-counting owned quotient values.
pub fn retainedLdeAdditionalResidentBytes(
    counts: ExtensionCounts,
) Error!usize {
    try counts.validate();
    const interpolation_views = std.math.mul(
        usize,
        counts.committed_lde,
        2,
    ) catch return error.ResourceReservationOverflow;
    const additional_views = std.math.add(
        usize,
        counts.retained_coefficients,
        interpolation_views,
    ) catch return error.ResourceReservationOverflow;
    return std.math.mul(usize, additional_views, @sizeOf([]M31)) catch
        error.ResourceReservationOverflow;
}

const parallel_domain_log_size: u32 = 12;

fn evaluateBuffersBounded(
    buffers: []const []M31,
    domain: anytype,
    twiddles: anytype,
) !void {
    const Job = struct {
        buffers: []const []M31,
        domain: @TypeOf(domain),
        twiddles: @TypeOf(twiddles),
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            prover_poly.evaluateBuffersWithTwiddles(
                self.buffers,
                self.domain,
                self.twiddles,
            ) catch |failure| {
                self.failure = failure;
            };
        }
    };
    return runTransformJobs(Job, buffers, domain, twiddles);
}

fn interpolateAndEvaluateBuffersBounded(
    coefficient_buffers: []const []M31,
    extension_buffers: []const []M31,
    committed_domain: anytype,
    committed_twiddles: anytype,
    evaluation_domain: anytype,
    evaluation_twiddles: anytype,
) !void {
    const Job = struct {
        coefficient_buffers: []const []M31,
        extension_buffers: []const []M31,
        committed_domain: @TypeOf(committed_domain),
        committed_twiddles: @TypeOf(committed_twiddles),
        evaluation_domain: @TypeOf(evaluation_domain),
        evaluation_twiddles: @TypeOf(evaluation_twiddles),
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            prover_poly.interpolateBuffersWithTwiddles(
                self.coefficient_buffers,
                self.committed_domain,
                self.committed_twiddles,
            ) catch |failure| {
                self.failure = failure;
                return;
            };
            prover_poly.evaluateBuffersWithTwiddles(
                self.extension_buffers,
                self.evaluation_domain,
                self.evaluation_twiddles,
            ) catch |failure| {
                self.failure = failure;
            };
        }
    };
    return runPipelineJobs(
        Job,
        coefficient_buffers,
        extension_buffers,
        committed_domain,
        committed_twiddles,
        evaluation_domain,
        evaluation_twiddles,
    );
}

fn runTransformJobs(
    comptime Job: type,
    buffers: []const []M31,
    domain: anytype,
    twiddles: anytype,
) !void {
    if (buffers.len == 0) return;
    if (domain.logSize() < parallel_domain_log_size) {
        var serial = Job{
            .buffers = buffers,
            .domain = domain,
            .twiddles = twiddles,
        };
        serial.run();
        if (serial.failure) |failure| return failure;
        return;
    }
    const pool = work_pool.getGlobalPool() orelse {
        var serial = Job{
            .buffers = buffers,
            .domain = domain,
            .twiddles = twiddles,
        };
        serial.run();
        if (serial.failure) |failure| return failure;
        return;
    };
    const worker_count = @min(pool.workerCount(), buffers.len);
    if (worker_count == 1) {
        var serial = Job{
            .buffers = buffers,
            .domain = domain,
            .twiddles = twiddles,
        };
        serial.run();
        if (serial.failure) |failure| return failure;
        return;
    }

    var lease = try pool.acquire(try work_pool.WorkerBudget.init(worker_count));
    defer lease.deinit();
    var jobs: [work_pool.MAX_WORKERS]Job = undefined;
    const buffers_per_worker = buffers.len / worker_count;
    const extra = buffers.len % worker_count;
    var next: usize = 0;
    for (jobs[0..worker_count], 0..) |*job, worker_index| {
        const assigned = buffers_per_worker + @intFromBool(worker_index < extra);
        job.* = .{
            .buffers = buffers[next .. next + assigned],
            .domain = domain,
            .twiddles = twiddles,
        };
        next += assigned;
    }
    std.debug.assert(next == buffers.len);

    var wait_group: std.Thread.WaitGroup = .{};
    var wave_active = false;
    defer if (wave_active) {
        wait_group.wait();
        lease.completeWave();
    };
    for (jobs[1..worker_count]) |*job| {
        try lease.spawnWg(&wait_group, Job.run, .{job});
        wave_active = true;
    }
    jobs[0].run();
    wait_group.wait();
    lease.completeWave();
    wave_active = false;
    for (jobs[0..worker_count]) |job| {
        if (job.failure) |failure| return failure;
    }
}

fn runPipelineJobs(
    comptime Job: type,
    coefficient_buffers: []const []M31,
    extension_buffers: []const []M31,
    committed_domain: anytype,
    committed_twiddles: anytype,
    evaluation_domain: anytype,
    evaluation_twiddles: anytype,
) !void {
    if (coefficient_buffers.len == 0) return;
    if (coefficient_buffers.len != extension_buffers.len)
        return error.InvalidProofShape;
    if (evaluation_domain.logSize() < parallel_domain_log_size) {
        var serial = Job{
            .coefficient_buffers = coefficient_buffers,
            .extension_buffers = extension_buffers,
            .committed_domain = committed_domain,
            .committed_twiddles = committed_twiddles,
            .evaluation_domain = evaluation_domain,
            .evaluation_twiddles = evaluation_twiddles,
        };
        serial.run();
        if (serial.failure) |failure| return failure;
        return;
    }
    const pool = work_pool.getGlobalPool() orelse {
        var serial = Job{
            .coefficient_buffers = coefficient_buffers,
            .extension_buffers = extension_buffers,
            .committed_domain = committed_domain,
            .committed_twiddles = committed_twiddles,
            .evaluation_domain = evaluation_domain,
            .evaluation_twiddles = evaluation_twiddles,
        };
        serial.run();
        if (serial.failure) |failure| return failure;
        return;
    };
    const worker_count = @min(pool.workerCount(), coefficient_buffers.len);
    if (worker_count == 1) {
        var serial = Job{
            .coefficient_buffers = coefficient_buffers,
            .extension_buffers = extension_buffers,
            .committed_domain = committed_domain,
            .committed_twiddles = committed_twiddles,
            .evaluation_domain = evaluation_domain,
            .evaluation_twiddles = evaluation_twiddles,
        };
        serial.run();
        if (serial.failure) |failure| return failure;
        return;
    }

    var lease = try pool.acquire(try work_pool.WorkerBudget.init(worker_count));
    defer lease.deinit();
    var jobs: [work_pool.MAX_WORKERS]Job = undefined;
    const buffers_per_worker = coefficient_buffers.len / worker_count;
    const extra = coefficient_buffers.len % worker_count;
    var next: usize = 0;
    for (jobs[0..worker_count], 0..) |*job, worker_index| {
        const assigned = buffers_per_worker + @intFromBool(worker_index < extra);
        job.* = .{
            .coefficient_buffers = coefficient_buffers[next .. next + assigned],
            .extension_buffers = extension_buffers[next .. next + assigned],
            .committed_domain = committed_domain,
            .committed_twiddles = committed_twiddles,
            .evaluation_domain = evaluation_domain,
            .evaluation_twiddles = evaluation_twiddles,
        };
        next += assigned;
    }
    std.debug.assert(next == coefficient_buffers.len);

    var wait_group: std.Thread.WaitGroup = .{};
    var wave_active = false;
    defer if (wave_active) {
        wait_group.wait();
        lease.completeWave();
    };
    for (jobs[1..worker_count]) |*job| {
        try lease.spawnWg(&wait_group, Job.run, .{job});
        wave_active = true;
    }
    jobs[0].run();
    wait_group.wait();
    lease.completeWave();
    wave_active = false;
    for (jobs[0..worker_count]) |job| {
        if (job.failure) |failure| return failure;
    }
}

fn validateSource(
    poly: prover_component.Poly,
    trace_log_size: u32,
    evaluation_log_size: u32,
) !void {
    try poly.validate();
    if (poly.log_size == evaluation_log_size) return;
    const coefficients = poly.coefficients orelse
        return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size)
        return error.InvalidProofShape;
}

/// Lightweight parity exercise reused by the filtered candidate-leaf proof
/// gate.  It compares the exact quotient-domain composition inputs produced
/// from retained coefficients (`.always`) and from only the committed LDE
/// (`.never`).
pub fn exerciseRetainedLdeParityForTest(allocator: std.mem.Allocator) !void {
    const trace_log_size: u32 = 3;
    const committed_log_size: u32 = 4;
    const evaluation_log_size: u32 = 5;
    const committed_size: usize = @as(usize, 1) << @intCast(committed_log_size);
    const evaluation_size: usize = @as(usize, 1) << @intCast(evaluation_log_size);

    var coefficient_values: [8]M31 = undefined;
    for (&coefficient_values, 0..) |*value, index| {
        value.* = M31.fromU64(@intCast(11 + index * 37));
    }
    const coefficients = try prover_poly.CircleCoefficients.initBorrowed(
        &coefficient_values,
    );
    const committed_values = try allocator.alloc(M31, committed_size);
    defer allocator.free(committed_values);
    @memcpy(committed_values[0..coefficient_values.len], &coefficient_values);
    @memset(committed_values[coefficient_values.len..], M31.zero());
    const committed_domain = canonic.CanonicCoset.new(
        committed_log_size,
    ).circleDomain();
    var committed_twiddles = try prover_twiddles.precomputeM31(
        allocator,
        committed_domain.half_coset,
    );
    defer prover_twiddles.deinitM31(allocator, &committed_twiddles);
    var committed_buffers = [_][]M31{committed_values};
    try prover_poly.evaluateBuffersWithTwiddles(
        &committed_buffers,
        committed_domain,
        prover_twiddles.TwiddleTree([]const M31).init(
            committed_twiddles.root_coset,
            committed_twiddles.twiddles,
            committed_twiddles.itwiddles,
        ),
    );

    const retained_poly = prover_component.Poly{
        .log_size = committed_log_size,
        .values = committed_values,
        .coefficients = coefficients,
    };
    const discarded_poly = prover_component.Poly{
        .log_size = committed_log_size,
        .values = committed_values,
    };
    var retained_counts = ExtensionCounts{};
    try retained_counts.add(try extensionSource(
        retained_poly,
        trace_log_size,
        evaluation_log_size,
    ));
    var discarded_counts = ExtensionCounts{};
    try discarded_counts.add(try extensionSource(
        discarded_poly,
        trace_log_size,
        evaluation_log_size,
    ));
    try std.testing.expectEqual(@as(usize, 1), retained_counts.owned);
    try std.testing.expectEqual(@as(usize, 1), retained_counts.retained_coefficients);
    try std.testing.expectEqual(@as(usize, 1), discarded_counts.owned);
    try std.testing.expectEqual(@as(usize, 1), discarded_counts.committed_lde);

    const evaluation_domain = canonic.CanonicCoset.new(
        evaluation_log_size,
    ).circleDomain();
    var retained_owner = try RetainedLdeOwner.init(allocator, retained_counts);
    defer retained_owner.deinit();
    const retained_evaluation = try retained_owner.value(
        retained_poly,
        trace_log_size,
        evaluation_log_size,
        evaluation_size,
    );
    try retained_owner.finish(evaluation_domain);

    var discarded_owner = try RetainedLdeOwner.init(allocator, discarded_counts);
    defer discarded_owner.deinit();
    const discarded_evaluation = try discarded_owner.value(
        discarded_poly,
        trace_log_size,
        evaluation_log_size,
        evaluation_size,
    );
    try discarded_owner.finish(evaluation_domain);

    const extension_bits: u5 = @intCast(
        evaluation_log_size - trace_log_size,
    );
    var denominator_inverses: [4]M31 = undefined;
    const trace_coset = canonic.CanonicCoset.new(trace_log_size).coset();
    for (&denominator_inverses, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            trace_coset,
            evaluation_domain.at(core_utils.bitReverseIndex(
                index,
                extension_bits,
            )),
        ).inv();
    }

    var retained_fold = M31.zero();
    var discarded_fold = M31.zero();
    for (retained_evaluation, discarded_evaluation, 0..) |
        retained,
        discarded,
        row,
    | {
        try std.testing.expect(retained.eql(discarded));
        const denominator = denominator_inverses[
            row >> @intCast(trace_log_size)
        ];
        const random_power = M31.fromU64(@intCast(3 + row * 19));
        retained_fold = retained_fold.add(
            retained.mul(denominator).mul(random_power),
        );
        discarded_fold = discarded_fold.add(
            discarded.mul(denominator).mul(random_power),
        );
    }
    try std.testing.expect(retained_fold.eql(discarded_fold));

    const retained_resident = try retainedLdeResidentBytes(
        retained_counts,
        evaluation_size,
    );
    const discarded_resident = try retainedLdeResidentBytes(
        discarded_counts,
        evaluation_size,
    );
    try std.testing.expectEqual(
        try residentBytes(1, evaluation_size) + @sizeOf([]M31),
        retained_resident,
    );
    try std.testing.expectEqual(
        try residentBytes(1, evaluation_size) + 2 * @sizeOf([]M31),
        discarded_resident,
    );
}

test "prepared evaluation owner: always and never quotient composition inputs match" {
    try exerciseRetainedLdeParityForTest(std.testing.allocator);
}

test "prepared evaluation owner: retained LDE fallback is bounded and fail closed" {
    const allocator = std.testing.allocator;
    var equal_domain_values = [_]M31{M31.zero()} ** 32;
    const equal_domain = prover_component.Poly{
        .log_size = 5,
        .values = &equal_domain_values,
    };
    try std.testing.expectEqual(
        ExtensionSource.borrowed,
        try extensionSource(equal_domain, 3, 5),
    );
    var no_extensions = try RetainedLdeOwner.init(allocator, .{});
    defer no_extensions.deinit();
    const borrowed = try no_extensions.value(equal_domain, 3, 5, 32);
    try std.testing.expect(borrowed.ptr == equal_domain_values[0..].ptr);
    try no_extensions.finish(canonic.CanonicCoset.new(5).circleDomain());

    var too_narrow_values = [_]M31{M31.zero()} ** 4;
    const too_narrow = prover_component.Poly{
        .log_size = 2,
        .values = &too_narrow_values,
    };
    try std.testing.expectError(
        error.InvalidProofShape,
        extensionSource(too_narrow, 3, 5),
    );
    try std.testing.expectError(
        error.InvalidProofShape,
        RetainedLdeOwner.init(allocator, .{ .owned = 1 }),
    );
}
