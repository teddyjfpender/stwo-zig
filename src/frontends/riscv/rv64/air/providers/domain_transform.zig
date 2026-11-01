//! Shared column-parallel coset transform, moved from the full CPU evaluator.
//! One bounded joined wave; each worker owns complete, disjoint column buffers.
//!
//! `expand` is the composition-time expansion of committed trace columns:
//! each worker copies its own columns' compact coefficients into their
//! evaluation buffers and transforms them. When every source is exactly half
//! of its buffer (the 2x blowup), the zero upper half is never written: the
//! extension FFT replaces the degenerate first layer by duplicating the lower
//! half. That is bit-identical to zero-padding and running the full FFT.
//! Twiddles come from an immutable process-wide cache, so components share
//! one precomputed tower instead of rebuilding it per evaluation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
const M = core.fields.m31.M31;
const Coset = core.circle.Coset;
const Domain = core.poly.circle.domain.CircleDomain;
const Poly = engine.air.component_prover.Poly;
const Twiddles = engine.poly.twiddles.TwiddleTree([]const M);
const poly = engine.poly.circle.poly;

pub fn evaluate(buffers: [][]M, domain: Domain, tree: Twiddles, pool: ?*work.WorkPool) !void {
    return run(.{ .buffers = buffers, .mode = .evaluated }, domain, tree, pool);
}

/// Allocate the evaluation buffer for one source, or borrow its resident
/// evaluation. Same ownership protocol and checks as
/// `hash_component_prepared_support.evaluationValues`, but the buffer is left
/// uninitialized: `expand` fills it from the source's coefficients.
pub fn reserve(
    allocator: std.mem.Allocator,
    source: Poly,
    eval_log_size: u32,
    eval_size: usize,
    owned_buffers: [][]M,
    owned_initialized: *usize,
) ![]const M {
    if (isResident(source, eval_log_size)) return source.values;
    if (owned_initialized.* >= owned_buffers.len) return error.InvalidProofShape;
    const coefficients = source.coefficients orelse return error.InvalidProofShape;
    if (coefficients.coefficients().len > eval_size) return error.InvalidProofShape;
    const values = try allocator.alloc(M, eval_size);
    owned_buffers[owned_initialized.*] = values;
    owned_initialized.* += 1;
    return values;
}

/// Fill and evaluate every buffer handed out by `reserve` for `sources`, in
/// order. Bit-identical to `evaluationValues` followed by
/// `evaluateBuffersWithTwiddles` with freshly precomputed twiddles.
pub fn expand(
    allocator: std.mem.Allocator,
    buffers: [][]M,
    sources: []const Poly,
    eval_log_size: u32,
    domain: Domain,
    pool: ?*work.WorkPool,
) !void {
    if (buffers.len == 0) return;
    const size = domain.size();
    const coefficients = try allocator.alloc([]const M, buffers.len);
    defer allocator.free(coefficients);
    var at: usize = 0;
    var extension = true;
    for (sources) |source| {
        if (isResident(source, eval_log_size)) continue;
        if (at >= buffers.len) return error.InvalidProofShape;
        const values = (source.coefficients orelse return error.InvalidProofShape).coefficients();
        if (values.len > size or buffers[at].len != size) return error.InvalidProofShape;
        extension = extension and values.len * 2 == size;
        coefficients[at] = values;
        at += 1;
    }
    if (at != buffers.len) return error.InvalidProofShape;
    const tree = try twiddles(domain);
    return run(.{
        .buffers = buffers,
        .sources = coefficients,
        .mode = if (extension) .extension else .padded,
    }, domain, tree, pool);
}

fn isResident(source: Poly, eval_log_size: u32) bool {
    return source.log_size == eval_log_size and source.values.len != 0;
}

/// Borrow the forward/inverse twiddle tower for `domain`. Entries are built
/// once by the exact serial `precomputeM31`, never mutated or freed, and a
/// smaller tower is served as the layer suffix of any cached tower whose root
/// repeatedly doubles to it (the same values a fresh precompute produces).
pub fn twiddles(domain: Domain) !Twiddles {
    const want = domain.half_coset;
    cache.mutex.lock();
    defer cache.mutex.unlock();
    for (cache.entries[0..cache.len]) |entry| {
        if (entry.root_coset.logSize() < want.logSize()) continue;
        if (!entry.root_coset.repeatedDouble(entry.root_coset.logSize() - want.logSize()).eql(want)) continue;
        return entry.subtree(want.logSize());
    }
    if (cache.len == cache.entries.len) return error.TwiddleCacheFull;
    const built = try engine.poly.twiddles.precomputeM31(std.heap.page_allocator, want);
    const tree = Twiddles.init(built.root_coset, built.twiddles, built.itwiddles);
    cache.entries[cache.len] = tree;
    cache.len += 1;
    return tree;
}

var cache: struct {
    mutex: std.Thread.Mutex = .{},
    entries: [64]Twiddles = undefined,
    len: usize = 0,
} = .{};

const Mode = enum { evaluated, padded, extension };
const Batch = struct {
    buffers: [][]M,
    sources: []const []const M = &.{},
    mode: Mode,
    fn slice(self: Batch, start: usize, end: usize) Batch {
        return .{
            .buffers = self.buffers[start..end],
            .sources = if (self.mode == .evaluated) &.{} else self.sources[start..end],
            .mode = self.mode,
        };
    }
};

fn run(batch: Batch, domain: Domain, tree: Twiddles, pool: ?*work.WorkPool) !void {
    const buffers = batch.buffers;
    if (buffers.len == 0) return;
    const size = domain.size();
    for (buffers) |buffer| if (buffer.len != size) return error.InvalidDomainTransformShape;
    const cells = std.math.mul(usize, buffers.len, size) catch return error.InvalidDomainTransformShape;
    const workers = if (pool) |active| @min(active.workerCount(), @min(buffers.len, @max(1, cells / 8192))) else 1;
    if (workers <= 1) return transform(batch, domain, tree);
    var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{
        .batch = batch.slice(buffers.len * i / workers, buffers.len * (i + 1) / workers),
        .target = domain,
        .twiddles = tree,
    };
    {
        var group = std.Thread.WaitGroup{};
        defer {
            group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers]) |*job| try lease.spawnWg(&group, Job.run, .{job});
        jobs[0].run();
    }
    for (jobs[0..workers]) |job| if (job.failure) |failure| return failure;
}

fn transform(batch: Batch, domain: Domain, tree: Twiddles) !void {
    switch (batch.mode) {
        .evaluated => return poly.evaluateBuffersWithTwiddles(batch.buffers, domain, tree),
        .padded => {
            for (batch.buffers, batch.sources) |buffer, source| {
                @memcpy(buffer[0..source.len], source);
                @memset(buffer[source.len..], M.zero());
            }
            return poly.evaluateBuffersWithTwiddles(batch.buffers, domain, tree);
        },
        .extension => {
            for (batch.buffers, batch.sources) |buffer, source| @memcpy(buffer[0..source.len], source);
            return poly.evaluateExtensionBuffersWithTwiddles(batch.buffers, domain, tree);
        },
    }
}

const Job = struct {
    batch: Batch,
    target: Domain,
    twiddles: Twiddles,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        transform(self.batch, self.target, self.twiddles) catch |err| {
            self.failure = err;
        };
    }
};
