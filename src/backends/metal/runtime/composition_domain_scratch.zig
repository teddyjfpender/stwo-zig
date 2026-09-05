//! Proof-local ownership for composition-domain trace evaluations.
//!
//! A committed PCS column describes the blowup domain while its retained
//! coefficients describe the unique trace polynomial.  Components whose
//! constraint degree exceeds the PCS blowup must evaluate those coefficients
//! on the wider composition domain; relabeling or lifting committed values is
//! not equivalent.  This owner materializes that exact evaluation once in a
//! Metal-resident, process-local buffer and exposes a shadow `Trace` whose
//! replaced columns remain pointer-closed to the source coefficients and the
//! resident allocation.  It has no codec and is never verifier admission.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const metal_runtime = @import("../runtime.zig");

const M31 = core.fields.m31.M31;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;
const TwiddleTree = prover.poly.twiddles.TwiddleTree([]const M31);

pub const FORMAT_VERSION: u16 = 1;

/// Concurrent owner windows.  Each window holds at most one resident scratch
/// buffer, so this is also the pool capacity and the peak resident footprint
/// multiplier.  Two windows let one proof's composition kernels execute while
/// the next proof expands its coefficients.
pub const OWNER_WINDOWS: u16 = 2;
pub const MAX_POOLED_RESIDENTS: usize = OWNER_WINDOWS;

var owner_windows: std.Thread.Semaphore = .{ .permits = OWNER_WINDOWS };
var pool_mutex: std.Thread.Mutex = .{};

/// Blocks until one owner window is free.  Pair with `releaseOwnerWindow`
/// after the owner is deinitialized.
pub fn acquireOwnerWindow() void {
    owner_windows.wait();
}

pub fn releaseOwnerWindow() void {
    owner_windows.post();
}

/// Resident buffers are recycled by exact byte length instead of being
/// allocated per proof.  A one-gigabyte shared allocation costs a fresh
/// page-fault sweep on every first touch; reuse keeps the pages mapped and
/// the transform binding contract (`byte_length == columns * rows * 4`)
/// exact.  Slots are keyed by the runtime that created them.
const PooledResidentV1 = struct {
    runtime: *metal_runtime.Runtime,
    resident: metal_runtime.ResidentBuffer,
};

var pooled_residents: [MAX_POOLED_RESIDENTS]?PooledResidentV1 =
    [_]?PooledResidentV1{null} ** MAX_POOLED_RESIDENTS;
var pool_hits: std.atomic.Value(u64) = .init(0);
var pool_misses: std.atomic.Value(u64) = .init(0);

pub const PoolSnapshotV1 = struct { hits: u64, misses: u64, pooled: usize };

pub fn poolSnapshot() PoolSnapshotV1 {
    var pooled: usize = 0;
    for (pooled_residents) |slot| pooled += @intFromBool(slot != null);
    return .{
        .hits = pool_hits.load(.monotonic),
        .misses = pool_misses.load(.monotonic),
        .pooled = pooled,
    };
}

/// Caller holds one owner window.
fn acquireResident(
    runtime: *metal_runtime.Runtime,
    byte_count: usize,
) !metal_runtime.ResidentBuffer {
    pool_mutex.lock();
    defer pool_mutex.unlock();
    for (&pooled_residents) |*slot| {
        const entry = slot.* orelse continue;
        if (entry.runtime == runtime and entry.resident.byte_length == byte_count) {
            slot.* = null;
            _ = pool_hits.fetchAdd(1, .monotonic);
            return entry.resident;
        }
    }
    _ = pool_misses.fetchAdd(1, .monotonic);
    return runtime.allocateResidentBuffer(byte_count);
}

/// Caller holds one owner window.  A full pool evicts the incoming buffer so
/// the resident footprint stays bounded by `MAX_POOLED_RESIDENTS` entries.
fn releaseResident(
    runtime: *metal_runtime.Runtime,
    resident: metal_runtime.ResidentBuffer,
) void {
    pool_mutex.lock();
    defer pool_mutex.unlock();
    for (&pooled_residents) |*slot| {
        if (slot.* == null) {
            slot.* = .{ .runtime = runtime, .resident = resident };
            return;
        }
    }
    var owned = resident;
    owned.deinit();
}

/// Frees every pooled buffer.  Must run before the shared Metal runtime is
/// torn down and after every composition owner has finished.
pub fn releasePooledResidents() void {
    pool_mutex.lock();
    defer pool_mutex.unlock();
    for (&pooled_residents) |*slot| {
        if (slot.*) |*entry| {
            entry.resident.deinit();
            slot.* = null;
        }
    }
}

pub const RequestV1 = struct {
    tree_index: usize,
    column_index: usize,
    trace_log_size: u32,
    evaluation_log_size: u32,
};

const EntryV1 = struct {
    request: RequestV1,
    source_coefficients_ptr: [*]const M31,
    source_coefficients_len: usize,
    resident_word_offset: usize,
};

pub const OwnedV1 = struct {
    allocator: std.mem.Allocator,
    runtime: *metal_runtime.Runtime,
    source_trace: *const Trace,
    trace: Trace,
    resident: metal_runtime.ResidentBuffer,
    request_storage: []RequestV1,
    entries: []EntryV1,
    evaluation_log_size: u32,
    evaluation_size: usize,
    resident_word_count: usize,
    gpu_milliseconds: f64,
    transform_wall_nanoseconds: u64,
    host_fill_nanoseconds: u64,
    host_fill_workers: usize,
    exact_resident_source: bool,

    /// Caller holds one owner window for the whole owner lifetime.
    pub fn init(
        allocator: std.mem.Allocator,
        runtime: *metal_runtime.Runtime,
        source_trace: *const Trace,
        requests: []const RequestV1,
        twiddles: TwiddleTree,
    ) !OwnedV1 {
        if (requests.len == 0) return error.EmptyCompositionDomainScratch;

        const request_storage = try allocator.dupe(RequestV1, requests);
        errdefer allocator.free(request_storage);
        std.mem.sortUnstable(
            RequestV1,
            request_storage,
            {},
            requestLessThan,
        );
        const unique_count = try compactAndValidateRequests(
            request_storage,
            source_trace,
        );
        const canonical_requests = request_storage[0..unique_count];
        const evaluation_log_size = canonical_requests[0].evaluation_log_size;
        if (evaluation_log_size >= @bitSizeOf(usize))
            return error.InvalidCompositionDomainScratch;
        const evaluation_size = @as(usize, 1) <<
            @intCast(evaluation_log_size);
        if (twiddles.root_coset.logSize() != evaluation_log_size - 1 or
            twiddles.twiddles.len != evaluation_size / 2)
        {
            return error.InvalidCompositionDomainTwiddles;
        }

        var shadow = try cloneTrace(allocator, source_trace);
        errdefer shadow.polys.deinitDeep(allocator);
        const resident_word_count = std.math.mul(
            usize,
            unique_count,
            evaluation_size,
        ) catch return error.CompositionDomainScratchSizeOverflow;
        const resident_byte_count = std.math.mul(
            usize,
            resident_word_count,
            @sizeOf(M31),
        ) catch return error.CompositionDomainScratchSizeOverflow;
        var resident = try acquireResident(runtime, resident_byte_count);
        errdefer releaseResident(runtime, resident);
        if (resident.byte_length != resident_byte_count or
            @intFromPtr(resident.contents) % @alignOf(M31) != 0)
        {
            return error.InvalidCompositionDomainResidentBuffer;
        }
        const resident_values_ptr: [*]M31 = @ptrCast(@alignCast(resident.contents));
        const resident_values = resident_values_ptr[0..resident_word_count];
        const columns = try allocator.alloc([]M31, unique_count);
        defer allocator.free(columns);
        const entries = try allocator.alloc(EntryV1, unique_count);
        errdefer allocator.free(entries);

        var fill_timer = try std.time.Timer.start();
        for (canonical_requests, columns, entries, 0..) |
            request,
            *destination,
            *entry,
            index,
        | {
            const source = source_trace.polys.items[request.tree_index][request.column_index];
            const coefficients = source.coefficients orelse
                return error.MissingCompositionDomainCoefficients;
            const coefficient_values = coefficients.coefficients();
            if (coefficients.logSize() != request.trace_log_size or
                coefficient_values.len > evaluation_size)
            {
                return error.InvalidCompositionDomainCoefficients;
            }
            const offset = std.math.mul(
                usize,
                index,
                evaluation_size,
            ) catch return error.CompositionDomainScratchSizeOverflow;
            destination.* = resident_values[offset..][0..evaluation_size];
            @constCast(shadow.polys.items[request.tree_index])[request.column_index] = .{
                .log_size = evaluation_log_size,
                .values = destination.*,
                .coefficients = source.coefficients,
            };
            entry.* = .{
                .request = request,
                .source_coefficients_ptr = coefficient_values.ptr,
                .source_coefficients_len = coefficient_values.len,
                .resident_word_offset = offset,
            };
        }
        const host_fill_workers = try fillResidentColumns(allocator, entries, columns);
        const host_fill_nanoseconds = fill_timer.read();

        var transform_timer = try std.time.Timer.start();
        const transform = try runtime.transformCircleResidentBatch(
            allocator,
            &resident,
            columns,
            twiddles.twiddles,
            evaluation_log_size,
            false,
        );
        const transform_wall_nanoseconds = transform_timer.read();
        if (!transform.direct_host_alias or !transform.exact_resident_source)
            return error.CompositionDomainTransformNotResident;
        var result = OwnedV1{
            .allocator = allocator,
            .runtime = runtime,
            .source_trace = source_trace,
            .trace = shadow,
            .resident = resident,
            .request_storage = request_storage,
            .entries = entries,
            .evaluation_log_size = evaluation_log_size,
            .evaluation_size = evaluation_size,
            .resident_word_count = resident_word_count,
            .gpu_milliseconds = transform.gpu_milliseconds,
            .transform_wall_nanoseconds = transform_wall_nanoseconds,
            .host_fill_nanoseconds = host_fill_nanoseconds,
            .host_fill_workers = host_fill_workers,
            .exact_resident_source = transform.exact_resident_source,
        };
        try result.validateBorrowed(source_trace);
        return result;
    }

    pub fn validateBorrowed(self: *const OwnedV1, source_trace: *const Trace) !void {
        if (self.source_trace != source_trace or self.entries.len == 0 or
            self.entries.len > self.request_storage.len or
            self.evaluation_log_size >= @bitSizeOf(usize) or
            self.evaluation_size !=
                (@as(usize, 1) << @intCast(self.evaluation_log_size)) or
            self.resident.byte_length != self.resident_word_count * @sizeOf(M31) or
            @intFromPtr(self.resident.contents) % @alignOf(M31) != 0 or
            !self.exact_resident_source or
            self.trace.polys.items.len != source_trace.polys.items.len)
        {
            return error.InvalidCompositionDomainScratch;
        }
        const begin = @intFromPtr(self.resident.contents);
        for (self.entries, 0..) |entry, index| {
            if (!std.meta.eql(
                entry.request,
                self.request_storage[index],
            ) or entry.request.evaluation_log_size != self.evaluation_log_size or
                entry.request.tree_index >= source_trace.polys.items.len or
                entry.request.tree_index >= self.trace.polys.items.len or
                entry.request.column_index >=
                    source_trace.polys.items[entry.request.tree_index].len or
                entry.request.column_index >=
                    self.trace.polys.items[entry.request.tree_index].len)
            {
                return error.InvalidCompositionDomainScratch;
            }
            const source = source_trace.polys.items[entry.request.tree_index][entry.request.column_index];
            const coefficients = source.coefficients orelse
                return error.MissingCompositionDomainCoefficients;
            const coefficient_values = coefficients.coefficients();
            const expanded = self.trace.polys.items[entry.request.tree_index][entry.request.column_index];
            const expected_offset = std.math.mul(
                usize,
                index,
                self.evaluation_size,
            ) catch return error.CompositionDomainScratchSizeOverflow;
            const expected_byte_offset = std.math.mul(
                usize,
                expected_offset,
                @sizeOf(M31),
            ) catch return error.CompositionDomainScratchSizeOverflow;
            const expected_address = std.math.add(
                usize,
                begin,
                expected_byte_offset,
            ) catch return error.CompositionDomainScratchSizeOverflow;
            if (entry.source_coefficients_ptr != coefficient_values.ptr or
                entry.source_coefficients_len != coefficient_values.len or
                entry.resident_word_offset != expected_offset or
                expanded.log_size != self.evaluation_log_size or
                expanded.values.len != self.evaluation_size or
                @intFromPtr(expanded.values.ptr) != expected_address or
                expanded.coefficients == null or
                expanded.coefficients.?.coefficients().ptr != coefficient_values.ptr)
            {
                return error.InvalidCompositionDomainScratch;
            }
        }
    }

    /// Caller holds one owner window; the resident buffer returns to the pool.
    pub fn deinit(self: *OwnedV1) void {
        const allocator = self.allocator;
        releaseResident(self.runtime, self.resident);
        self.trace.polys.deinitDeep(allocator);
        allocator.free(self.entries);
        allocator.free(self.request_storage);
        self.* = undefined;
    }
};

/// Copies every retained coefficient block into its resident column and
/// zero-fills the remaining evaluation rows.  Columns are independent, so the
/// gigabyte-scale fill is split across the shared work pool instead of
/// streaming through the single owner thread while the lock is held.
fn fillResidentColumns(
    allocator: std.mem.Allocator,
    entries: []const EntryV1,
    columns: []const []M31,
) !usize {
    std.debug.assert(entries.len == columns.len);
    const minimum_columns_per_worker: usize = 8;
    const pool = prover.work_pool.getGlobalPool();
    const worker_count = if (pool) |active|
        @min(active.workerCount(), @max(@as(usize, 1), entries.len / minimum_columns_per_worker))
    else
        1;
    if (worker_count <= 1) {
        fillResidentRange(entries, columns);
        return 1;
    }
    const ranges = try allocator.alloc(FillRangeV1, worker_count);
    defer allocator.free(ranges);
    for (ranges, 0..) |*range, index| {
        range.* = .{
            .entries = entries[entries.len * index / worker_count .. entries.len * (index + 1) / worker_count],
            .columns = columns[entries.len * index / worker_count .. entries.len * (index + 1) / worker_count],
        };
    }
    var wait_group = std.Thread.WaitGroup{};
    for (ranges[1..]) |*range| pool.?.spawnWg(&wait_group, FillRangeV1.run, .{range});
    FillRangeV1.run(&ranges[0]);
    wait_group.wait();
    return worker_count;
}

const FillRangeV1 = struct {
    entries: []const EntryV1,
    columns: []const []M31,

    fn run(self: *FillRangeV1) void {
        fillResidentRange(self.entries, self.columns);
    }
};

fn fillResidentRange(entries: []const EntryV1, columns: []const []M31) void {
    for (entries, columns) |entry, destination| {
        const source = entry.source_coefficients_ptr[0..entry.source_coefficients_len];
        @memcpy(destination[0..source.len], source);
        @memset(destination[source.len..], M31.zero());
    }
}

pub fn exactResidentBytes(
    column_count: usize,
    evaluation_log_size: u32,
) !u64 {
    if (column_count == 0 or evaluation_log_size >= 63)
        return error.InvalidCompositionDomainScratch;
    const row_bytes = std.math.mul(
        u64,
        @as(u64, 1) << @intCast(evaluation_log_size),
        @sizeOf(M31),
    ) catch return error.CompositionDomainScratchSizeOverflow;
    return std.math.mul(
        u64,
        std.math.cast(u64, column_count) orelse
            return error.CompositionDomainScratchSizeOverflow,
        row_bytes,
    ) catch error.CompositionDomainScratchSizeOverflow;
}

fn compactAndValidateRequests(
    storage: []RequestV1,
    trace: *const Trace,
) !usize {
    var unique_count: usize = 0;
    for (storage) |request| {
        if (request.tree_index >= trace.polys.items.len or
            request.column_index >= trace.polys.items[request.tree_index].len or
            request.trace_log_size == 0 or
            request.evaluation_log_size <= request.trace_log_size or
            request.evaluation_log_size - request.trace_log_size > 3)
        {
            return error.InvalidCompositionDomainScratchRequest;
        }
        const source = trace.polys.items[request.tree_index][request.column_index];
        try source.validate();
        if (source.log_size >= request.evaluation_log_size)
            return error.InvalidCompositionDomainScratchRequest;
        if (unique_count != 0) {
            const previous = storage[unique_count - 1];
            if (previous.tree_index == request.tree_index and
                previous.column_index == request.column_index)
            {
                if (previous.trace_log_size != request.trace_log_size or
                    previous.evaluation_log_size != request.evaluation_log_size)
                {
                    return error.ConflictingCompositionDomainScratchRequest;
                }
                continue;
            }
            if (previous.evaluation_log_size != request.evaluation_log_size)
                return error.MixedCompositionDomainScratchLogSizes;
        }
        storage[unique_count] = request;
        unique_count += 1;
    }
    if (unique_count == 0) return error.EmptyCompositionDomainScratch;
    return unique_count;
}

fn cloneTrace(
    allocator: std.mem.Allocator,
    source: *const Trace,
) !Trace {
    const trees = try allocator.alloc([]const Poly, source.polys.items.len);
    errdefer allocator.free(trees);
    var initialized: usize = 0;
    errdefer for (trees[0..initialized]) |tree| allocator.free(tree);
    for (source.polys.items, trees) |source_tree, *destination_tree| {
        const owned = try allocator.dupe(Poly, source_tree);
        destination_tree.* = owned;
        initialized += 1;
    }
    return .{ .polys = core.pcs.TreeVec([]const Poly).initOwned(trees) };
}

fn requestLessThan(_: void, left: RequestV1, right: RequestV1) bool {
    if (left.tree_index != right.tree_index)
        return left.tree_index < right.tree_index;
    return left.column_index < right.column_index;
}

test "Metal composition domain scratch exact byte count is degree aware" {
    try std.testing.expectEqual(
        @as(u64, 1_044_381_696),
        try exactResidentBytes(2 + 239 + 8, 20),
    );
    try std.testing.expectError(
        error.InvalidCompositionDomainScratch,
        exactResidentBytes(0, 20),
    );
}

test "Metal composition domain scratch evaluates retained coefficients in one exact resident owner" {
    const allocator = std.testing.allocator;
    const coefficient_log_size: u32 = 17;
    const committed_log_size: u32 = 18;
    const evaluation_log_size: u32 = 19;
    const coefficient_count = @as(usize, 1) << coefficient_log_size;

    const coefficient_values = try allocator.alloc(M31, coefficient_count);
    defer allocator.free(coefficient_values);
    for (coefficient_values, 0..) |*value, index| {
        value.* = M31.fromCanonical(@intCast((index * 29 + 17) % core.fields.m31.Modulus));
    }
    const coefficients = try prover.poly.circle.CircleCoefficients.initBorrowed(
        coefficient_values,
    );
    const committed_domain = core.poly.circle.canonic.CanonicCoset.new(
        committed_log_size,
    ).circleDomain();
    const committed = try coefficients.evaluate(allocator, committed_domain);
    defer allocator.free(@constCast(committed.values));
    const expected_domain = core.poly.circle.canonic.CanonicCoset.new(
        evaluation_log_size,
    ).circleDomain();
    const expected = try coefficients.evaluate(allocator, expected_domain);
    defer allocator.free(@constCast(expected.values));

    const source_tree = try allocator.dupe(Poly, &.{.{
        .log_size = committed_log_size,
        .values = committed.values,
        .coefficients = coefficients,
    }});
    defer allocator.free(source_tree);
    const trees = try allocator.dupe([]const Poly, &.{source_tree});
    var source = Trace{
        .polys = core.pcs.TreeVec([]const Poly).initOwned(trees),
    };
    defer source.polys.deinit(allocator);

    var twiddles = try prover.poly.twiddles.precomputeM31(
        allocator,
        expected_domain.half_coset,
    );
    defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
    var runtime = try metal_runtime.Runtime.init();
    defer runtime.deinit();
    // Pooled residents belong to this runtime; drop them before it goes away.
    defer releasePooledResidents();
    acquireOwnerWindow();
    defer releaseOwnerWindow();
    const pool_before = poolSnapshot();
    source_tree[0].coefficients = null;
    try std.testing.expectError(
        error.MissingCompositionDomainCoefficients,
        OwnedV1.init(
            allocator,
            &runtime,
            &source,
            &.{.{
                .tree_index = 0,
                .column_index = 0,
                .trace_log_size = coefficient_log_size,
                .evaluation_log_size = evaluation_log_size,
            }},
            .{
                .root_coset = twiddles.root_coset,
                .twiddles = twiddles.twiddles,
                .itwiddles = twiddles.itwiddles,
            },
        ),
    );
    source_tree[0].coefficients = coefficients;
    var scratch = try OwnedV1.init(
        allocator,
        &runtime,
        &source,
        &.{.{
            .tree_index = 0,
            .column_index = 0,
            .trace_log_size = coefficient_log_size,
            .evaluation_log_size = evaluation_log_size,
        }},
        .{
            .root_coset = twiddles.root_coset,
            .twiddles = twiddles.twiddles,
            .itwiddles = twiddles.itwiddles,
        },
    );
    defer scratch.deinit();

    try scratch.validateBorrowed(&source);
    try std.testing.expect(scratch.exact_resident_source);
    try std.testing.expectEqual(
        @intFromPtr(scratch.resident.contents),
        @intFromPtr(scratch.trace.polys.items[0][0].values.ptr),
    );
    try std.testing.expectEqualSlices(
        M31,
        expected.values,
        scratch.trace.polys.items[0][0].values,
    );

    const saved_values = scratch.trace.polys.items[0][0].values;
    @constCast(scratch.trace.polys.items[0])[0].values = committed.values;
    try std.testing.expectError(
        error.InvalidCompositionDomainScratch,
        scratch.validateBorrowed(&source),
    );
    @constCast(scratch.trace.polys.items[0])[0].values = saved_values;
    try scratch.validateBorrowed(&source);

    // A second owner of the same geometry reuses the pooled resident buffer
    // instead of allocating, and its evaluation stays exact.
    const first_contents = @intFromPtr(scratch.resident.contents);
    scratch.deinit();
    scratch = try OwnedV1.init(
        allocator,
        &runtime,
        &source,
        &.{.{
            .tree_index = 0,
            .column_index = 0,
            .trace_log_size = coefficient_log_size,
            .evaluation_log_size = evaluation_log_size,
        }},
        .{
            .root_coset = twiddles.root_coset,
            .twiddles = twiddles.twiddles,
            .itwiddles = twiddles.itwiddles,
        },
    );
    // The rejected first owner allocated (one miss) and returned its buffer
    // to the pool on the error path; both accepted owners then hit.
    const pool_after = poolSnapshot();
    try std.testing.expectEqual(first_contents, @intFromPtr(scratch.resident.contents));
    try std.testing.expectEqual(pool_before.hits + 2, pool_after.hits);
    try std.testing.expectEqual(pool_before.misses + 1, pool_after.misses);
    try std.testing.expectEqual(@as(usize, 0), pool_after.pooled);
    try std.testing.expectEqualSlices(
        M31,
        expected.values,
        scratch.trace.polys.items[0][0].values,
    );
    try scratch.validateBorrowed(&source);
}

fn cloneAllocationFixture(allocator: std.mem.Allocator) !void {
    const values = [_]M31{ M31.one(), M31.zero(), M31.one(), M31.zero() };
    const polys = [_]Poly{.{ .log_size = 2, .values = &values }};
    const trees = try allocator.dupe([]const Poly, &.{&polys});
    var source = Trace{
        .polys = core.pcs.TreeVec([]const Poly).initOwned(trees),
    };
    defer source.polys.deinit(allocator);
    var clone = try cloneTrace(allocator, &source);
    defer clone.polys.deinitDeep(allocator);
}

test "Metal composition domain scratch clone cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        cloneAllocationFixture,
        .{},
    );
}

comptime {
    if (FORMAT_VERSION != 1 or @sizeOf(M31) != 4)
        @compileError("Metal composition-domain scratch contract drifted");
}
