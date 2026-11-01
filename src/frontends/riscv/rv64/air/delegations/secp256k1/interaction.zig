//! Batch-inverted, row-chunk parallel secp truth interaction witness.
//!
//! Exact field-element equivalent of the scalar reference recipe in
//! trace.zig: every BYTE term is 1/(z - b) for b in [0, 256), so it comes from
//! one 256-entry inverse dictionary; the three Wire35 terms per row are
//! batch-inverted over bounded row blocks. Field addition is exact, so the
//! chunk-relative prefixes plus a stable logical-chunk offset reproduce the
//! serial running sum value-for-value.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const P = L.P;
const E = @import("equations.zig");
const T = @import("trace.zig");
const physical = @import("../../witness.zig").physical;
const work = engine.work_pool;

pub const MIN_STACK: usize = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub const MIN_ROWS_PER_WORKER: usize = 64;
/// Rows per wire batch inversion: 3 * 32 = 96 denominators keeps the packed
/// QM31 Montgomery path (multiple of 32) on aarch64.
const BLOCK_ROWS: usize = 32;
const CORRECTION_ROWS: usize = 256;
const BYTES: usize = 32;

/// Where a metadata-row column value comes from (see Trace.metadataRow).
const Source = union(enum) { zero, active, id, byte: u16 };

pub const Prepared = struct {
    trace: *const T.Trace,
    data: []M,
    /// 1/(z - b); `byte_zero[b]` marks z == b (scalar recipe: DivisionByZero).
    byte_inverse: [256]Q,
    byte_zero: [256]bool,
    /// offset - c0 * program tag, shared by all three wire events.
    wire_base: Q,
    wire: E.Wire,
    /// Main sources for the 32 tuple bytes of each event.
    wire_bytes: [3][BYTES]Source,
    /// Main source of the call-id tuple slot.
    id_source: Source,
    active_source: Source,
    /// Lookup-byte index read by each BYTE term (identity in every layout).
    byte_sources: []const Source,

    fn sourceValue(source: Source, active_row: bool, id: M, bytes: []const u8) M {
        if (!active_row) return M.zero();
        return switch (source) {
            .zero => M.zero(),
            .active => M.one(),
            .id => id,
            .byte => |i| M.fromCanonical(bytes[i]),
        };
    }

    /// Chunk-relative running sums for logical rows [start, end).
    pub fn fillRange(self: *const Prepared, start: usize, end: usize) !Q {
        const trace = self.trace;
        const n = trace.size();
        const kind = trace.kind;
        const per = trace.program.rows(kind == .product);
        const active_rows = @as(usize, trace.calls) * per;
        const count = L.byteCount(kind);
        const batches = L.batches(kind);
        var sum = Q.zero();
        var denominators: [3 * BLOCK_ROWS]Q = undefined;
        var inverses: [3 * BLOCK_ROWS]Q = undefined;
        var coefficients: [3 * BLOCK_ROWS]M = undefined;
        var block = start;
        while (block < end) : (block += BLOCK_ROWS) {
            const rows: usize = @min(BLOCK_ROWS, end - block);
            for (0..rows) |local| {
                const logical = block + local;
                const r = physical(logical, trace.log_size);
                const active_row = logical < active_rows;
                const bytes: []const u8 = if (active_row) trace.lookup_bytes[logical * count ..][0..count] else &.{};
                const id = if (active_row) M.fromCanonical(@intCast(@as(usize, trace.first_id) + logical / per)) else M.zero();
                const active = sourceValue(self.active_source, active_row, id, bytes);
                const tuple_id = sourceValue(self.id_source, active_row, id, bytes);
                inline for (0..3) |event| {
                    const fixed_id = trace.fixed[(switch (event) {
                        0 => L.LHS_ID,
                        1 => L.RHS_ID,
                        else => L.RESULT_ID,
                    }) * n + r];
                    var d = self.wire_base.sub(self.wire.coefficients[1].mulM31(tuple_id)).sub(self.wire.coefficients[2].mulM31(fixed_id));
                    for (self.wire_bytes[event], self.wire.coefficients[3..]) |source, c| d = d.sub(c.mulM31(sourceValue(source, active_row, id, bytes)));
                    if (d.isZero()) return error.DivisionByZero;
                    denominators[3 * local + event] = d;
                    coefficients[3 * local + event] = active.mul(switch (event) {
                        0 => trace.fixed[L.LHS_WIRE * n + r].neg(),
                        1 => trace.fixed[L.RHS_WIRE * n + r].neg(),
                        else => trace.fixed[L.USES * n + r],
                    });
                }
            }
            try core.fields.batchInverseInPlace(Q, denominators[0 .. 3 * rows], inverses[0 .. 3 * rows]);
            for (0..rows) |local| {
                const logical = block + local;
                const r = physical(logical, trace.log_size);
                const active_row = logical < active_rows;
                const bytes: []const u8 = if (active_row) trace.lookup_bytes[logical * count ..][0..count] else &.{};
                const id = if (active_row) M.fromCanonical(@intCast(@as(usize, trace.first_id) + logical / per)) else M.zero();
                for (0..batches) |batch| {
                    if (batch + 1 == batches) {
                        for (0..3) |event| sum = sum.add(inverses[3 * local + event].mulM31(coefficients[3 * local + event]));
                    } else {
                        for (0..3) |j| {
                            const index = 3 * batch + j;
                            if (index < count) {
                                const value = sourceValue(self.byte_sources[index], active_row, id, bytes);
                                if (value.v > 255) return error.InvalidSecpByte;
                                if (self.byte_zero[value.v]) return error.DivisionByZero;
                                sum = sum.add(self.byte_inverse[value.v]);
                            }
                        }
                    }
                    store(self.data, n, r, batch, sum);
                }
            }
        }
        return sum;
    }
};

fn store(data: []M, n: usize, row: usize, secure_column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(4 * secure_column + c) * n + row] = v;
}

/// Metadata-row column sources in Trace.metadataRow overwrite order.
fn columnSources(a: std.mem.Allocator, kind: L.Kind) ![]Source {
    const sources = try a.alloc(Source, L.main(kind));
    @memset(sources, .zero);
    for (0..L.byteCount(kind)) |i| sources[T.byteColumn(kind, i)] = .{ .byte = @intCast(i) };
    sources[0] = .active;
    sources[L.base(kind)] = .id;
    return sources;
}

pub fn generate(trace: *T.Trace, ch: E.Challenges, pool: ?*work.WorkPool) !Q {
    if (trace.interaction.len != 0) return error.SecpInteractionAlreadyGenerated;
    try trace.validateMetadata();
    const n = trace.size();
    const kind = trace.kind;
    const a = trace.allocator;
    const columns = try columnSources(a, kind);
    defer a.free(columns);
    const byte_sources = try a.alloc(Source, L.byteCount(kind));
    defer a.free(byte_sources);
    for (byte_sources, 0..) |*v, i| v.* = columns[T.byteColumn(kind, i)];

    var prepared: Prepared = .{
        .trace = trace,
        .data = &.{},
        .byte_inverse = undefined,
        .byte_zero = @splat(false),
        .wire_base = ch.wire.offset.sub(ch.wire.coefficients[0].mulM31(M.fromCanonical(@intFromEnum(trace.program.kind)))),
        .wire = ch.wire,
        .wire_bytes = undefined,
        .id_source = columns[L.base(kind)],
        .active_source = columns[0],
        .byte_sources = byte_sources,
    };
    for (0..3) |event| {
        const offset = if (kind == .product) switch (event) {
            0 => L.mul.Layout.lhs,
            1 => L.mul.Layout.rhs,
            else => L.mul.Layout.result,
        } else switch (event) {
            0 => L.linear.Layout.lhs,
            1 => L.linear.Layout.rhs,
            else => L.linear.Layout.result,
        };
        for (&prepared.wire_bytes[event], 0..) |*v, k| v.* = columns[offset + k];
    }
    {
        var denominators: [256]Q = undefined;
        for (&denominators, 0..) |*d, b| {
            d.* = ch.bytes.sub(Q.fromBase(M.fromCanonical(@intCast(b))));
            if (d.isZero()) {
                prepared.byte_zero[b] = true;
                d.* = Q.one();
            }
        }
        try core.fields.batchInverseInPlace(Q, &denominators, &prepared.byte_inverse);
    }

    const workers = try workerCount(n, pool);
    const data = try a.alloc(M, L.interaction(kind) * n);
    errdefer a.free(data);
    prepared.data = data;
    const sum = if (workers == 1) try prepared.fillRange(0, n) else blk: {
        @import("../../native_output_pages.zig").prepare(data);
        break :blk try generateParallel(&prepared, pool.?, workers);
    };
    trace.interaction = data;
    return sum;
}

pub fn workerCount(n: usize, pool: ?*work.WorkPool) !usize {
    const active = pool orelse return 1;
    const workers = @min(active.workerCount(), work.MAX_WORKERS, @max(1, n / MIN_ROWS_PER_WORKER));
    if (workers > 1 and active.stackSize() < MIN_STACK) return error.InvalidSecpInteractionWorkerStack;
    return workers;
}

fn generateParallel(prepared: *const Prepared, pool: *work.WorkPool, workers: usize) !Q {
    std.debug.assert(workers > 1 and workers <= work.MAX_WORKERS);
    var lease = try pool.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    const n = prepared.trace.size();
    var jobs: [work.MAX_WORKERS]Prefix = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .prepared = prepared, .start = n * i / workers, .end = n * (i + 1) / workers };
    {
        var group: std.Thread.WaitGroup = .{};
        defer {
            group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers]) |*job| try lease.spawnWg(&group, Prefix.run, .{job});
        jobs[0].run();
    }
    // Stable logical chunk order fixes both the claim and the offsets.
    var offsets: [work.MAX_WORKERS]Q = undefined;
    var claim = Q.zero();
    for (jobs[0..workers], offsets[0..workers]) |job, *offset| {
        if (job.err) |err| return err;
        offset.* = claim;
        claim = claim.add(job.sum);
    }
    const batches = L.batches(prepared.trace.kind);
    var corrections: [work.MAX_WORKERS]Correction = undefined;
    for (corrections[0..workers], 0..) |*job, i| job.* = .{ .prepared = prepared, .offsets = &offsets, .workers = workers, .start = batches * i / workers, .end = batches * (i + 1) / workers };
    {
        var group: std.Thread.WaitGroup = .{};
        defer {
            group.wait();
            lease.completeWave();
        }
        for (corrections[1..workers]) |*job| try lease.spawnWg(&group, Correction.run, .{job});
        corrections[0].run();
    }
    return claim;
}

const Prefix = struct {
    prepared: *const Prepared,
    start: usize,
    end: usize,
    sum: Q = Q.zero(),
    err: ?anyerror = null,
    fn run(self: *Prefix) void {
        self.sum = self.prepared.fillRange(self.start, self.end) catch |err| {
            self.err = err;
            return;
        };
    }
};

const Correction = struct {
    prepared: *const Prepared,
    offsets: *const [work.MAX_WORKERS]Q,
    workers: usize,
    start: usize,
    end: usize,
    fn run(self: *Correction) void {
        const trace = self.prepared.trace;
        const n = trace.size();
        // Disjoint secure-column groups per worker; streamed physical tiles.
        var delta: [4][CORRECTION_ROWS]M = undefined;
        var begin: usize = 0;
        while (begin < n) : (begin += CORRECTION_ROWS) {
            const count: usize = @min(CORRECTION_ROWS, n - begin);
            for (0..count) |r| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(begin + r, trace.log_size), trace.log_size);
                // Inverse of [floor(n*i/W), floor(n*(i+1)/W)).
                const chunk = ((logical + 1) * self.workers - 1) / n;
                const limbs = self.offsets[chunk].toM31Array();
                for (0..4) |c| delta[c][r] = limbs[c];
            }
            for (self.start..self.end) |batch| for (0..4) |c| {
                const column = self.prepared.data[(4 * batch + c) * n + begin ..][0..count];
                for (column, delta[c][0..count]) |*value, offset| value.* = value.add(offset);
            };
        }
    }
};
