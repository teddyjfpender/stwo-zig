//! Throughput-v1 table multiplicities (2^21 chi, 2^16 xor5) for a finished
//! permutation trace. Same row gate as the compact counts (`counts.zig`); the
//! tuple is the AIR's `E.throughputTupleFor` and the index is the RV32 table
//! authority's exact inverse, so an out-of-table query fails here first.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Shared = @import("../../providers/native_fill.zig");
const M = core.fields.m31.M31;
const L = @import("layout.zig");
const E = @import("equations.zig");
const T = @import("trace.zig");
const physical = @import("../../witness.zig").physical;
const tables = @import("../../../../air/guest_precompile/keccakf_throughput_tables_v1.zig");
const work = engine.work_pool;
const P = E.BatchPolicy.throughput_v1;
pub const CHI_ROWS: usize = 1 << 21;
pub const XOR5_ROWS: usize = 1 << 16;
pub const Options = struct { pool: ?*work.WorkPool = null };
pub const Counts = struct {
    allocator: std.mem.Allocator,
    chi: []u64,
    xor5: []u64,
    pub fn fromTrace(a: std.mem.Allocator, trace: *const T.Trace) !Counts {
        return fromTraceWithOptions(a, trace, .{ .pool = work.currentScopedPool() });
    }
    pub fn fromTraceWithOptions(a: std.mem.Allocator, trace: *const T.Trace, options: Options) !Counts {
        try trace.validateMetadata();
        const chi = try a.alloc(u64, CHI_ROWS);
        errdefer a.free(chi);
        const xor5 = try a.alloc(u64, XOR5_ROWS);
        errdefer a.free(xor5);
        @memset(chi, 0);
        @memset(xor5, 0);
        const n: usize = trace.metadata.len;
        const workers = if (options.pool) |p| @min(p.workerCount(), @max(1, n / 4096)) else 1;
        if (workers == 1) {
            try addRange(trace, 0, n, chi, xor5);
        } else {
            var active_rows: u64 = 0;
            for (0..n) |logical| {
                if (trace.metadata[logical].flags & 1 == 0) continue;
                const r = physical(logical, trace.log_size);
                for (0..24) |round| if (!trace.fixed[(2 + round) * trace.size() + r].isZero()) {
                    active_rows += 1;
                    break;
                };
            }
            if (active_rows != 0) {
                const mass: [2]u64 = .{ try std.math.mul(u64, active_rows, P.chiLookups()), try std.math.mul(u64, active_rows, P.xor5Lookups()) };
                var failure = std.atomic.Value(u16).init(0);
                Shared.fill(Adapter, a, .{ .trace = trace, .failure = &failure }, n, .{ chi, xor5 }, mass, options.pool) catch |err| {
                    if (failure.load(.acquire) != 0) return @errorFromInt(failure.load(.acquire));
                    if (err != error.WorkerBudgetUnavailable) return err;
                    @memset(chi, 0);
                    @memset(xor5, 0);
                    try addRange(trace, 0, n, chi, xor5);
                };
                if (failure.load(.acquire) != 0) return @errorFromInt(failure.load(.acquire));
            }
        }
        return .{ .allocator = a, .chi = chi, .xor5 = xor5 };
    }
    pub fn deinit(self: *Counts) void {
        self.allocator.free(self.chi);
        self.allocator.free(self.xor5);
        self.* = undefined;
    }
};
fn addRange(trace: *const T.Trace, start: usize, end: usize, chi: []u64, xor5: []u64) !void {
    const n = trace.size();
    for (start..end) |logical| {
        const r = physical(logical, trace.log_size);
        var selectors: [24]M = undefined;
        var active = false;
        for (&selectors, 0..) |*s, i| {
            s.* = trace.fixed[(2 + i) * n + r];
            active = active or !s.isZero();
        }
        active = active and (trace.metadata[logical].flags & 1 != 0);
        if (!active) continue;
        const main = try trace.metadataRow(logical);
        const next = try trace.metadataRow((logical + 1) % n);
        for (0..P.lookups()) |event| {
            const tuple = E.throughputTupleFor(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], next[0..L.STATE], &selectors, event);
            if (event < P.chiLookups()) chi[try tables.index(.chi, &tuple)] += 1 else xor5[try tables.index(.xor5, &tuple)] += 1;
        }
    }
}
const CountContext = struct { trace: *const T.Trace, failure: *std.atomic.Value(u16) };
const Adapter = struct {
    pub const BINS = [_]usize{ CHI_ROWS, XOR5_ROWS };
    pub const Context = CountContext;
    pub fn prepare(_: CountContext) void {}
    pub fn rows(context: CountContext, start: usize, end: usize, counts: []u64) void {
        addRange(context.trace, start, end, counts[0..CHI_ROWS], counts[CHI_ROWS..]) catch |err| {
            _ = context.failure.cmpxchgStrong(0, @intFromError(err), .release, .monotonic);
        };
    }
};
