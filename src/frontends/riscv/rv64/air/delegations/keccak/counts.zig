//! Post-construction native lookup counts. One retained tuple/index authority
//! feeds private worker histograms; only a completely checked merge is returned.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Shared = @import("../../providers/native_fill.zig");
const M = core.fields.m31.M31;
const L = @import("layout.zig");
const T = @import("trace.zig");
const physical = @import("../../witness.zig").physical;
const tables = @import("../../../../air/guest_precompile/keccakf_tables.zig");
const tuple_algebra = @import("../../../../air/guest_precompile/keccakf_lookup_tuples.zig");
const work = engine.work_pool;
pub const HISTOGRAM_BYTES_PER_WORKER: usize = (8192 + 1024) * @sizeOf(u64);
pub const Profile = struct { workers: usize = 1, round_rows: u64 = 0, chi_queries: u64 = 0, xor5_queries: u64 = 0 };
pub const Options = struct { pool: ?*work.WorkPool = null, allocator: ?std.mem.Allocator = null, profile: ?*Profile = null };
pub const Counts = struct {
    chi: [8192]u64 = @splat(0),
    xor5: [1024]u64 = @splat(0),
    pub fn fromTrace(trace: *const T.Trace) !Counts {
        return fromTraceWithOptions(trace, .{ .pool = work.currentScopedPool() });
    }
    pub fn fromTraceWithOptions(trace: *const T.Trace, options: Options) !Counts {
        return countImpl(trace, options, null);
    }
    /// Explicit serial control uses the same row/tuple/index computation.
    pub fn serial(trace: *const T.Trace) !Counts {
        try trace.validateMetadata();
        return serialValidated(trace);
    }
    fn serialValidated(trace: *const T.Trace) !Counts {
        var result = Counts{};
        try addRange(trace, 0, trace.metadata.len, &result.chi, &result.xor5);
        return result;
    }
    fn countImpl(trace: *const T.Trace, options: Options, fail_after: ?usize) !Counts {
        try trace.validateMetadata();
        if (options.profile) |p| p.* = .{};
        const n: usize = trace.metadata.len;
        const workers = if (options.pool) |p| @min(p.workerCount(), @max(1, n / 4096)) else 1;
        if (workers == 1) {
            const result = try serialValidated(trace);
            if (options.profile) |p| {
                for (result.chi) |v| p.chi_queries += v;
                for (result.xor5) |v| p.xor5_queries += v;
                p.round_rows = p.chi_queries / L.STATE;
            }
            return result;
        }
        // This scan preserves the existing native gate exactly, including
        // arbitrary retained flags/fixed values used by adversarial controls.
        var active_rows: u64 = 0;
        for (0..n) |logical| {
            if (trace.metadata[logical].flags & 1 == 0) continue;
            const r = physical(logical, trace.log_size);
            for (0..24) |round| if (!trace.fixed[(2 + round) * trace.size() + r].isZero()) {
                active_rows += 1;
                break;
            };
        }
        const mass: [2]u64 = .{ try std.math.mul(u64, active_rows, L.STATE), try std.math.mul(u64, active_rows, L.PARITY) };
        if (options.profile) |p| p.* = .{ .workers = workers, .round_rows = active_rows, .chi_queries = mass[0], .xor5_queries = mass[1] };
        if (active_rows == 0) {
            if (options.profile) |p| p.workers = 1;
            return .{};
        }
        var failure = std.atomic.Value(u16).init(0);
        const context = CountContext{ .trace = trace, .failure = &failure };
        var result = Counts{};
        const a = options.allocator orelse trace.allocator;
        const produced = if (comptime builtin.is_test) if (fail_after) |after|
            Shared.testing.failSubmission(Adapter, a, context, n, .{ &result.chi, &result.xor5 }, mass, options.pool.?, after)
        else
            Shared.fill(Adapter, a, context, n, .{ &result.chi, &result.xor5 }, mass, options.pool) else Shared.fill(Adapter, a, context, n, .{ &result.chi, &result.xor5 }, mass, options.pool);
        produced catch |err| {
            if (failure.load(.acquire) != 0) return @errorFromInt(failure.load(.acquire));
            if (err == error.WorkerBudgetUnavailable) {
                if (options.profile) |p| p.workers = 1;
                return serialValidated(trace);
            }
            return err;
        };
        if (failure.load(.acquire) != 0) return @errorFromInt(failure.load(.acquire));
        return result;
    }
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
            for (0..L.STATE) |event| {
                const tuple = tuple_algebra.chi(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], next[0..L.STATE], &selectors, event);
                const index = try tables.index(.chi, &tuple);
                chi[index] += 1;
            }
            for (0..L.PARITY) |event| {
                const tuple = tuple_algebra.xor5(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], event);
                const index = try tables.index(.xor5, &tuple);
                xor5[index] += 1;
            }
        }
    }
    pub const testing = if (builtin.is_test) struct {
        pub fn failSubmission(trace: *const T.Trace, options: Options, after: usize) !Counts {
            return countImpl(trace, options, after);
        }
    } else struct {};
};
const CountContext = struct { trace: *const T.Trace, failure: *std.atomic.Value(u16) };
const Adapter = struct {
    pub const BINS = [_]usize{ 8192, 1024 };
    pub const Context = CountContext;
    pub fn prepare(_: Context) void {}
    pub fn rows(context: Context, start: usize, end: usize, counts: []u64) void {
        Counts.addRange(context.trace, start, end, counts[0..8192], counts[8192..]) catch |err| {
            _ = context.failure.cmpxchgStrong(0, @intFromError(err), .release, .monotonic);
        };
    }
};
