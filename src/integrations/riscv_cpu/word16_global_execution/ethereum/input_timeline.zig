//! Observation-only timelines; never serialized into proof authority.
const std = @import("std");
const C = @import("../services/gkr_local/coordinator.zig");
const SetupCache = @import("setup_cache.zig");
const Capture = @import("capture.zig").Owner;
/// block_to_inputs phase report (observation only; never proof authority).
/// Every *_at_ns is nanoseconds since gkr_main entry on the monotonic clock.
pub const BlockToInputs = struct {
    clock: []const u8 = "ns since gkr_main entry (monotonic)",
    scope: []const u8,
    init_done_at_ns: u64 = 0,
    capture_done_at_ns: u64 = 0,
    plan_done_at_ns: u64 = 0,
    keys_done_at_ns: u64 = 0,
    setup_done_at_ns: u64 = 0,
    coordinator_admitted_at_ns: u64 = 0,
    t_first_ns: u64 = 0,
    t_first_any_ns: u64 = 0,
    t_all_cpu_ns: u64 = 0,
    t_all_ns: u64 = 0,
    stages: struct { init_ns: u64 = 0, capture_import_ns: u64 = 0, plan_ns: u64 = 0, setup_ns: u64 = 0, setup_keys_ns: u64 = 0, setup_fixed_ns: u64 = 0, coordinator_admission_ns: u64 = 0 } = .{},
    segments: []const Segment = &.{},
    setup_cache: ?SetupCache.Stats = null,
    /// Capture-relative timeline (init, segment 0 / last / all inputs, ledger).
    capture: ?CaptureInputs = null,
    const Segment = struct { ordinal: usize, kind: []const u8, source_begin_at_ns: u64, source_ready_at_ns: u64, source_ns: u64 };
    pub fn finish(self: *BlockToInputs, a: std.mem.Allocator, timings: []const C.WorkerTiming, cpu_count: usize) !void {
        const segments = try a.alloc(Segment, timings.len);
        var first_any: u64 = std.math.maxInt(u64);
        for (segments, timings, 0..) |*out, t, i| {
            out.* = .{ .ordinal = i, .kind = if (i < cpu_count) "cpu" else "truth", .source_begin_at_ns = t.source_begin_ns, .source_ready_at_ns = t.source_ready_ns, .source_ns = t.source_ready_ns -| t.source_begin_ns };
            if (i < cpu_count) {
                self.t_all_cpu_ns = @max(self.t_all_cpu_ns, t.source_ready_ns);
                first_any = @min(first_any, t.source_ready_ns);
            }
            self.t_all_ns = @max(self.t_all_ns, t.source_ready_ns);
        }
        self.segments = segments;
        self.t_first_ns = if (timings.len != 0) timings[0].source_ready_ns else 0;
        self.t_first_any_ns = if (first_any == std.math.maxInt(u64)) 0 else first_any;
        self.stages = .{
            .init_ns = self.init_done_at_ns,
            .capture_import_ns = self.capture_done_at_ns -| self.init_done_at_ns,
            .plan_ns = self.plan_done_at_ns -| self.capture_done_at_ns,
            .setup_ns = self.setup_done_at_ns -| self.plan_done_at_ns,
            .setup_keys_ns = self.keys_done_at_ns -| self.plan_done_at_ns,
            .setup_fixed_ns = self.setup_done_at_ns -| self.keys_done_at_ns,
            .coordinator_admission_ns = self.coordinator_admitted_at_ns -| self.setup_done_at_ns,
        };
    }
};
/// Producer block-to-inputs timeline, nanoseconds on this CLI's clock (started
/// after request parse and pool start). Report-only; no protocol effect. On the
/// packet route it excludes the separate `nativeprepare` process.
pub const CaptureInputs = struct {
    /// Expected image + program init (and compact decode), before capture.
    init_ns: u64,
    /// Segment 0 inputs ready: captured, admitted and its ledger shard built.
    first_inputs_ns: ?u64,
    /// Last segment's ledger shard built.
    last_inputs_ns: ?u64,
    /// All segment inputs ready, including the global boundary cells.
    all_inputs_ns: u64,
    /// Serial ordered ledger, summed over segments; and its `finish`.
    ledger_ns: u64,
    ledger_finish_ns: u64,
    pub fn of(timer: *const std.time.Timer, init_ns: u64, all_ns: u64, captured: *const Capture) CaptureInputs {
        return .{ .init_ns = init_ns, .first_inputs_ns = sinceTimer(timer, captured.first_inputs_at), .last_inputs_ns = sinceTimer(timer, captured.last_inputs_at), .all_inputs_ns = all_ns, .ledger_ns = captured.timing.ledger_ns, .ledger_finish_ns = captured.timing.finish_ns };
    }
    fn sinceTimer(timer: *const std.time.Timer, at: ?std.time.Instant) ?u64 {
        return if (at) |value| value.since(timer.started) else null;
    }
};
