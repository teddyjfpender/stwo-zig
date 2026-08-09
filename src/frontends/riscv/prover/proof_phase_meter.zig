//! Allocation-free exact witness-phase timing.
//!
//! A `Meter` is single-owner state. Its borrowed `ClockSource` may be shared,
//! so the callback and context must support every concurrent caller that owns
//! a meter. The context must outlive the meter and all open region tokens.

const std = @import("std");

pub const ClockSource = struct {
    context: *anyopaque,
    now_fn: *const fn (context: *anyopaque) anyerror!u64,

    pub inline fn now(self: ClockSource) anyerror!u64 {
        return self.now_fn(self.context);
    }
};

const ActiveRegion = struct {
    generation: u64,
    start_ns: ?u64,
};

pub const Meter = struct {
    source: ?ClockSource,
    witness_ns: u64 = 0,
    last_boundary_ns: ?u64 = null,
    active: ?ActiveRegion = null,
    next_generation: u64 = 0,

    pub fn init(source: ?ClockSource) Meter {
        return .{ .source = source };
    }

    /// Opens one region. A successful enabled begin publishes its sampled
    /// boundary, but no duration is published until the matching finish.
    pub fn begin(self: *Meter) !WitnessRegion {
        if (self.active != null) return error.ProofPhaseRegionAlreadyActive;
        const generation = std.math.add(u64, self.next_generation, 1) catch
            return error.ProofPhaseGenerationOverflow;

        const start_ns: ?u64 = if (self.source) |source| sampled: {
            const now_ns = try source.now();
            if (self.last_boundary_ns) |last| {
                if (now_ns < last) return error.ProofPhaseClockRegression;
            }
            break :sampled now_ns;
        } else null;

        self.next_generation = generation;
        self.active = .{ .generation = generation, .start_ns = start_ns };
        if (start_ns) |boundary| self.last_boundary_ns = boundary;
        return .{ .meter = self, .generation = generation };
    }

    pub fn hasActiveRegion(self: *const Meter) bool {
        return self.active != null;
    }

    fn finish(self: *Meter, generation: u64) !void {
        const active = self.active orelse return error.ProofPhaseRegionNotActive;
        if (active.generation != generation) return error.ProofPhaseRegionStale;

        if (self.source) |source| {
            const start_ns = active.start_ns orelse unreachable;
            const finish_ns = try source.now();
            if (finish_ns < start_ns) return error.ProofPhaseClockRegression;
            const elapsed_ns = finish_ns - start_ns;
            const witness_ns = std.math.add(u64, self.witness_ns, elapsed_ns) catch
                return error.ProofPhaseWitnessOverflow;

            self.witness_ns = witness_ns;
            self.last_boundary_ns = finish_ns;
        } else std.debug.assert(active.start_ns == null);
        self.active = null;
    }

    fn abort(self: *Meter, generation: u64) void {
        const active = self.active orelse return;
        if (active.generation == generation) self.active = null;
    }
};

/// Linear-use handle for one region. Zig values are copyable, so meter-side
/// generations ensure copied or stale handles cannot finish or abort a newer
/// region. Do not move the meter itself while a token is open.
pub const WitnessRegion = struct {
    meter: *Meter,
    generation: u64,
    state: State = .active,

    const State = enum { active, closed };

    /// Commits the elapsed duration atomically. Every failure leaves a matching
    /// region active, allowing `errdefer region.abort()` to clean it up.
    pub fn finish(self: *WitnessRegion) !void {
        if (self.state == .closed) return error.ProofPhaseRegionClosed;
        try self.meter.finish(self.generation);
        self.state = .closed;
    }

    /// Cleanup is deliberately idempotent. A stale copied token closes only
    /// itself; the generation check prevents it from clearing a newer region.
    pub fn abort(self: *WitnessRegion) void {
        if (self.state == .closed) return;
        self.meter.abort(self.generation);
        self.state = .closed;
    }
};
