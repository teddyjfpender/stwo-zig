//! Execution session options and borrowed diagnostic observer contracts.
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const trace = @import("trace.zig");
const memory_state = @import("memory_state.zig");
const state_chain = @import("state_chain.zig");
const HostInterface = @import("../host/interface.zig").HostInterface;
const SegmentClockFrame = @import("result.zig").SegmentClockFrame;

/// Controls whether a resumable session retains the whole execution trace or
/// transfers each completed range directly to its `SegmentResult`.
///
/// `cumulative` preserves the original diagnostic surface. `segment_owned`
/// is the bounded-memory production path: after every yielded segment the
/// session retains only the clock origin needed to admit the next row.
pub const TraceRetention = enum { cumulative, segment_owned };

/// Optional diagnostic observer invoked only after typed core retirement has
/// committed. The callback cannot influence proof bytes or instruction
/// semantics; any error poisons the owning execution session before a segment
/// can be published.
pub const RetirementObserverV1 = struct {
    context: *anyopaque,
    begin_segment_fn: *const fn (*anyopaque, u32) anyerror!void,
    core_row_fn: *const fn (*anyopaque, trace.TraceRow) anyerror!void,

    pub fn beginSegment(self: RetirementObserverV1, segment_index: u32) !void {
        return self.begin_segment_fn(self.context, segment_index);
    }

    pub fn observeCoreRow(
        self: RetirementObserverV1,
        row: trace.TraceRow,
    ) !void {
        return self.core_row_fn(self.context, row);
    }
};

/// Optional, versioned view of the exact architectural boundary immediately
/// before one decoded core instruction retires. All execution-owned state is
/// borrowed as const: observers may derive diagnostic custody, but cannot
/// mutate the guest, reserve transitions, or alter retirement ordering.
pub const PreRetirementBoundaryV1 = struct {
    execution_clock: u32,
    cpu: *const Cpu,
    memory: *const Memory,
    memory_layout: memory_state.MemoryLayout,
    state_chain_tracker: *const state_chain.StateChainTracker,
};

/// Candidate/diagnostic-only pre-retirement observer. The default-null route
/// performs no call and preserves the existing post-retirement observer order.
pub const PreRetirementBoundaryObserverV1 = struct {
    context: *anyopaque,
    observe_fn: *const fn (
        *anyopaque,
        PreRetirementBoundaryV1,
    ) anyerror!void,

    pub fn observe(
        self: PreRetirementBoundaryObserverV1,
        boundary: PreRetirementBoundaryV1,
    ) !void {
        return self.observe_fn(self.context, boundary);
    }
};

pub const SessionOptions = struct {
    host: ?HostInterface = null,
    input: []const u8 = &.{},
    stop_on_halt_flag: bool = false,
    strict_completion: bool = false,
    trace_retention: TraceRetention = .cumulative,
    clock_frame: SegmentClockFrame = .global_continuous,
    retirement_observer: ?RetirementObserverV1 = null,
    pre_retirement_boundary_observer: ?PreRetirementBoundaryObserverV1 = null,
};
