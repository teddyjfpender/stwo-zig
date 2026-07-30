//! Public admission, lifecycle, publication, and telemetry contracts.

const std = @import("std");

pub const ShapeKey = [32]u8;
pub const Ticket = u64;

pub const Error = error{
    CounterOverflow,
    InvalidLimits,
    InvalidState,
    RuntimeNotReady,
    ServiceBusy,
    ServicePoisoned,
    TicketOverflow,
    ThreadOwnershipViolation,
    TimeWentBackwards,
    UnsupportedExecutionLaneCount,
};

pub const Limits = struct {
    max_pending: usize,
    max_request_device_bytes: u64,
    max_queued_input_bytes: u64,
    enqueue_while_running: bool = true,

    pub fn validate(self: Limits) Error!void {
        if (self.max_pending == 0 or
            self.max_request_device_bytes == 0 or
            self.max_queued_input_bytes == 0)
        {
            return error.InvalidLimits;
        }
    }
};

/// The caller retains ownership when admission is rejected. An accepted
/// request moves into the service and is destroyed exactly once by `Workload`.
pub const RequestMetadata = struct {
    shape_key: ShapeKey,
    predicted_device_bytes: u64,
    retained_input_bytes: u64,
};

pub const Admission = union(enum) {
    accepted: Ticket,
    busy,
    queue_capacity,
    request_device_capacity,
    queued_input_capacity,
    poisoned,
    stopped,
};

pub const FailureDisposition = enum {
    /// Worker cleanup returned the runtime to ready.
    request_only,
    /// Runtime ownership is uncertain and must be relinquished.
    poison_runtime,
};

pub const Receipt = struct {
    ticket: Ticket,
    runtime_generation: u64,
    shape_key: ShapeKey,
    predicted_device_bytes: u64,
    retained_input_bytes: u64,
    runtime_init_ns: u64,
    queue_depth_at_admission: usize,
    admitted_ns: u64,
    started_ns: u64,
    finished_ns: u64,
    queue_wait_ns: u64,
    service_ns: u64,
    service_cold: bool,
    shape_cache_hit: bool,
    shape_retained_after: bool,
    poisoned_runtime: bool,
};

pub const Telemetry = struct {
    runtime_generation: u64 = 1,
    runtime_init_ns: u64,
    total_runtime_init_ns: u64,
    execution_lane_count: u32,
    admissions: u64 = 0,
    busy_rejections: u64 = 0,
    queue_capacity_rejections: u64 = 0,
    request_device_capacity_rejections: u64 = 0,
    queued_input_capacity_rejections: u64 = 0,
    poisoned_rejections: u64 = 0,
    stopped_rejections: u64 = 0,
    requests_started: u64 = 0,
    requests_completed: u64 = 0,
    requests_failed: u64 = 0,
    requests_canceled: u64 = 0,
    publications: u64 = 0,
    shape_hits: u64 = 0,
    shape_misses: u64 = 0,
    runtime_poisons: u64 = 0,
    queue_depth: usize = 0,
    queue_high_water: usize = 0,
    queued_input_bytes: u64 = 0,
    queued_input_high_water: u64 = 0,
    total_queue_wait_ns: u64 = 0,
    total_service_ns: u64 = 0,
    cold_service_ns: u64 = 0,
};

pub const PumpOutcome = union(enum) {
    completed: Ticket,
    failed: Ticket,
    poisoned: Ticket,
    unavailable_poisoned,
    idle,
    busy,
    stopped,
};

pub const AbortOutcome = enum {
    canceled,
    busy,
    too_late,
    unknown,
    stopped,
};

pub const SystemClock = struct {
    timer: std.time.Timer,

    pub fn start() !SystemClock {
        return .{ .timer = try std.time.Timer.start() };
    }

    pub fn now(self: *SystemClock) u64 {
        return self.timer.read();
    }
};
