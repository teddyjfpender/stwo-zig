//! Default-OFF CPU0 MAIN before global inventory. Local static admission is
//! mandatory, separately from whole-request/global-planner qualification.
const std = @import("std");
const Pipeline = @import("../services/pipeline.zig");
const W = @import("../services/gkr_local/worker_protocol.zig");
const engine = @import("stwo_prover_engine");
pub const FLAG = "STWO_RV64_EARLY_NATIVE_MAIN";
pub const STACK_BYTES: usize = 2 << 20;
/// One private source+MAIN-commit admission. Raw copies do not retain ownership.
/// finish_joined follows Source.releaseMain and TC completion on success, or
/// joined unpublished-owner destruction on failure. The physical phase gate
/// may then open, but retained-tree admission survives until actual final
/// worker/PCS destruction (including global-inventory rejection/abort).
pub const Ticket = struct {
    context: *anyopaque,
    finish_joined: *const fn (*anyopaque) anyerror!void,
    release_destroyed: *const fn (*anyopaque) void,
};
pub const MemoryAdmission = struct {
    context: *anyopaque,
    /// Null is unavailable, never implicitly unbudgeted for an early GPU job.
    /// The RAM/CPU0 helper reserves its explicit 2MiB stack before spawn and
    /// retains that reservation until join, using this exact budget owner.
    host_budget: ?*engine.host_budget_allocator.SharedHostBudget = null,
    /// Borrowed request header/slices are valid for this call only. Derive/copy
    /// the pinned class/cost plan now; do not retain a pointer to this frame.
    /// Reserve BEFORE CPU/JALR clone, MAIN allocation or GPU source launch.
    reserve: *const fn (*anyopaque, std.mem.Allocator, Pipeline.DeviceSourceStage.Request, W.PcsConfig) anyerror!Ticket,
};
