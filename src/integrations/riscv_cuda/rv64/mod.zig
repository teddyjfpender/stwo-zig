//! Additive RV64 numerical CUDA lane, based on PR310. Full Ethereum CUDA proof
//! dispatch remains unavailable until witness/PCS/transcript parity qualifies.
pub const plan = @import("plan.zig");
pub const scheduler = @import("scheduler.zig");
pub const resident = @import("resident.zig");
pub const production_ready = false;
test {
    _ = @import("tests/plan_test.zig");
    _ = @import("tests/scheduler_test.zig");
    _ = @import("tests/resident_test.zig");
}
