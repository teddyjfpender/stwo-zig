//! Checked resource and work declarations for structured prover tasks.

const std = @import("std");

/// Every task declares all five ADR-0027 byte classes. Resident classes are
/// admitted once for the epoch; exclusive scratch is backpressured per wave;
/// worker-stack requirements are checked against the pool's configured stack.
pub const ResourceReservation = struct {
    final_output_bytes: usize = 0,
    exclusive_scratch_bytes: usize = 0,
    shared_resident_bytes: usize = 0,
    device_resident_bytes: usize = 0,
    worker_stack_bytes: usize = 0,

    pub fn residentBytes(self: ResourceReservation) !usize {
        var total = std.math.add(
            usize,
            self.final_output_bytes,
            self.shared_resident_bytes,
        ) catch return error.ResourceReservationOverflow;
        total = std.math.add(
            usize,
            total,
            self.device_resident_bytes,
        ) catch return error.ResourceReservationOverflow;
        return total;
    }
};

/// Multiplies static integer factors without saturation or timing feedback.
pub fn checkedWorkEstimate(factors: []const u64) !u64 {
    if (factors.len == 0) return 0;
    var estimate: u64 = 1;
    for (factors) |factor| {
        estimate = std.math.mul(u64, estimate, factor) catch
            return error.WorkEstimateOverflow;
    }
    return estimate;
}
