//! Receiver-owned correctness/cost profiles for the OP-only P2 workstream.
//! No production selector admits these constructions. Query strength alone
//! is not a composed security certificate; see the bounded review document.
const std = @import("std");
const core = @import("stwo_core");
pub const Profile = enum {
    reference_b2_q24_p0,
    op_target_b4_q72_p0_fold4_v1,
    op_control_b2_q144_p0_fold4_v1,
    pub fn config(self: Profile) core.pcs.PcsConfig {
        var fri = core.fri.FriConfig.init(0, if (self == .op_target_b4_q72_p0_fold4_v1) 2 else 1, switch (self) {
            .reference_b2_q24_p0 => 24,
            .op_target_b4_q72_p0_fold4_v1 => 72,
            .op_control_b2_q144_p0_fold4_v1 => 144,
        }) catch unreachable;
        if (self != .reference_b2_q24_p0) fri.fold_step = 4;
        return .{ .pow_bits = 0, .fri_config = fri };
    }
    pub fn domain(self: Profile) []const u8 {
        return switch (self) {
            .reference_b2_q24_p0 => "stwo/rv64/p2-five-roster/reference-om31-v2/classic-logup/v1\x00",
            .op_target_b4_q72_p0_fold4_v1 => "stwo/opstack/p2-five-roster/target-b4-q72-p0-fold4/v1\x00",
            .op_control_b2_q144_p0_fold4_v1 => "stwo/opstack/p2-five-roster/control-b2-q144-p0-fold4/v1\x00",
        };
    }
};
pub const production_admission_open = false;
pub const security_qualified = false;
pub const security_label = "128-bit security target under documented assumptions";

/// Benchmark control of this unadmitted prototype, never a crypto selector.
/// Both schedules must produce identical roots, transcript and proof bytes.
pub fn monolithicControl() !bool {
    const value = std.posix.getenv("STWO_OP_P2_MONOLITHIC_CONTROL") orelse return false;
    if (value.len == 0 or std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidOpPoseidonCommitControl;
}
