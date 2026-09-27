//! Fresh genuine OPEN root verifier. Expected original PublicData/window policy
//! must be reconstructed independently from the job's public statement. No
//! transported decoded tuple, metadata hash, or sibling receipt admits it.
const std = @import("std");
const Public = @import("block_v5_global_public_export_policy_v1.zig");
const Fields = @import("block_v5_global_public_fields_v1.zig");
const Bus = @import("block_v5_global_public_export_bus_v1.zig");
const Protocol = @import("block_v5_reusable_global_public_export_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    pub const complete_block_authority = false;
    pub const source_authorities_pending = @import("../prover/block_v5_recursive_coverage_plan_v1.zig").SOURCE_COUNT;
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
/// key/id/schedule are independently admitted setup, never file-selected. This
/// fresh call recreates B5PD framing, every expected digest coordinate, decoded
/// field and public span; Admission binds those exact expectations before PCS.
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, expected_id: [32]u8, schedule: []const Bus.Wire, independently_expected: Public.Policy, limits: Fields.Limits) !OpenEquation {
    var public = try Public.init(a, independently_expected, limits);
    defer public.deinit();
    const admission = try Protocol.Admission.init(key, expected_id, schedule, .{ .public = &public });
    return verifyAdmitted(a, bytes, &admission);
}
/// Reuses independently reconstructed public fields through fresh verification
/// and subsequent normalization. Admission and owner borrows remain immutable
/// through this call; this API still performs the original typed checks.
pub fn verifyPrepared(a: std.mem.Allocator, bytes: []const u8, admission: *const Protocol.Admission) !OpenEquation {
    try admission.validate();
    return verifyAdmitted(a, bytes, admission);
}
fn verifyAdmitted(a: std.mem.Allocator, bytes: []const u8, admission: *const Protocol.Admission) !OpenEquation {
    var proof = try Parent.codec.decode(a, bytes, admission);
    var equation = try Parent.verify(&proof, admission);
    errdefer equation.deinit();
    try equation.validate(admission, admission.expected_id);
    return .{ .equation = equation };
}
