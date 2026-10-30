//! Detached joint-memory parent verification from independently rebuilt public
//! frames and a separately selected expected key. No base proof files or live
//! producer rows are consulted. The return is an OPEN memory relation only.
const std = @import("std");
const Profile = @import("block_v7_memory_joint_fixed_profile_v1.zig");
const Public = @import("block_v7_memory_joint_public_v1.zig");
const Protocol = @import("block_v7_memory_joint_parent_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    open: @import("../prover/block_v7_memory_joint_protocol_v1.zig").Open,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, independently_selected: *const Profile.Owned, expected_key: Protocol.Key, wires: []const Public.Wire) !Verified {
    const geometries = try a.alloc(@import("../prover/block_v5_ram_lanes_protocol_v1.zig").Claim, independently_selected.input.claims.ram.len);
    defer a.free(geometries);
    for (geometries, independently_selected.input.claims.ram) |*g, claim| g.* = claim.geometry;
    try @import("../prover/block_v7_memory_joint_proof_v1.zig").For(@import("stwo_cpu_backend").CpuBackend).requireFixedRoot(a, independently_selected.input.policy, geometries, independently_selected.input.interval_log, independently_selected.input.roots[0], .{});
    var values = try Public.reconstruct(a, independently_selected);
    defer values.deinit();
    const roster = [_]Protocol.Bus.Expected{.{ .profile = independently_selected.seal, .epoch = independently_selected.input.epoch.digest, .roots = independently_selected.input.roots }};
    const admission = try Protocol.Admission.init(expected_key, try expected_key.identity(), wires, .{ .children = &.{values} }, &roster);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, try expected_key.identity());
    const open = try @import("../prover/block_v7_memory_joint_protocol_v1.zig").closeVerifiedClaims(independently_selected.input.claims);
    return .{ .equation = equation, .open = open };
}
