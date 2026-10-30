//! Fresh compact lookup parent verification with an independently selected lookup policy
//! and expected key. The result is an OPEN six native lookup relations only.
const std = @import("std");
const Profile = @import("block_v7_lookup_compact_fixed_profile_v1.zig");
const Public = @import("block_v7_lookup_compact_public_v1.zig");
const Protocol = @import("block_v7_lookup_compact_parent_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Native = @import("../prover/block_v7_lookup_compact_proof_v1.zig");
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    open: Native.Verified,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, selected: *const Profile.Owned, key: Protocol.Key, wires: []const Public.Wire) !Verified {
    try Native.For(@import("stwo_cpu_backend").CpuBackend).requireFixedRoots(a, selected.input.policy, .{});
    var values = try Public.reconstruct(a, selected);
    defer values.deinit();
    const expected = [_]Protocol.Bus.Expected{.{ .profile = selected.seal, .epoch = selected.input.policy.epoch.digest, .roots = selected.input.policy.roots }};
    const admission = try Protocol.Admission.init(key, try key.identity(), wires, .{ .children = &.{values} }, &expected);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, try key.identity());
    return .{ .equation = equation, .open = .{ .epoch = selected.input.policy.epoch.digest, .plan = try selected.input.policy.plan.identity(), .roots = selected.input.policy.roots, .layout = selected.input.policy.layout.digest, .claims = selected.input.claims } };
}
