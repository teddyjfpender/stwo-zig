//! Fresh ROM parent verification with an independently selected program policy
//! and expected key. The result is an OPEN program-fetch relation only.
const std = @import("std");
const Profile = @import("block_v7_program_fixed_profile_v1.zig");
const Public = @import("block_v7_program_public_v1.zig");
const Protocol = @import("block_v7_program_parent_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Native = @import("../prover/block_v7_program_provider_v1.zig");
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    open: Native.Verified,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, selected: *const Profile.Owned, key: Protocol.Key, wires: []const Public.Wire) !Verified {
    try Native.ForBackend(@import("stwo_cpu_backend").CpuBackend).requireFixedRoots(a, selected.input.policy);
    var values = try Public.reconstruct(a, selected);
    defer values.deinit();
    const expected = [_]Protocol.Bus.Expected{.{ .profile = selected.seal, .epoch = selected.input.policy.epoch.digest, .roots = selected.input.policy.roots }};
    const admission = try Protocol.Admission.init(key, try key.identity(), wires, .{ .children = &.{values} }, &expected);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, try key.identity());
    return .{ .equation = equation, .open = .{ .epoch = selected.input.policy.epoch.digest, .plan = try selected.input.policy.plan.digest(), .roots = selected.input.policy.roots, .claim = selected.input.claim, .fetch_count = selected.input.policy.plan.expected_fetches } };
}
