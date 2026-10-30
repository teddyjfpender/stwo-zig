//! Detached native recursive equation receiver. This returns only OPEN source
//! exports; the block receiver must close each register window and global bus.
const std = @import("std");
const Profile = @import("block_v7_native_fixed_profile_v1.zig");
const Public = @import("block_v7_native_public_v1.zig");
const Protocol = @import("block_v7_native_parent_protocol_v1.zig");
const Source = @import("../prover/block_v7_native_source_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    open: Source.Exports,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, profile: *const Profile.Owned, claims: Public.Claims, key: Protocol.Key, wires: []const Public.Wire) !Verified {
    try profile.validate();
    // A parent proving arbitrary fixed columns is not a native verifier.
    try @import("../prover/block_v5_native_execution_proof_v3.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).verifyFixed(a, profile.pin.shape, profile.pin.template, profile.epoch.config);
    var values = try Public.reconstruct(a, profile, claims);
    defer values.deinit();
    const roster = [_]Protocol.Bus.Expected{@import("block_v7_native_fixed_roster_v1.zig").expected(profile)};
    const admission = try Protocol.Admission.init(key, try key.identity(), wires, .{ .children = &.{values} }, &roster);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, try key.identity());
    const drawn = try profile.epoch.draw(a);
    const open = try Source.exportsFromClaims(a, profile.pin, claims.projection, claims.access, &drawn);
    return .{ .equation = equation, .open = open };
}
