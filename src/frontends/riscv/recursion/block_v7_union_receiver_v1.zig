//! Detached joined recursive receiver. Independent metadata reconstructs the
//! original equations, public wire values and exact global closure. A producer
//! capture, source STARK, live witness or successful producer receipt is unused.
const std = @import("std");
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Public = @import("block_v7_union_public_v1.zig");
const Protocol = @import("block_v7_union_parent_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Closure = @import("../prover/block_v7_window_union_public_closure_v1.zig");
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    summary: Closure.Summary,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn expected(profile: *const Profile.Owned) !Protocol.Bus.Expected {
    return .{ .profile = profile.seal, .epoch = profile.statement.input.epoch.digest, .root_count = @intCast(try @import("air/block_v7_union_transcript_v1.zig").firstInteraction(profile)) };
}
/// The key and wire schedule are independently derived trusted policy. A
/// received envelope must never nominate either as its own authority.
pub fn verifyAgainstKey(a: std.mem.Allocator, bytes: []const u8, profile: *const Profile.Owned, claims: *const Multi.Claims, key: Protocol.Key, wires: []const Public.Wire) !Verified {
    try profile.validateAgainst(claims);
    var values = try Public.reconstruct(a, profile, claims);
    defer values.deinit();
    const roster = [_]Protocol.Bus.Expected{try expected(profile)};
    const admission = try Protocol.Admission.init(key, try key.identity(), wires, .{ .children = &.{values} }, &roster);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, try key.identity());
    var components = try Multi.AdmittedComponents.init(a, profile.statement.trusted, profile.statement.input, claims, profile.limits.original);
    defer components.deinit();
    const summary = try Closure.close(a, &components, profile.statement.input, claims);
    return .{ .equation = equation, .summary = summary };
}
/// Complete fresh setup entry point: no serialized key/schedule is trusted.
pub fn verify(a: std.mem.Allocator, bytes: []const u8, profile: *const Profile.Owned, claims: *const Multi.Claims, capacity: u32, parent_profile: @import("blake3_execution_parent_protocol.zig").Profile, limits: @import("block_v7_union_fixed_roster_v1.zig").Limits) !Verified {
    return verifyStatement(a, bytes, profile.statement, claims, profile.limits, capacity, parent_profile, limits);
}
pub fn verifyStatement(a: std.mem.Allocator, bytes: []const u8, statement: *const @import("../prover/block_v7_multi_union_statement_v1.zig").ForMode(true).Owned, claims: *const Multi.Claims, original: Profile.Limits, capacity: u32, parent_profile: @import("blake3_execution_parent_protocol.zig").Profile, limits: @import("block_v7_union_fixed_roster_v1.zig").Limits) !Verified {
    const capsule = try @import("block_v7_union_compiler_capsule_v1.zig").Capsule.derive(a, statement, claims, original);
    defer capsule.deinit();
    const profile = capsule.profile();
    var cold = try @import("block_v7_union_fixed_roster_v1.zig").Owned.deriveFromCapsule(a, capsule, capacity, limits);
    defer cold.deinit();
    const geometry = try Parent.ForBackend(@import("stwo_cpu_backend").CpuBackend).deriveKeyFromFixed(a, cold.fixed, cold.context, parent_profile);
    const roster = [_]Protocol.Bus.Expected{try expected(profile)};
    const key = try Protocol.Key.fromGeometry(geometry, cold.wires, &roster);
    var values = try capsule.values(a);
    defer values.deinit();
    const admission = try Protocol.Admission.init(key, try key.identity(), cold.wires, .{ .children = &.{values} }, &roster);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, try key.identity());
    const summary = try Closure.close(a, &capsule.compiler().admission.components, profile.statement.input, &capsule.compiler().claims);
    return .{ .equation = equation, .summary = summary };
}
