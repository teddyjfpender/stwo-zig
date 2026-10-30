//! Strategy-based shared parent verifier; no original equations duplicated.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return With(@import("block_v8_endpoint_recursive_adapter_v1.zig").For(family));
}
pub fn With(comptime Adapter: type) type {
    return struct {
        // Fresh receiver reconstructs the verifier from independently admitted B8
        // metadata, authenticates all original equations and their symbolic ledger.
        const std = @import("std");
        const Profile = Adapter.Profile;
        const Public = Adapter.Public;
        const Protocol = Adapter.Protocol;
        const Parent = @import("blake3_execution_parent_proof.zig");
        const Ledger = Adapter.Ledger;
        pub const Verified = struct {
            equation: @import("blake3_native_parent_verifier.zig").Verified,
            summary: Ledger.Summary,
            pub fn deinit(self: *Verified) void {
                self.equation.deinit();
                self.* = undefined;
            }
        };
        pub fn expected(profile: *const Profile.Owned) !Protocol.Bus.Expected {
            try profile.validate();
            return .{ .profile = profile.seal, .epoch = Adapter.epoch(profile).digest, .root_count = @intCast(Adapter.firstRoots(profile)) };
        }
        pub fn verifyStatement(a: std.mem.Allocator, bytes: []const u8, statement: *const Adapter.Statement.Owned, claims: Ledger.Claims, original: Profile.Limits, capacity: u32, parent_profile: @import("blake3_execution_parent_protocol.zig").Profile, limits: Adapter.Fixed.Limits) !Verified {
            const profile = try Profile.Owned.derive(a, statement, claims, original);
            defer profile.deinit();
            var cold = try Adapter.Fixed.Owned.derive(a, profile, capacity, limits);
            defer cold.deinit();
            const geometry = try Parent.ForBackend(@import("stwo_cpu_backend").CpuBackend).deriveKeyFromFixed(a, cold.fixed, cold.context, parent_profile);
            const roster = [_]Protocol.Bus.Expected{try expected(profile)};
            const key = try Protocol.Key.fromGeometry(geometry, cold.wires, &roster);
            var values = try Public.reconstruct(a, profile);
            defer values.deinit();
            const admission = try Protocol.Admission.init(key, try key.identity(), cold.wires, .{ .children = &.{values} }, &roster);
            var decoded = try Parent.codec.decode(a, bytes, &admission);
            var equation = try Parent.verify(&decoded, &admission);
            errdefer equation.deinit();
            try equation.validate(&admission, try key.identity());
            const summary = try Adapter.summary(profile);
            return .{ .equation = equation, .summary = summary };
        }
    };
}
