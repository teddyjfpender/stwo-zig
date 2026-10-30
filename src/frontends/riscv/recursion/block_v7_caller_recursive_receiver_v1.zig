//! Detached actual caller parent verification. A receiver independently selects
//! policy, whole epoch, expected key and the public claims; no base proof or
//! producer columns are consulted. Returned global obligations remain OPEN.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const Profile = Policy.FixedProfile;
        const Public = Policy.Public;
        const Protocol = Policy.ParentProtocol;
        const Parent = @import("blake3_execution_parent_proof.zig");
        const Source = Policy.Source;
        pub const Verified = struct {
            equation: @import("blake3_native_parent_verifier.zig").Verified,
            open: Source.Exports,
            pub fn deinit(self: *Verified) void {
                self.equation.deinit();
                self.* = undefined;
            }
        };
        pub fn verify(a: std.mem.Allocator, bytes: []const u8, independently_selected: *const Profile.Owned, expected_key: Protocol.Key, wires: []const Public.Wire) !Verified {
            try independently_selected.validate();
            const admitted = &independently_selected.admitted;
            try Policy.Proof.ForBackend(@import("stwo_cpu_backend").CpuBackend).requireFixedRoot(a, admitted.pin());
            var values = try Public.reconstruct(a, admitted, &independently_selected.arithmetic, &independently_selected.claims);
            defer values.deinit();
            const roster = [_]Protocol.Bus.Expected{.{ .profile = independently_selected.seal, .epoch = admitted.epoch.digest, .roots = admitted.source.roots ++ .{admitted.source.access_root} }};
            const admission = try Protocol.Admission.init(expected_key, try expected_key.identity(), wires, .{ .children = &.{values} }, &roster);
            var decoded = try Parent.codec.decode(a, bytes, &admission);
            var equation = try Parent.verify(&decoded, &admission);
            errdefer equation.deinit();
            try equation.validate(&admission, try expected_key.identity());
            const open = try Source.exports(&admitted.relations.schedule, &independently_selected.arithmetic, &independently_selected.claims);
            if (!open.internal_residual.isZero()) return error.UnclosedV7CallerInternalRelations;
            return .{ .equation = equation, .open = open };
        }
    };
}
