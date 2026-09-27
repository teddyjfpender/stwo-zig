//! Synchronous immutable admission scope for new version2 recipe identities.
//! Borrowed policies and schedules must remain immutable until finish. Full
//! guards run at entry/exit, not once per wire; no descendant owners are cached.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Digest = @import("block_v5_public_supply_identity_v2.zig");
pub const Limits = Digest.Limits;
pub fn ForValues(comptime Values: type) type {
    return struct {
        const Self = @This();
        values: Values,
        wires: []const Bus.Wire,
        identity: Digest.Identity,
        active: bool = true,
        pub fn begin(values: Values, wires: []const Bus.Wire, limits: Limits) !Self {
            return .{ .values = values, .wires = wires, .identity = try Digest.compute(values, wires, limits) };
        }
        pub fn at(self: *const Self, ordinal: usize) ![4]M {
            if (!self.active or ordinal >= self.wires.len) return error.InvalidPublicSupplySession;
            const coordinates = try self.values.at(self.wires[ordinal]);
            for (coordinates) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidPublicSupplySession;
            return coordinates;
        }
        pub fn finish(self: *Self) ![32]u8 {
            if (!self.active) return error.InvalidPublicSupplySession;
            self.active = false;
            const current = try Digest.compute(self.values, self.wires, .{ .max_local_wires = self.wires.len });
            if (!std.meta.eql(self.identity, current)) return error.MutatedPublicSupplySession;
            return current.closure;
        }
    };
}
