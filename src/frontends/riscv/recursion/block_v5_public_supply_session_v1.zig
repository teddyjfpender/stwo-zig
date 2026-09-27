//! Synchronous immutable lookup session. The caller must prevent mutation of
//! the borrowed admitted policy and schedule until finish; Zig does not enforce
//! immutability or moves. Full guards run at entry/exit, never per supplied wire.
//! This is not proof authority and does not cache descendant owners.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Limits = struct { max_local_wires: usize = 1 << 24 };
pub fn ForValues(comptime Values: type) type {
    return struct {
        const Self = @This();
        values: Values,
        wires: []const Bus.Wire,
        schedule_id: [32]u8,
        value_id: [32]u8,
        active: bool,
        pub fn begin(values: Values, wires: []const Bus.Wire, limits: Limits) !Self {
            if (limits.max_local_wires == 0 or wires.len > limits.max_local_wires or wires.len > std.math.maxInt(u32)) return error.ClosedPublicSupplyResourceLimit;
            try values.validate();
            return .{ .values = values, .wires = wires, .schedule_id = try Bus.scheduleDigest(wires), .value_id = try digest(values, wires), .active = true };
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
            try self.values.validate();
            if (!std.meta.eql(self.schedule_id, try Bus.scheduleDigest(self.wires)) or !std.meta.eql(self.value_id, try digest(self.values, self.wires))) return error.MutatedPublicSupplySession;
            var channel = core.channel.blake3.Channel{};
            channel.mixU32s(&.{ 0x42355343, 1, @intCast(self.wires.len) });
            channel.mixRoot(self.schedule_id);
            channel.mixRoot(self.value_id);
            return channel.digestBytes();
        }
        fn digest(values: Values, wires: []const Bus.Wire) ![32]u8 {
            var channel = core.channel.blake3.Channel{};
            channel.mixU32s(&.{ 0x42355356, 1 });
            for (wires) |wire| {
                const coordinates = try values.at(wire);
                var raw: [4]u32 = undefined;
                for (&raw, coordinates) |*word, value| {
                    if (value.v >= core.fields.m31.Modulus) return error.InvalidPublicSupplySession;
                    word.* = value.v;
                }
                channel.mixU32s(&raw);
            }
            return channel.digestBytes();
        }
    };
}
