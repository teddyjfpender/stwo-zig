//! One proof-local relation namespace. Draw ONLY after sealed FIXED+MAIN and
//! the trusted statement/program/ordinal have entered the local transcript.
const std = @import("std");
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const R = @import("fractions.zig");
pub fn For(comptime C: type) type {
    return struct {
        offsets: [std.enums.values(R.Relation).len]C,
        coefficients: [std.enums.values(R.Relation).len][R.MAX_ARITY]C,
        /// V2 draws exactly its original nine namespaces; the appended V3
        /// namespace is initialized but draws no transcript bytes by default.
        pub fn draw(channel: anytype) @This() {
            return drawMode(channel, false);
        }
        pub fn drawV3(channel: anytype) @This() {
            return drawMode(channel, true);
        }
        pub fn drawForInstances(channel: anytype, instances: []const @import("frame.zig").Instance) @This() {
            for (instances) |instance| if (instance.origin == .core and instance.origin.core == .cpu and instance.terms == 14) return drawV3(channel);
            return draw(channel);
        }
        pub fn drawMode(channel: anytype, v3: bool) @This() {
            const relations = std.enums.values(R.Relation);
            const count: usize = if (v3) relations.len else @intFromEnum(R.Relation.byte_pair);
            channel.mixU32s(&.{ if (v3) @as(u32, 0x4c474b33) else 0x4c474b31, 8, @intCast(count) });
            var out = @This(){ .offsets = @splat(C.zero()), .coefficients = @splat(@splat(C.zero())) };
            for (relations[0..count]) |relation| {
                const index = @intFromEnum(relation);
                channel.mixU32s(&.{ @intCast(index), @intCast(relation.arity()) });
                out.offsets[index] = channel.drawSecureFelt();
                for (0..relation.arity()) |i| out.coefficients[index][i] = if (relation == .range8) C.one() else channel.drawSecureFelt();
            }
            return out;
        }
        /// Native metadata is base-valued. Keep every tuple product a small
        /// M31 by OM31 multiply rather than promoting both operands to OM31.
        pub fn denominatorBase(self: *const @This(), relation: R.Relation, tuple: anytype) C {
            std.debug.assert(tuple.len == relation.arity());
            const index = @intFromEnum(relation);
            var d = self.offsets[index];
            for (tuple, 0..) |value, i| d = d.sub(self.coefficients[index][i].mulM31(value));
            return d;
        }
        pub fn denominatorFor(self: *const @This(), comptime F: type, relation: R.Relation, tuple: anytype) E.SecureFor(F) {
            std.debug.assert(tuple.len == relation.arity());
            const index = @intFromEnum(relation);
            var d = E.splatFor(F, self.offsets[index]);
            for (tuple, 0..) |value, i| d = d.sub(E.mulBaseFor(F, E.splatFor(F, self.coefficients[index][i]), value));
            return d;
        }
    };
}
