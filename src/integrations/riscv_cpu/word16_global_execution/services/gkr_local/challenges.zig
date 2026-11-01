//! One proof-local relation namespace. Draw ONLY after sealed FIXED+MAIN and
//! the trusted statement/program/ordinal have entered the local transcript.
const std = @import("std");
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const R = @import("fractions.zig");
pub fn For(comptime C: type) type {
    return struct {
        offsets: [std.enums.values(R.Relation).len]C,
        coefficients: [std.enums.values(R.Relation).len][R.MAX_ARITY]C,
        pub fn draw(channel: anytype) @This() {
            channel.mixU32s(&.{ 0x4c474b31, 8, @intCast(std.enums.values(R.Relation).len) });
            var out: @This() = undefined;
            for (std.enums.values(R.Relation)) |relation| {
                const index = @intFromEnum(relation);
                channel.mixU32s(&.{ @intCast(index), @intCast(relation.arity()) });
                out.offsets[index] = channel.drawSecureFelt();
                out.coefficients[index] = @splat(C.zero());
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
