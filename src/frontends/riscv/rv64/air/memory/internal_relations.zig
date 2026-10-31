//! One tagged relation for private RAM graph/data/permit packets. All fields
//! are full QM31 during domain and OODS evaluation. External CPU-state, bytes,
//! mapping-ROM and permutation relations remain separate typed obligations.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const policy_air = @import("policy_air.zig");
pub const Q = core.fields.qm31.QM31;
pub const ARITY = 24;
pub const Kind = enum(u32) { node = 0, payload = 1, digest = 2, header = 3, permit = 4, init_word = 5 };
/// Tagged relation draw over constant lane C (QM31 natively, external wires otherwise).
pub fn ChallengeFor(comptime C: type) type {
    return struct {
        offset: C,
        coefficients: [ARITY]C,
        pub fn draw(channel: *@import("../protocol.zig").Channel) @This() {
            channel.mixU32s(&.{ 0x52414d32, 0x494e544c, ARITY });
            var result = @This(){ .offset = channel.drawSecureFelt(), .coefficients = undefined };
            for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
            return result;
        }
        /// The six tag offsets are derived from the draw with lane arithmetic.
        pub fn prepare(self: @This()) PreparedFor(C) {
            var result = PreparedFor(C){ .coefficients = self.coefficients, .offsets = undefined };
            for (&result.offsets, 0..) |*offset, i| offset.* = self.offset.sub(self.coefficients[0].mul(E.qFor(C, @intCast(i))));
            return result;
        }
    };
}
pub const Challenge = ChallengeFor(Q);
pub fn PreparedFor(comptime C: type) type {
    return struct {
        coefficients: [ARITY]C,
        offsets: [6]C,
        pub fn combine(self: *const @This(), kind: Kind, fields: []const C) C {
            std.debug.assert(fields.len < ARITY);
            var result = self.offsets[@intFromEnum(kind)];
            for (fields, self.coefficients[1..][0..fields.len]) |field, coefficient| result = result.sub(field.mul(coefficient));
            return result;
        }
        pub fn payload(self: *const @This(), id: C, position: C, value: C) C {
            return self.combine(.payload, &.{ id, position, value });
        }
        pub fn digest(self: *const @This(), id: C, value: [9]C) C {
            var fields: [10]C = undefined;
            fields[0] = id;
            @memcpy(fields[1..10], &value);
            return self.combine(.digest, &fields);
        }
        pub fn node(self: *const @This(), epoch: C, height: C, index: [7]C, value: [9]C) C {
            var fields: [18]C = undefined;
            fields[0] = epoch;
            fields[1] = height;
            @memcpy(fields[2..9], &index);
            @memcpy(fields[9..18], &value);
            return self.combine(.node, &fields);
        }
        pub fn permitChallenge(self: *const @This()) policy_air.PermitChallengeFor(C) {
            var result = policy_air.PermitChallengeFor(C){ .offset = self.offsets[@intFromEnum(Kind.permit)], .coefficients = undefined };
            @memcpy(&result.coefficients, self.coefficients[1..12]);
            return result;
        }
    };
}
pub const Prepared = PreparedFor(Q);
const std = @import("std");

test "private RAM tagged relation: sparse methods preserve every full-extension coordinate" {
    var challenge = Challenge{ .offset = Q.fromU32Unchecked(3, 5, 7, 11), .coefficients = undefined };
    for (&challenge.coefficients, 0..) |*coefficient, i| coefficient.* = Q.fromU32Unchecked(@intCast(i + 13), @intCast(i + 31), @intCast(i + 53), @intCast(i + 79));
    const prepared = challenge.prepare();
    var index: [7]Q = undefined;
    var digest: [9]Q = undefined;
    for (&index, 0..) |*field, i| field.* = Q.fromU32Unchecked(@intCast(i + 2), 19, 37, 61);
    for (&digest, 0..) |*field, i| field.* = Q.fromU32Unchecked(17, @intCast(i + 23), 41, 67);
    var tuple: [ARITY]Q = @splat(Q.zero());
    tuple[0] = E.q(@intFromEnum(Kind.node));
    tuple[1] = Q.fromU32Unchecked(1, 2, 3, 4);
    tuple[2] = Q.fromU32Unchecked(5, 6, 7, 8);
    @memcpy(tuple[3..10], &index);
    @memcpy(tuple[10..19], &digest);
    var expected = challenge.offset;
    for (tuple, challenge.coefficients) |field, coefficient| expected = expected.sub(field.mul(coefficient));
    try std.testing.expectEqualDeep(expected, prepared.node(tuple[1], tuple[2], index, digest));
    const permit = prepared.permitChallenge();
    var permit_tuple: policy_air.PermitTuple = undefined;
    for (&permit_tuple, 0..) |*field, i| field.* = Q.fromU32Unchecked(@intCast(i + 7), 29, 43, 73);
    try std.testing.expectEqualDeep(prepared.combine(.permit, &permit_tuple), permit.denominator(permit_tuple));
}
