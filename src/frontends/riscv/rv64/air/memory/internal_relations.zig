//! One tagged relation for private RAM graph/data/permit packets. All fields
//! are full QM31 during domain and OODS evaluation. External CPU-state, bytes,
//! mapping-ROM and permutation relations remain separate typed obligations.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const policy_air = @import("policy_air.zig");
pub const Q = core.fields.qm31.QM31;
pub const ARITY = 24;
pub const Kind = enum(u32) { node = 0, payload = 1, digest = 2, header = 3, permit = 4, init_word = 5 };
pub const Challenge = struct {
    offset: Q,
    coefficients: [ARITY]Q,
    pub fn draw(channel: *@import("../protocol.zig").Channel) Challenge {
        channel.mixU32s(&.{ 0x52414d32, 0x494e544c, ARITY });
        var result = Challenge{ .offset = channel.drawSecureFelt(), .coefficients = undefined };
        for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
        return result;
    }
    pub fn prepare(self: Challenge) Prepared {
        var result = Prepared{ .coefficients = self.coefficients, .offsets = undefined };
        for (&result.offsets, 0..) |*offset, i| offset.* = self.offset.sub(self.coefficients[0].mul(E.q(@intCast(i))));
        return result;
    }
};
pub const Prepared = struct {
    coefficients: [ARITY]Q,
    offsets: [6]Q,
    pub fn combine(self: *const Prepared, kind: Kind, fields: []const Q) Q {
        std.debug.assert(fields.len < ARITY);
        var result = self.offsets[@intFromEnum(kind)];
        for (fields, self.coefficients[1..][0..fields.len]) |field, coefficient| result = result.sub(field.mul(coefficient));
        return result;
    }
    pub fn payload(self: *const Prepared, id: Q, position: Q, value: Q) Q {
        return self.combine(.payload, &.{ id, position, value });
    }
    pub fn digest(self: *const Prepared, id: Q, value: [9]Q) Q {
        var fields: [10]Q = undefined;
        fields[0] = id;
        @memcpy(fields[1..10], &value);
        return self.combine(.digest, &fields);
    }
    pub fn node(self: *const Prepared, epoch: Q, height: Q, index: [7]Q, value: [9]Q) Q {
        var fields: [18]Q = undefined;
        fields[0] = epoch;
        fields[1] = height;
        @memcpy(fields[2..9], &index);
        @memcpy(fields[9..18], &value);
        return self.combine(.node, &fields);
    }
    pub fn permitChallenge(self: *const Prepared) policy_air.PermitChallenge {
        var result = policy_air.PermitChallenge{ .offset = self.offsets[@intFromEnum(Kind.permit)], .coefficients = undefined };
        @memcpy(&result.coefficients, self.coefficients[1..12]);
        return result;
    }
};
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
