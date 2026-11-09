//! Closed source-cost oracle only; no ISA/source suite/AIR admission.
const std = @import("std");
const B = @import("stwo_riscv_frontend").rv64_air.crypto.curves.spec;
fn geometry(comptime m: [4]i32) B.RelationGeometry {
    const terms = comptime [_]B.Term{
        .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = m[0] },
        .{ .a = .{ .in = 2 }, .b = .{ .in = 3 }, .coef = -m[1] },
        .{ .a = .{ .in = 2 }, .coef = m[2] },
        .{ .a = .{ .out = 0 }, .coef = -m[3] },
    };
    const definition = comptime B.Def{ .limbs = 32, .coords = 4, .written = 1, .inputs = 4, .outputs = 1, .witnesses = 0, .modulus = .{ .constant = B.BN254_P }, .relations = &.{&terms}, .asymmetric_carries = true };
    return B.deriveRelation(definition, &terms);
}
test "pairing fused source cost matches original exact integer carry authority" {
    inline for (.{
        .{ .mass = [4]i32{ 6, 6, 1, 2 }, .q = 33, .bits = 17, .offset = 67424, .positive = 29809248, .negative = 29809756 },
        .{ .mass = [4]i32{ 6, 6, 1, 1 }, .q = 33, .bits = 17, .offset = 67424, .positive = 29809262, .negative = 29809501 },
        .{ .mass = [4]i32{ 5, 6, 1, 3 }, .q = 33, .bits = 17, .offset = 71504, .positive = 28768882, .negative = 28769611 },
        .{ .mass = [4]i32{ 40, 23, 0, 1 }, .q = 34, .bits = 19, .offset = 194681, .positive = 133399980, .negative = 133395862 },
        .{ .mass = [4]i32{ 97, 56, 0, 1 }, .q = 34, .bits = 21, .offset = 883205, .positive = 429152039, .negative = 429141826 },
    }) |expected| {
        const g = comptime geometry(expected.mass);
        try std.testing.expectEqual(@as(usize, expected.q), g.q_bytes);
        try std.testing.expectEqual(@as(usize, 65), g.groups);
        try std.testing.expectEqual(@as(usize, 64), g.carries);
        try std.testing.expectEqual(@as(u32, expected.bits), g.carry_bits);
        try std.testing.expectEqual(@as(u64, expected.offset), g.carry_offset);
        try std.testing.expectEqual(@as(u64, expected.positive), g.residual_positive_bound);
        try std.testing.expectEqual(@as(u64, expected.negative), g.residual_negative_bound);
        try std.testing.expect(g.residual_positive_bound < B.M31 and g.residual_negative_bound < B.M31);
    }
}
