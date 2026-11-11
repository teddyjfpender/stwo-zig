//! The OP guest's shifted BN254 packet is admitted by the existing truth AIR.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const H = @import("tests.zig").Harness(.arith384_mont);
const C = @import("../../../ethereum_services/candidate_curves.zig");
const Fast = @import("../../../ethereum_services/montgomery_bn254.zig");

test "BN254 shifted Montgomery packets bind exact outputs in the existing AIR" {
    const p = C.BN254_P;
    const values = [_]u256{ 0, 1, p - 1, @as(u256, 1) << 192 };
    for (values) |a| for (values) |b| {
        const packet = H.packetOf(&.{ @as(u384, a) << 128, b, p });
        var main: [H.L.MAIN]Q = undefined;
        const witness = try H.rowOf(&packet, &main);
        // Native AIR generation is independent of the executor specialization.
        try std.testing.expectEqual(@as(@import("spec.zig").Big, Fast.product(a, b)), witness.out[0]);
        try std.testing.expect(H.accepted(&main));
        H.forge(&packet, &.{H.bytesOf(witness.out[0] ^ 1)}, &.{}, &main);
        try std.testing.expect(!H.accepted(&main));
    };
}

test "OP Arkworks scalar Montgomery packets admit shifted noncanonical inputs and reject forged outputs" {
    const moduli = [_]u256{ C.BLS12_381_SCALAR_P, C.BN254_SCALAR_P };
    for (moduli) |p| {
        const values = [_]u256{ 0, 1, p - 1, @as(u256, 1) << 192 };
        for (values) |a| for (values) |b| {
            const shifted = @as(u384, a) << 128;
            const packet = H.packetOf(&.{ shifted, b, p });
            var main: [H.L.MAIN]Q = undefined;
            const witness = try H.rowOf(&packet, &main);
            try std.testing.expectEqual(@as(@import("spec.zig").Big, C.mont384(shifted, b, p)), witness.out[0]);
            try std.testing.expect(witness.out[0] < p);
            try std.testing.expect(H.accepted(&main));
            H.forge(&packet, &.{H.bytesOf(witness.out[0] ^ 1)}, &.{}, &main);
            try std.testing.expect(!H.accepted(&main));
        };
    }
}
