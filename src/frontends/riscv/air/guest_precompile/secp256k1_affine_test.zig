const std = @import("std");
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");

const Secp256k1 = std.crypto.ecc.Secp256k1;
const csp_input = [_]u8{
    0xe4, 0x95, 0xc7, 0x07, 0xf9, 0x13, 0x9a, 0x49, 0x9b, 0xa2, 0x6b, 0xb8,
    0xe8, 0x53, 0xe7, 0x7e, 0x3b, 0x29, 0xea, 0xd1, 0xf6, 0x26, 0x9e, 0x93,
    0xa8, 0xb7, 0x8d, 0x08, 0x50, 0x79, 0xee, 0xd5, 0x04, 0x05, 0xb3, 0x04,
    0x75, 0xaf, 0x82, 0xde, 0x72, 0xca, 0x14, 0x45, 0x99, 0x79, 0xe2, 0xc4,
    0x2a, 0x82, 0xa0, 0x79, 0xbb, 0x8e, 0x75, 0x42, 0x04, 0xbb, 0xfb, 0xbc,
    0x46, 0xf1, 0x96, 0x1b, 0x62, 0x04, 0xdd, 0xf4, 0x75, 0x99, 0xc8, 0x3b,
    0x4d, 0xd3, 0x85, 0x7f, 0x53, 0xdf, 0xa0, 0x89, 0xc1, 0x8c, 0xd5, 0x2a,
    0x3a, 0x79, 0xa3, 0xc0, 0x34, 0xd4, 0xc3, 0xce, 0xb2, 0x8f, 0x0c, 0x52,
    0x87, 0x97, 0x4a, 0x99, 0xc1, 0x96, 0x65, 0x05, 0x41, 0x1c, 0xc2, 0x06,
    0x2a, 0xb5, 0x1a, 0x44, 0xae, 0x6e, 0x47, 0x9d, 0xc5, 0x74, 0xc7, 0x34,
    0x1a, 0x2f, 0x65, 0x48, 0x89, 0xd3, 0xd0, 0x7b, 0x3d, 0x19, 0x13, 0xa0,
    0x4f, 0xd6, 0x5d, 0x1d, 0x07, 0xc3, 0x87, 0xb4, 0x1f, 0x7b, 0x11, 0x30,
    0xdc, 0x6b, 0x8b, 0x64, 0x22, 0xdd, 0xe0, 0xe4, 0xcb, 0xc5, 0x31, 0x30,
    0x90, 0xf4, 0x04, 0xdd, 0x0d,
};

test "secp256k1 affine: complete add and double agree with Zig secp" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const generator = affine.basePoint();
    const doubled = try affine.double(&tape, generator);
    const added = try affine.addPoints(&tape, generator, generator);
    try std.testing.expect(affine.Point.eql(doubled, added));
    try std.testing.expect((try affine.pointToStd(doubled)).equivalent(Secp256k1.basePoint.dbl()));

    const inverse = affine.Point{
        .x = generator.x,
        .y = field.bytesFromInteger(field.base_modulus.integer() - integer(generator.y)),
        .infinity = false,
    };
    try std.testing.expect((try affine.addPoints(&tape, generator, inverse)).infinity);
    try std.testing.expect(affine.Point.eql(try affine.addPoints(&tape, .{}, generator), generator));
    try std.testing.expect(affine.Point.eql(try affine.addPoints(&tape, generator, .{}), generator));
}

test "secp256k1 affine: joint wNAF matches independent GLV reference" {
    var generator = std.Random.DefaultPrng.init(0x5ec0_5ec0_2561_2561);
    const random = generator.random();
    for (0..12) |_| {
        var tape = affine.Tape.init(std.testing.allocator);
        defer tape.deinit();
        const order = field.scalar_modulus.integer();
        const point_scalar = 1 + random.int(u256) % (order - 1);
        const generator_scalar = 1 + random.int(u256) % (order - 1);
        const other_scalar = 1 + random.int(u256) % (order - 1);
        const point_std = try Secp256k1.basePoint.mul(field.bytesFromInteger(point_scalar), .little);
        const point = try affine.pointFromSec1(&point_std.toUncompressedSec1());
        const actual = try affine.doubleScalarWnaf(
            &tape,
            field.bytesFromInteger(generator_scalar),
            point,
            field.bytesFromInteger(other_scalar),
        );
        const expected = try Secp256k1.mulDoubleBasePublic(
            Secp256k1.basePoint,
            field.bytesFromInteger(generator_scalar),
            point_std,
            field.bytesFromInteger(other_scalar),
            .little,
        );
        try std.testing.expect((try affine.pointToStd(actual)).equivalent(expected));
        try std.testing.expect(tape.products.items.len < 1_900);
    }
}

test "secp256k1 affine: GLV tape matches baseline and reduces product rows" {
    var generator = std.Random.DefaultPrng.init(0x1234_5ec0_2561_abcd);
    const random = generator.random();
    for (0..12) |_| {
        const order = field.scalar_modulus.integer();
        const point_scalar = 1 + random.int(u256) % (order - 1);
        const generator_scalar = 1 + random.int(u256) % (order - 1);
        const other_scalar = 1 + random.int(u256) % (order - 1);
        const point_std = try Secp256k1.basePoint.mul(field.bytesFromInteger(point_scalar), .little);
        const point = try affine.pointFromSec1(&point_std.toUncompressedSec1());

        var baseline = affine.Tape.init(std.testing.allocator);
        defer baseline.deinit();
        const expected = try affine.doubleScalarWnaf(
            &baseline,
            field.bytesFromInteger(generator_scalar),
            point,
            field.bytesFromInteger(other_scalar),
        );
        var glv = affine.Tape.init(std.testing.allocator);
        defer glv.deinit();
        const actual = try affine.doubleScalarGlvWnaf(
            &glv,
            field.bytesFromInteger(generator_scalar),
            point,
            field.bytesFromInteger(other_scalar),
        );
        try std.testing.expect(affine.Point.eql(expected, actual));
        try std.testing.expect(glv.products.items.len * 4 < baseline.products.items.len * 3);
        try std.testing.expectEqual(@as(usize, 2), glv.scalar_splits.items.len);
    }
}

test "secp256k1 affine: CSP signature verifies with compact operation tape" {
    try std.testing.expectEqual(@as(usize, 161), csp_input.len);
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const valid = try affine.verifyEcdsa(
        &tape,
        csp_input[0..32].*,
        csp_input[32..97].*,
        csp_input[97..129].*,
        csp_input[129..161].*,
    );
    try std.testing.expect(valid);
    try std.testing.expectEqual(@as(usize, 1_039), tape.products.items.len);
    try std.testing.expectEqual(@as(usize, 1_516), tape.linears.items.len);
    try std.testing.expectEqual(@as(usize, 228), tape.points.items.len);
    for (tape.products.items) |*record| try record.witness.validateExact(record.modulus.modulus());
}

test "secp256k1 affine: pinned bad signature is rejected" {
    var bad_input = csp_input;
    bad_input[160] ^= 1;
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    try std.testing.expect(!try affine.verifyEcdsa(
        &tape,
        bad_input[0..32].*,
        bad_input[32..97].*,
        bad_input[97..129].*,
        bad_input[129..161].*,
    ));
}

fn integer(value: affine.Value) u256 {
    return std.mem.readInt(u256, &value, .little);
}
