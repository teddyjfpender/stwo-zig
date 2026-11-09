//! Independent integer checks for layout-sensitive extension multiplication.
const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const modulus: u64 = 2147483647;

// This schoolbook expansion uses neither field helpers nor Karatsuba. Each
// basis is i^(index & 1) * u^(index >> 1), with i^2=-1 and u^2=2+i.
fn integerProduct(a: [4]u32, b: [4]u32) [4]u32 {
    var result = [_]u64{0} ** 4;
    for (a, 0..) |left, i| {
        for (b, 0..) |right, j| {
            var term = @as(u64, left) * right % modulus;
            var imaginary = (i & 1) + (j & 1);
            if (imaginary == 2) {
                imaginary = 0;
                term = (modulus - term) % modulus;
            }
            const extension = (i >> 1) + (j >> 1);
            if (extension < 2) {
                const index = 2 * extension + imaginary;
                result[index] = (result[index] + term) % modulus;
            } else {
                result[imaginary] = (result[imaginary] + 2 * term) % modulus;
                const shifted = if (imaginary == 0) term else modulus - term;
                result[1 - imaginary] = (result[1 - imaginary] + shifted) % modulus;
            }
        }
    }
    return .{ @intCast(result[0]), @intCast(result[1]), @intCast(result[2]), @intCast(result[3]) };
}

fn field(limbs: [4]u32) QM31 {
    return QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
}

fn words(value: *const QM31) [4]u32 {
    return .{ value.c0.a.v, value.c0.b.v, value.c1.a.v, value.c1.b.v };
}

noinline fn detachedProduct(a: QM31, b: QM31) QM31 {
    return a.mul(b);
}

fn integerComplex(a: [4]u32, b: [4]u32) [2]u32 {
    return .{
        @intCast((@as(u64, a[0]) * b[0] % modulus + modulus - @as(u64, a[1]) * b[1] % modulus) % modulus),
        @intCast((@as(u64, a[0]) * b[1] % modulus + @as(u64, a[1]) * b[0] % modulus) % modulus),
    };
}

fn checkContexts(a: *const QM31, b: *const QM31) !void {
    const expected = integerProduct(words(a), words(b));
    const expected_complex = integerComplex(words(a), words(b));
    const complex = a.c0.mul(b.c0);
    const complex_reverse = b.c0.mul(a.c0);
    const complex_words = [_]u32{ complex.a.v, complex.b.v };
    const reverse_words = [_]u32{ complex_reverse.a.v, complex_reverse.b.v };
    try std.testing.expectEqualSlices(u32, &expected_complex, &complex_words);
    try std.testing.expectEqualSlices(u32, &expected_complex, &reverse_words);
    const direct = a.mul(b.*);
    const reverse = b.mul(a.*);
    const detached = detachedProduct(a.*, b.*);
    try std.testing.expectEqualSlices(u32, &expected, &words(&direct));
    try std.testing.expectEqualSlices(u32, &expected, &words(&reverse));
    try std.testing.expectEqualSlices(u32, &expected, &words(&detached));
}

test "qm31 integer: pinned first FRI extension product" {
    var operands = [_]QM31{
        field(.{ 5, 7, 11, 13 }),
        field(.{ 1303640556, 459797465, 1763438021, 535549304 }),
    };
    std.mem.doNotOptimizeAway(&operands);
    const expected = [_]u32{ 1502722113, 2034726791, 546122166, 519690011 };
    try std.testing.expectEqualSlices(u32, &expected, &integerProduct(words(&operands[0]), words(&operands[1])));
    try checkContexts(&operands[0], &operands[1]);
}

test "qm31 integer: runtime edges and seeded aggregate call contexts" {
    const edge_words = [_][4]u32{
        .{ 0, 0, 0, 0 },                   .{ 1, 0, 0, 0 }, .{ 0, 1, 0, 0 },
        .{ 0, 0, 1, 0 },                   .{ 0, 0, 0, 1 }, .{ 2147483646, 2147483646, 2147483646, 2147483646 },
        .{ 1, 2147483646, 2, 2147483645 },
    };
    const operands = try std.testing.allocator.alloc(QM31, 2);
    defer std.testing.allocator.free(operands);
    for (edge_words) |a| {
        for (edge_words) |b| {
            operands[0] = field(a);
            operands[1] = field(b);
            std.mem.doNotOptimizeAway(operands.ptr);
            try checkContexts(&operands[0], &operands[1]);
        }
    }
    var prng = std.Random.DefaultPrng.init(0x6672_695f_716d_3331);
    const random = prng.random();
    for (0..4096) |_| {
        for (operands) |*operand| {
            var value: [4]u32 = undefined;
            for (&value) |*word| word.* = @intCast(@as(u64, random.int(u32)) % modulus);
            operand.* = field(value);
        }
        std.mem.doNotOptimizeAway(operands.ptr);
        try checkContexts(&operands[0], &operands[1]);
    }
}

test "qm31 integer: first circle fold without stage instrumentation" {
    const core = @import("stwo_core");
    var input: [256]QM31 = undefined;
    for (&input, 0..) |*value, i| {
        const x: u32 = @intCast(i);
        value.* = field(.{ x + 1, 2 * x + 3, 3 * x + 5, 7 * x + 11 });
    }
    var output = [_]QM31{QM31.zero()} ** 128;
    const domain = core.poly.circle.canonic.CanonicCoset.new(8).circleDomain();
    try core.fri.foldCircleIntoLine(&output, &input, domain, field(.{ 5, 7, 11, 13 }));
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("STWO_CIRCUIT_VALUES_V1\x00");
    hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, output.len)));
    for (&output) |*value| {
        for (words(value)) |word| hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, word)));
    }
    try std.testing.expectEqualStrings(
        "012d32936102268b54bb331e44297762696434e0f64e8794086ec51d373d44ec",
        &std.fmt.bytesToHex(hasher.finalResult(), .lower),
    );
}

test "qm31 integer: required regression discovery" {
    inline for (.{
        "qm31 integer: pinned first FRI extension product",
        "qm31 integer: runtime edges and seeded aggregate call contexts",
        "qm31 integer: first circle fold without stage instrumentation",
    }) |suffix| {
        var found: usize = 0;
        for (@import("builtin").test_functions) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".test." ++ suffix)) found += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), found);
    }
}
