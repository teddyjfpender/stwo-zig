//! Allocation-free Montgomery inversion with independent native SIMD chains.
//! The input is read-only and must not overlap the output, as with the scalar
//! striped batch inverter. No field, transcript or canonical encoding changes.
const std = @import("std");
const O = @import("om31.zig").OM31;
const simd = @import("packed_om31.zig");
const width = @import("m31.zig").PACK_WIDTH;
const stride = 2 * width;

pub fn invert(input: []const O, output: []O) !void {
    if (input.len < stride or input.len % stride != 0 or output.len < input.len)
        return error.InvalidBatchGeometry;
    const n = input.len;
    var products = [_]simd.PackedOM31{simd.splat(O.one())} ** 2;
    var first: usize = 0;
    while (first < n) : (first += stride) {
        inline for (0..2) |group| {
            const at = first + group * width;
            products[group] = simd.mul(products[group], simd.loadNative(input[at..]));
            simd.storeNative(output[at..], products[group]);
        }
    }
    // Invert all terminal products with one scalar field inversion. Copy the
    // tail before overwriting output, so reverse traversal can use its prefix.
    const tails = output[n - stride ..][0..stride].*;
    var prefixes: [stride]O = undefined;
    var product = O.one();
    for (tails, &prefixes) |tail, *prefix| {
        prefix.* = product;
        product = product.mul(tail);
    }
    var running = try product.inv();
    var tail_inverse: [stride]O = undefined;
    var index: usize = stride;
    while (index != 0) {
        index -= 1;
        tail_inverse[index] = running.mul(prefixes[index]);
        running = running.mul(tails[index]);
    }
    var inverses = [_]simd.PackedOM31{
        simd.loadNative(&tail_inverse),
        simd.loadNative(tail_inverse[width..]),
    };
    first = n;
    while (first > stride) {
        first -= stride;
        inline for (0..2) |group| {
            const at = first + group * width;
            simd.storeNative(output[at..], simd.mul(simd.loadNative(output[at - stride ..]), inverses[group]));
            inverses[group] = simd.mul(inverses[group], simd.loadNative(input[at..]));
        }
    }
    inline for (0..2) |group| simd.storeNative(output[group * width ..], inverses[group]);
}

test "OM31 packed batch inversion preserves every coordinate and immutable input" {
    const M = @import("m31.zig").M31;
    var rng = std.Random.DefaultPrng.init(0x4f38494e56455254);
    const a = std.testing.allocator;
    for ([_]usize{ stride, stride * 3, stride * 8, 4096, 4096 * 6 }) |n| {
        const input = try a.alloc(O, n);
        defer a.free(input);
        const output = try a.alloc(O, n);
        defer a.free(output);
        for (input, 0..) |*x, i| {
            var c: [8]M = undefined;
            for (&c) |*v| v.* = M.fromU64(rng.random().int(u32));
            x.* = if (i % 7 == 0) O.one() else O.fromM31Array(c);
        }
        const copy = try a.dupe(O, input);
        defer a.free(copy);
        try invert(input, output);
        for (input, output, copy) |x, inverse, original| {
            try std.testing.expect(x.eql(original));
            try std.testing.expect(x.mul(inverse).eql(O.one()));
        }
        input[n / 2] = O.zero();
        try std.testing.expectError(error.DivisionByZero, invert(input, output));
    }
    var input: [stride]O = @splat(O.one());
    var output: [stride]O = undefined;
    try std.testing.expectError(error.InvalidBatchGeometry, invert(input[0 .. stride - 1], &output));
    try std.testing.expectError(error.InvalidBatchGeometry, invert(&input, output[0 .. stride - 1]));
}
