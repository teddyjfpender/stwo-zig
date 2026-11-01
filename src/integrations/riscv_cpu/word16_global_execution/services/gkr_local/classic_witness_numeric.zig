//! Native packed OM Montgomery chains and contribution dots. Scratch owners
//! are supplied by the bounded witness plan; no allocation or transcript work.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const P = core.fields.packed_om31;
const W = core.fields.m31.PACK_WIDTH;
const C = @import("classic_witness.zig");
pub fn batchInverse(input: []const O, output: []O) !void {
    std.debug.assert(output.len >= input.len);
    if (input.len < W or input.len % W != 0) return core.fields.batchInverseInPlace(O, input, output);
    var product = P.splat(O.one());
    var at: usize = 0;
    while (at < input.len) : (at += W) {
        product = product.mul(P.loadNative(input[at..]));
        P.storeNative(output[at..], product);
    }
    var tail: [W]O = undefined;
    var inverse: [W]O = undefined;
    inline for (0..W) |i| tail[i] = P.lane(product, i);
    try core.fields.batchInverseInPlace(O, &tail, &inverse);
    var inv = P.loadNative(&inverse);
    at = input.len;
    while (at > W) {
        at -= W;
        P.storeNative(output[at..], P.loadNative(output[at - W ..]).mul(inv));
        inv = inv.mul(P.loadNative(input[at..]));
    }
    P.storeNative(output, inv);
}
pub fn contributions(numerators: []const C.Numerator, inverses: []const O, out: []O) void {
    std.debug.assert(numerators.len == inverses.len and out.len >= inverses.len);
    var at: usize = 0;
    while (at + W <= inverses.len) : (at += W) {
        var all_base = true;
        var b: core.fields.m31.PackedM31 = undefined;
        inline for (0..W) |i| switch (numerators[at + i]) {
            .base => |v| b[i] = v.v,
            .secure => {
                all_base = false;
                b[i] = 0;
            },
        };
        const inv = P.loadNative(inverses[at..]);
        const result = if (all_base) inv.mulBase(b) else blk: {
            var n: [W]O = undefined;
            inline for (0..W) |i| n[i] = switch (numerators[at + i]) {
                .base => |v| O.fromBase(v),
                .secure => |v| v,
            };
            break :blk inv.mul(P.loadNative(&n));
        };
        P.storeNative(out[at..], result);
    }
    for (at..inverses.len) |i| out[i] = numerators[i].multiply(inverses[i]);
}
pub fn sum(values: []const O) O {
    var total = P.splat(O.zero());
    var at: usize = 0;
    while (at + W <= values.len) : (at += W) total = total.add(P.loadNative(values[at..]));
    var result = O.zero();
    inline for (0..W) |i| result = result.add(P.lane(total, i));
    for (at..values.len) |i| result = result.add(values[i]);
    return result;
}
