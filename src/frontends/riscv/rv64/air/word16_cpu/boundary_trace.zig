//! Request-specific public register coefficients over immutable selectors.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const L = @import("layout.zig");
const P = @import("public.zig");
const Boundary = @import("boundary.zig");
const Lookup = @import("lookup.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
pub const Result = struct { values: []M, claim: Q };
pub fn generate(a: std.mem.Allocator, fixed: []const M, public: P.Public, cpu_log: u32, challenges: Lookup.RegisterChallenges) !Result {
    try public.validate(cpu_log);
    if (fixed.len != 34 * 32) return error.InvalidWord16BoundaryShape;
    const output = try a.alloc(M, 8 * 32);
    errdefer a.free(output);
    var denominators: [32][2]Q = undefined;
    var products: [32]Q = undefined;
    var inverses: [32]Q = undefined;
    for (0..32) |row| {
        const pos = L.physical(row, 5);
        var selectors: [34]M = undefined;
        for (&selectors, 0..) |*value, column| value.* = fixed[column * 32 + pos];
        const before = Boundary.tupleFor(M, &selectors, public, false);
        const after = Boundary.tupleFor(M, &selectors, public, true);
        denominators[row] = .{ challenges.offset, challenges.offset };
        for (challenges.coefficients, before, after) |coefficient, initial, final| {
            denominators[row][0] = denominators[row][0].sub(coefficient.mulM31(initial));
            denominators[row][1] = denominators[row][1].sub(coefficient.mulM31(final));
        }
        products[row] = denominators[row][0].mul(denominators[row][1]);
    }
    try core.fields.batchInverseInPlace(Q, &products, &inverses);
    var sum = Q.zero();
    for (0..32) |row| {
        const pos = L.physical(row, 5);
        sum = sum.add(denominators[row][0].sub(denominators[row][1]).mul(inverses[row]));
        for (inverses[row].toM31Array(), 0..) |coordinate, i| output[i * 32 + pos] = coordinate;
        for (sum.toM31Array(), 0..) |coordinate, i| output[(4 + i) * 32 + pos] = coordinate;
    }
    for (sum.toM31Array(), 0..) |coordinate, i| {
        for (0..32) |row| output[(4 + i) * 32 + row] = output[(4 + i) * 32 + row].sub(coordinate);
    }
    return .{ .values = output, .claim = sum };
}
