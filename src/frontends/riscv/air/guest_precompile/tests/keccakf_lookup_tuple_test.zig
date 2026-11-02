//! Extraction parity over arbitrary secure-field values, including caller rows.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const current = @import("../keccakf_interaction_plan.zig");
const reference = @import("keccakf_lookup_reference.zig");
const trace = @import("../keccakf_trace.zig");
const relations = @import("../keccakf_relations.zig");
test "Keccak pure tuple extraction preserves every legacy arbitrary-QM31 pair" {
    try run();
}
pub fn run() !void {
    var main: [trace.Layout.main_columns]Q = undefined;
    var next: [1600]Q = undefined;
    var output: [1600]Q = undefined;
    var selectors: [29]Q = undefined;
    var random = std.Random.DefaultPrng.init(0xf6c31071c5);
    const rng = random.random();
    for (&main) |*v| v.* = Q.fromU32Unchecked(rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1);
    for (&next) |*v| v.* = Q.fromU32Unchecked(rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1);
    for (&output) |*v| v.* = Q.fromU32Unchecked(rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1);
    for (&selectors) |*v| v.* = Q.fromU32Unchecked(rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1, rng.int(u32) >> 1);
    const ch = relations.Relations.dummy();
    const expected = try reference.rowPairsGeneric(Q, &main, &next, &output, &selectors, &ch);
    const actual = try current.rowPairsGeneric(Q, &main, &next, &output, &selectors, &ch);
    for (expected, actual) |e, a| {
        try std.testing.expect(e.n1.eql(a.n1));
        try std.testing.expect(e.d1.eql(a.d1));
        try std.testing.expect(e.n2.eql(a.n2));
        try std.testing.expect(e.d2.eql(a.d2));
    }
}
