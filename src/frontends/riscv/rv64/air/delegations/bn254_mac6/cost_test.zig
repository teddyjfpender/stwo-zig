//! Source-count model only: no proof, profile or accepted program.
const std = @import("std");
const N = @import("normalize.zig");
const S = @import("../bn254_miller/spec.zig");
const W = @import("../bn254_miller/witness.zig");
fn padded(n: usize) usize {
    return std.math.ceilPowerOfTwo(usize, @max(n, 1)) catch unreachable;
}
test "MAC6 actual four-pair Miller capacity cost" {
    for ([_]usize{ 4, 6, 8, 12 }) |capacity| {
        var rows: usize = 0;
        var products: usize = 0;
        for (&W.ROM.nodes) |*node| {
            const expression = S.expression(node.*);
            var terms: [145]N.Term = undefined;
            for (expression.terms[0..expression.len], terms[0..expression.len]) |t, *out| out.* = .{ .a = t.a, .b = t.b, .coefficient = t.coefficient };
            const c = try N.countForCapacity(capacity, terms[0..expression.len]);
            rows += c.rows;
            products += c.terms;
        }
        const main = 64 * capacity + 338;
        const fixed = 3 * capacity + 4;
        const height = padded(rows);
        const facts = height * (512 + padded(2 * capacity + 2));
        std.debug.print("MAC_MODEL Miller K={d} original={d} rows={d} temps={d} padded={d} main={d} main_cells={d} native_MAC_cells={d} facts={d} opening_MAC={d} products={d}\n", .{ capacity, S.ROWS, rows, rows - S.ROWS, height, main, height * main, height * (main + fixed + 32), facts, main + fixed + 32, products });
        try std.testing.expect(rows >= S.ROWS);
    }
}
test "MAC6 complete joined pairing capacity cost" {
    const P = @import("../bn254_pairing/spec.zig");
    const PW = @import("../bn254_pairing/witness.zig");
    for ([_]usize{ 4, 6, 8, 12 }) |capacity| {
        var rows: usize = 0;
        var products: usize = 0;
        var assertions: usize = 0;
        for (&PW.ROM.nodes) |*node| {
            if (node.kind == .hint) continue;
            const expression = P.expression(node.*);
            var terms: [145]N.Term = undefined;
            for (expression.terms[0..expression.len], terms[0..expression.len]) |t, *out| out.* = .{ .a = t.a, .b = t.b, .coefficient = t.coefficient };
            const c = try N.countForCapacity(capacity, terms[0..expression.len]);
            rows += c.rows;
            products += c.terms;
            assertions += @intFromBool(expression.asserted != null);
        }
        const main = 64 * capacity + 338;
        const fixed = 3 * capacity + 4;
        const height = padded(rows);
        const hint_height = padded(P.HINTS);
        const frontier_height = padded(P.INITIAL + P.ASSERTIONS);
        // Current qualified hint95, 35/33/16 frontier, 1/1/16 BYTE table.
        const other_cells = hint_height * (3 + 95 + 32) + frontier_height * (35 + 33 + 16) + 256 * 18;
        const facts = height * (512 + padded(2 * capacity + 2)) + hint_height * 65 + frontier_height + 256;
        const cells = height * (main + fixed + 32) + other_cells;
        std.debug.print("MAC_MODEL Pairing K={d} original={d} rows={d} temps={d} padded={d} main={d} main_cells={d} total_cells_hint95={d} facts={d} opening_hint95={d} initial={d} hints={d} assertions={d} products={d}\n", .{ capacity, P.ARITHMETIC, rows, rows - P.ARITHMETIC, height, main, height * main, cells, facts, main + fixed + 32 + 130 + 84 + 18, P.INITIAL, P.HINTS, assertions, products });
        try std.testing.expectEqual(@as(usize, P.ASSERTIONS), assertions);
    }
}
