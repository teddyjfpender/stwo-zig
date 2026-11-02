const std = @import("std");
const K = @import("case.zig");
const Catalog = @import("catalog_services.zig");
const a = std.testing.allocator;

test "services: every exported component matches its native domain evaluator bit for bit" {
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rng = prng.random();
    var cases: std.ArrayList(K.Case) = .empty;
    defer {
        for (cases.items) |*c| c.deinit(a);
        cases.deinit(a);
    }
    try Catalog.all(a, rng, &cases);
    // keccak 1 + secp-family 11 + bulk 9 + sponge 2 + LS-D64 2.
    try std.testing.expectEqual(@as(usize, 25), cases.items.len);
    for (cases.items) |*c| {
        try K.expectParity(a, c, rng);
        const s = try c.exported.program.stats(a);
        std.debug.print("composition IR {s}: constraints={d} nodes={d} inputs={d} params={d} max_degree={d} parity=pass\n", .{ c.name, s.constraints, s.nodes, s.inputs, s.parameters, s.max_degree });
    }
}
