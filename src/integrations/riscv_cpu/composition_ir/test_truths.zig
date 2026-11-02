const std = @import("std");
const K = @import("case.zig");
const Catalog = @import("catalog_truths.zig");
const a = std.testing.allocator;

test "truths: every exported component matches its native domain evaluator bit for bit" {
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rng = prng.random();
    var cases: std.ArrayList(K.Case) = .empty;
    defer {
        for (cases.items) |*c| c.deinit(a);
        cases.deinit(a);
    }
    try Catalog.all(a, rng, &cases);
    for (cases.items) |*c| {
        var timer = try std.time.Timer.start();
        try K.expectParity(a, c, rng);
        const shape = c.exported.shape;
        const stats = try c.exported.program.stats(a);
        std.debug.print("truth {s}: log {d}/{d} constraints {d} nodes {d} inputs {d} params {d} max_degree {d} offsets [{d},{d}] parity ok ({d} ms)\n", .{ c.name, shape.log_size, shape.eval_log, stats.constraints, stats.nodes, stats.inputs, stats.parameters, stats.max_degree, stats.min_offset, stats.max_offset, timer.read() / std.time.ns_per_ms });
    }
}
