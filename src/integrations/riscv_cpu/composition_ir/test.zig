const std = @import("std");
const R = @import("record.zig");
const K = @import("case.zig");
const Catalog = @import("catalog.zig");
const a = std.testing.allocator;
test {}

test "CPU layouts: IR composition equals the native domain evaluator bit for bit" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rng = prng.random();
    for ([_][2]bool{ .{ false, false }, .{ true, false }, .{ true, true } }) |mode| {
        var case = try Catalog.cpu(a, rng, 6, mode[0], mode[1]);
        defer case.deinit(a);
        try K.expectParity(a, &case, rng);
    }
}

test "a forged exported program is caught by the parity check" {
    var prng = std.Random.DefaultPrng.init(0xBAD);
    const rng = prng.random();
    var case = try Catalog.cpu(a, rng, 6, true, false);
    defer case.deinit(a);
    const program = &case.exported.program;
    // Flip one literal constant that is not 0/1, then re-seal the identity so
    // only the semantic check can notice.
    var mutated = false;
    for (program.constants) |*words| if (words[0] > 1 and std.mem.allEqual(u32, words[1..], 0)) {
        words[0] = (words[0] + 1) % core_modulus;
        mutated = true;
        break;
    };
    try std.testing.expect(mutated);
    program.identity = program.identityDigest();
    var trace = try R.RandomTrace.init(a, rng, case.exported.shape, case.fill);
    defer trace.deinit(a);
    try std.testing.expectError(error.CompositionIrParityMismatch, R.checkDomain(a, &case.exported, case.prover, &trace, R.randomQ(rng)));
}
const core_modulus = @import("stwo_core").fields.m31.Modulus;

test "CPU-proof core roster: every component kind matches its native domain evaluator" {
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rng = prng.random();
    var cases: std.ArrayList(K.Case) = .empty;
    defer {
        for (cases.items) |*c| c.deinit(a);
        cases.deinit(a);
    }
    try Catalog.all(a, rng, &cases);
    for (cases.items) |*c| try K.expectParity(a, c, rng);
}
