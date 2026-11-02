const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const R = A.memory.closed_ram;
const Boundary = A.memory.load_store_v2.boundary_source;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
fn reference(cells: []const R.types.Cell, initial: bool, ch: R.types.RamChallenges) !Q {
    var claim = Q.zero();
    for (cells) |cell| {
        var tuple: [14]Q = undefined;
        tuple[0] = Q.one();
        @memcpy(tuple[1..5], &R.types.word(Q, cell.address));
        tuple[5] = E.q(cell.state.epoch);
        tuple[6] = E.q(@as(u16, @truncate(cell.state.tick)));
        tuple[7] = E.q(cell.state.tick >> 16);
        @memcpy(tuple[8..12], &R.types.word(Q, cell.state.value));
        tuple[12] = E.q(cell.state.rights & 1);
        tuple[13] = E.q(cell.state.rights >> 1);
        const inverse = try ch.denominatorFor(Q, tuple).inv();
        claim = if (initial) claim.sub(inverse) else claim.add(inverse);
    }
    return claim;
}
fn challenge() R.types.RamChallenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch = R.types.RamChallenges{ .offset = channel.drawSecureFelt(), .coefficients = undefined };
    for (&ch.coefficients) |*c| c.* = channel.drawSecureFelt();
    return ch;
}
test "native RAM expected claims match scalar full64 oracle through full and partial4096 chunks" {
    const cells = try a.alloc(R.types.Cell, 8193);
    defer a.free(cells);
    var rng = std.Random.DefaultPrng.init(0x94619ac83);
    const random = rng.random();
    for (cells, 0..) |*cell, index| cell.* = .{ .address = random.int(u64) & ~@as(u64, 7), .state = .{ .value = random.int(u64), .epoch = random.int(u16), .tick = @truncate(random.int(u32)), .rights = @truncate(index) } };
    cells[0] = .{ .address = 0xfffffffffffffff8, .state = .{ .value = 0xffffffffffffffff, .epoch = 65535, .tick = 0xffffff, .rights = 3 } };
    const ch = challenge();
    for ([_]usize{ 0, 1, 4095, 4096, 4097, 8193 }) |count| for ([_]bool{ false, true }) |initial| try std.testing.expectEqualDeep(try reference(cells[0..count], initial, ch), try Boundary.expectedClaim(cells[0..count], initial, ch));
}
test "native expected claims reject first second-window and final poles without poisoning retry" {
    const cells = try a.alloc(R.types.Cell, 8193);
    defer a.free(cells);
    for (cells, 0..) |*cell, index| cell.* = .{ .address = 8 * @as(u64, @intCast(index)), .state = .{ .value = index, .rights = 3 } };
    var ch = R.types.RamChallenges{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    ch.coefficients[8] = Q.one();
    for ([_]usize{ 0, 4096, 8192 }) |where| {
        ch.offset = E.q(@intCast(where));
        try std.testing.expectError(error.DivisionByZero, Boundary.expectedClaim(cells, true, ch));
        try std.testing.expectError(error.DivisionByZero, Boundary.expectedClaim(cells, false, ch));
        const honest = challenge();
        try std.testing.expectEqualDeep(try reference(cells, false, honest), try Boundary.expectedClaim(cells, false, honest));
    }
}
