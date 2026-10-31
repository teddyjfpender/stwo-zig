const std = @import("std");
const core = @import("stwo_core");
const R = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram;
const F = @import("../rv64_closed_ram_fixture.zig");
const P = @import("../rv64_closed_ram_public.zig");
const C = @import("../rv64_closed_ram.zig");
const Native = @import("rv64_closed_ram_test.zig");
const Q = core.fields.qm31.QM31;
test "closed RAM future fork duplicate image owner padding permission and range attacks fail actual proofs" {
    for ([_]C.Attack{ .future_before, .duplicate_init, .orphan_write, .readonly_write, .bad_image, .noncanonical, .padding, .owner_weight, .owner_origin, .fork, .range_count }) |attack| {
        if (C.produce(std.testing.allocator, P.fixture(), attack)) |encoded_| {
            var encoded = encoded_;
            defer encoded.deinit(std.testing.allocator);
            try std.testing.expectError(error.ConstraintsNotSatisfied, C.verify(std.testing.allocator, P.fixture(), encoded));
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}
test "closed RAM receiver rejects balanced physical claim changes and different terminal image" {
    var encoded = try C.produce(std.testing.allocator, P.fixture(), .none);
    defer encoded.deinit(std.testing.allocator);
    const old = encoded.claims;
    encoded.claims[0].ram = encoded.claims[0].ram.add(Q.one());
    encoded.claims[1].ram = encoded.claims[1].ram.sub(Q.one());
    if (C.verify(std.testing.allocator, P.fixture(), encoded)) |_| return error.AcceptedBalancedClaimAttack else |_| {}
    encoded.claims = old;
    encoded.claims[4].ram = Q.one();
    encoded.claims[0].ram = encoded.claims[0].ram.sub(Q.one());
    try std.testing.expectError(error.UnusedClosedRamClaim, C.verify(std.testing.allocator, P.fixture(), encoded));
    encoded.claims = old;
    var terminal = P.TERMINAL;
    terminal[0].state.value += 1;
    var other = P.fixture();
    other.terminal = &terminal;
    if (C.verify(std.testing.allocator, other, encoded)) |_| return error.AcceptedWrongTerminal else |_| {}
    var initial = P.INITIAL;
    initial[0].state.value += 1;
    other = P.fixture();
    other.initial = &initial;
    if (C.verify(std.testing.allocator, other, encoded)) |_| return error.AcceptedWrongImage else |_| {}
    other = P.fixture();
    other.split = 3;
    if (C.verify(std.testing.allocator, other, encoded)) |_| return error.AcceptedWrongCount else |_| {}
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(std.testing.allocator, encoded.bytes);
    defer proof.deinit(std.testing.allocator);
    proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
    const tampered = try @import("stwo_proof_wire").encodeProofBytesBinary(std.testing.allocator, proof);
    defer std.testing.allocator.free(tampered);
    if (C.verify(std.testing.allocator, P.fixture(), .{ .bytes = tampered, .claims = old })) |_| return error.AcceptedWrongRoot else |_| {}
}
test "closed RAM independently expected owner rejects time forks missing image and duplicate INIT" {
    var operations = P.OPERATIONS;
    operations[1].address = operations[0].address;
    operations[1].epoch = operations[0].epoch;
    operations[1].tick = operations[0].tick;
    var expected = P.fixture();
    expected.operations = &operations;
    try std.testing.expectError(error.DuplicateClosedRamOrigin, expected.validate());
    operations = P.OPERATIONS;
    operations[0].address = 0x4000;
    try std.testing.expectError(error.ClosedRamAddressOutsideImage, expected.validate());
    var initial = P.INITIAL;
    initial[1].address = initial[0].address;
    expected = P.fixture();
    expected.initial = &initial;
    try std.testing.expectError(error.InvalidClosedRamImage, expected.validate());
}
test "closed RAM strict pole failure publishes no interaction and can retry" {
    var fixture = try F.Fixture.init(std.testing.allocator, P.fixture());
    defer fixture.deinit();
    var ch = Native.challenges();
    ch.ram.offset = Q.zero();
    ch.ram.coefficients = @splat(Q.zero());
    if (fixture.traces[0].generate(ch)) |_| return error.AcceptedRamPole else |_| {}
    try std.testing.expectEqual(@as(usize, 0), fixture.traces[0].interaction.len);
    _ = try fixture.traces[0].generate(Native.challenges());
    try std.testing.expect(fixture.traces[0].interaction.len != 0);
}
fn allocationScenario(a: std.mem.Allocator) !void {
    var f = try F.Fixture.init(a, P.fixture());
    defer f.deinit();
    _ = try f.generate(Native.challenges());
}
test "closed RAM native sources all allocation failures cleanly release owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}

test "closed RAM locally valid fork and wrong owner cannot close the global ledger" {
    for ([_]C.Attack{ .fork, .owner_origin }) |attack| {
        var fixture = try F.Fixture.init(std.testing.allocator, P.fixture());
        defer fixture.deinit();
        try C.mutate(&fixture, attack);
        const ch = Native.challenges();
        const claims = try fixture.generate(ch);
        var sums: [4]Q = @splat(Q.zero());
        for (&fixture.traces, claims) |*trace, claim| {
            try Native.audit(trace, claim, ch);
            for (claim.values(), &sums) |v, *sum| sum.* = sum.add(v);
        }
        const affected: usize = if (attack == .fork) 0 else 1;
        try std.testing.expect(!sums[affected].isZero());
        for (sums, 0..) |sum, i| if (i != affected) try std.testing.expect(sum.isZero());
    }
}
