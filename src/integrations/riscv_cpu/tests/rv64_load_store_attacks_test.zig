const std = @import("std");
const core = @import("stwo_core");
const C = @import("../rv64_load_store.zig");
const Data = C.Data;
const F = @import("../rv64_load_store_fixture.zig");
const X = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v1;
const Native = @import("rv64_load_store_test.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
test "LS malformed operands signs address alignment bytes clock permissions owner and counts fail physical proof" {
    const data = Data.fixture();
    for ([_]C.Attack{ .wrong_store_b, .wrong_store_b_high, .preserved_byte, .wrong_signed_load, .misaligned, .bad_add_carry, .effective_alias, .quotient_alias, .wrong_selection, .wrong_parity, .readonly_write, .orphan_write, .future_before, .fork, .inactive, .owner_weight, .range_count, .selection_count, .selection_weight_cancel }) |attack| {
        if (C.produce(std.testing.allocator, data.expected(), attack)) |encoded_| {
            var encoded = encoded_;
            defer encoded.deinit(std.testing.allocator);
            try std.testing.expectError(error.ConstraintsNotSatisfied, C.verify(std.testing.allocator, data.expected(), encoded));
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}
test "LS byte-selection paired truth equals independent little-endian oracle for all inputs and parities" {
    for (0..65536) |input| {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(input), .little);
        var fixed: [4]M = undefined;
        for (X.selection.fixedFact(input), &fixed) |value, *v| v.* = M.fromCanonical(value);
        inline for (0..2) |parity| {
            const wanted = [5]u32{ @intCast(input), parity, bytes[parity], bytes[parity] >> 7, bytes[1] >> 7 };
            try std.testing.expectEqualSlices(u32, &wanted, &X.selection.fact(2 * input + parity));
            const actual = X.selection.tupleFor(M, &fixed, parity);
            for (actual, wanted) |a, b| try std.testing.expectEqual(b, a.v);
            try std.testing.expectEqual(2 * input + parity, try X.selection.rowIndex(wanted));
        }
    }
    try std.testing.expectError(error.InvalidLoadStoreSelection, X.selection.rowIndex(.{ 65536, 0, 0, 0, 0 }));
    try std.testing.expectError(error.InvalidLoadStoreSelection, X.selection.rowIndex(.{ 128, 0, 128, 0, 0 }));
}
test "LS paired selection pole rejects either zero denominator even at zero multiplicity and retries" {
    var trace = try X.trace.Trace.init(std.testing.allocator, .selection, 16, 0);
    defer trace.deinit();
    for (0..2) |parity| {
        var ch = Native.challenges();
        ch.selection.offset = if (parity == 0) Q.zero() else Q.one();
        ch.selection.coefficients = @splat(Q.zero());
        ch.selection.coefficients[1] = Q.one();
        if (trace.generate(ch)) |_| return error.AcceptedSelectionPole else |_| {}
        try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    }
    _ = try trace.generate(Native.challenges());
    try std.testing.expect(trace.interaction.len != 0);
}
test "LS local fork and unused store-B upper limb need distinct global RAM and owner closures" {
    const data = Data.fixture();
    for ([_]C.Attack{ .fork, .wrong_store_b_high }) |attack| {
        var fixture = try F.Fixture.init(std.testing.allocator, data.expected());
        defer fixture.deinit();
        try C.mutate(&fixture, attack);
        const ch = Native.challenges();
        const claims = try fixture.generate(ch);
        try Native.audit(&fixture.ls[0], claims[0], ch);
        try Native.audit(&fixture.ls[1], claims[1], ch);
        try Native.audit(&fixture.owner, claims[4], ch);
        try Native.audit(&fixture.selection, claims[7], ch);
        var sums: [5]Q = @splat(Q.zero());
        for (claims) |claim| for (claim.values(), &sums) |v, *sum| {
            sum.* = sum.add(v);
        };
        const affected: usize = if (attack == .fork) 0 else 1;
        try std.testing.expect(!sums[affected].isZero());
        for (sums, 0..) |sum, i| if (i != affected) try std.testing.expect(sum.isZero());
    }
}

test "LS fresh receiver rejects balanced claims different input terminal raw instruction and root" {
    var data = Data.fixture();
    var encoded = try C.produce(std.testing.allocator, data.expected(), .none);
    defer encoded.deinit(std.testing.allocator);
    const saved = encoded.claims;
    encoded.claims[0].owner = encoded.claims[0].owner.add(Q.one());
    encoded.claims[1].owner = encoded.claims[1].owner.sub(Q.one());
    if (C.verify(std.testing.allocator, data.expected(), encoded)) |_| return error.AcceptedBalancedLsClaim else |_| {}
    encoded.claims = saved;
    encoded.claims[4].ram = Q.one();
    encoded.claims[0].ram = encoded.claims[0].ram.sub(Q.one());
    try std.testing.expectError(error.UnusedLoadStoreClaim, C.verify(std.testing.allocator, data.expected(), encoded));
    encoded.claims = saved;
    data.terminal[0].state.value ^= 1;
    if (C.verify(std.testing.allocator, data.expected(), encoded)) |_| return error.AcceptedWrongTerminal else |_| {}
    data = Data.fixture();
    data.initial[1].state.value ^= 1;
    if (C.verify(std.testing.allocator, data.expected(), encoded)) |_| return error.AcceptedWrongImage else |_| {}
    data = Data.fixture();
    data.operations[0].instruction = Data.loadWord(4, 0);
    if (C.verify(std.testing.allocator, data.expected(), encoded)) |_| return error.AcceptedWrongOpcode else |_| {}
    data = Data.fixture();
    var wrong_count = data.expected();
    wrong_count.split -= 1;
    if (C.verify(std.testing.allocator, wrong_count, encoded)) |_| return error.AcceptedWrongCount else |_| {}
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(std.testing.allocator, encoded.bytes);
    defer proof.deinit(std.testing.allocator);
    proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
    const bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(std.testing.allocator, proof);
    defer std.testing.allocator.free(bytes);
    data = Data.fixture();
    if (C.verify(std.testing.allocator, data.expected(), .{ .bytes = bytes, .claims = saved })) |_| return error.AcceptedWrongRoot else |_| {}
}
fn allocationScenario(a: std.mem.Allocator) !void {
    const data = Data.fixture();
    var f = try F.Fixture.init(a, data.expected());
    defer f.deinit();
    _ = try f.generate(Native.challenges());
}
test "LS sources clean all allocation failures before publication" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}

test "LS expected request admission binds natural alignment raw decoder policy and unique origins" {
    var data = Data.fixture();
    data.operations[16].instruction = Data.loadWord(1, 1);
    try std.testing.expectError(error.InvalidLoadStoreOperation, data.expected().validate());
    data = Data.fixture();
    data.operations[0].tick = 5;
    try std.testing.expectError(error.InvalidLoadStoreOperation, data.expected().validate());
    data = Data.fixture();
    data.operations[0].instruction = 0x00108093;
    try std.testing.expectError(error.NotLoadStoreInstruction, data.expected().validate());
    data = Data.fixture();
    data.operations[1].tick = data.operations[0].tick;
    try std.testing.expectError(error.DuplicateLoadStoreOrigin, data.expected().validate());
    data = Data.fixture();
    data.terminal[0].state.rights = 0;
    try std.testing.expectError(error.InvalidLoadStoreImage, data.expected().validate());
    data = Data.fixture();
    data.initial[1].address = data.initial[0].address;
    try std.testing.expectError(error.InvalidLoadStoreImage, data.expected().validate());
    // A field inverse of eight is not an integer aligned-word quotient. This
    // is why quotient canonicality is retained in the conservative local AIR.
    const inverse8 = try M.fromCanonical(8).inv();
    try std.testing.expect(M.one().sub(inverse8.mul(M.fromCanonical(8))).isZero());
    try std.testing.expect(inverse8.v >= 65536);
}
