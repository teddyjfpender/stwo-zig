const std = @import("std");
const B = @import("../rv64_word16_cpu_request.zig");
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const Q = E.Q;
fn dense(n: u32) Q {
    return Q.fromPartialEvals(.{ E.q(n), E.q(n + 3), E.q(n + 7), E.q(n + 11) });
}
fn row(t: Q) B.ViewFor(Q) {
    var v: B.ViewFor(Q) = undefined;
    v.bus_id = dense(2).add(t.mul(dense(3)));
    v.use_immediate = dense(5).add(t.mul(dense(6)));
    for (0..4) |i| {
        const n: u32 = @intCast(11 * i + 20);
        v.a[i] = dense(n).add(t.mul(dense(n + 1)));
        v.register_b[i] = dense(n + 2).add(t.mul(dense(n + 3)));
        v.immediate[i] = dense(n + 4).add(t.mul(dense(n + 5)));
        v.effective_b[i] = dense(n + 6).add(t.mul(dense(n + 7)));
        v.c[i] = dense(n + 8).add(t.mul(dense(n + 9)));
    }
    return v;
}
test "word16 CPU payload is affine and immediate projection exactly quadratic" {
    var samples: [4][4]Q = undefined;
    var tuples: [3][B.PAYLOAD]Q = undefined;
    for (0..4) |i| {
        const v = row(E.q(@intCast(i)));
        var sink = E.Sink{ .values = &samples[i] };
        B.evaluate(Q, v, &sink);
        try std.testing.expectEqual(B.MUX_CONSTRAINTS, sink.count);
        if (i < 3) tuples[i] = B.payload(Q, v);
    }
    for (0..4) |i| {
        const third = samples[3][i].sub(samples[2][i].mul(E.q(3))).add(samples[1][i].mul(E.q(3))).sub(samples[0][i]);
        try std.testing.expect(third.isZero());
    }
    for (0..B.PAYLOAD) |i| try std.testing.expect(tuples[2][i].sub(tuples[1][i].mul(E.q(2))).add(tuples[0][i]).isZero());
    for ([_]u32{ 0, 1 }) |immediate| {
        var v = row(Q.zero());
        v.use_immediate = E.q(immediate);
        v.effective_b = if (immediate == 0) v.register_b else v.immediate;
        var residuals: [4]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        B.evaluate(Q, v, &sink);
        for (residuals) |value| try std.testing.expect(value.isZero());
        for (0..4) |i| {
            v.effective_b[i] = v.effective_b[i].add(Q.one());
            sink = .{ .values = &residuals };
            B.evaluate(Q, v, &sink);
            try std.testing.expect(!residuals[i].isZero());
            v.effective_b[i] = v.effective_b[i].sub(Q.one());
        }
    }
    try std.testing.expect(!B.physical_bus_closed);
}
test "word16 request hints preserve full64 operands and explicit branch result" {
    const add = B.project(.ADDI, 0xffff000180007fff, 1, 0xffffffffffffffff, 0x8000000000000000, false).?;
    try std.testing.expectEqualSlices(u16, &.{ 0x7fff, 0x8000, 1, 0xffff }, add.values[1..5]);
    try std.testing.expectEqualSlices(u16, &.{ 0xffff, 0xffff, 0xffff, 0xffff }, add.values[5..9]);
    try std.testing.expectEqualSlices(u16, &.{ 0, 0, 0, 0x8000 }, add.values[9..13]);
    const shift = B.project(.SLL, 1, 63, 7, 1 << 63, false).?;
    try std.testing.expectEqual(@as(u16, 63), shift.values[5]);
    const branch = B.project(.BGE, 0, 0, 100, 0xffffffffffffffff, true).?;
    try std.testing.expectEqualSlices(u16, &.{ 1, 0, 0, 0 }, branch.values[9..13]);
    try std.testing.expect(B.project(.LD, 0, 0, 0, 0, false) == null);
    try std.testing.expect(B.project(.JALR, 0, 0, 0, 0, false) == null);
}

test "word16 global pure function IDs are disjoint across every family" {
    const Operations = @import("stwo_riscv_frontend").rv64_air.word16_v1.operations;
    const Opcode = @import("stwo_riscv_frontend").rv64.decode.Opcode;
    var seen: [256]bool = @splat(false);
    const families = [_]Operations.Family{ .alu, .binary, .shift };
    var count: usize = 0;
    inline for (.{ Operations.Alu, Operations.Binary, Operations.Shift }, 0..) |Enum, i| {
        for (std.enums.values(Enum)) |op| {
            const id = Operations.busIdFor(families[i], @intFromEnum(op));
            try std.testing.expect(!seen[id]);
            seen[id] = true;
            count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 19), count);
    for (std.enums.values(Opcode)) |opcode| {
        if (Operations.classify(opcode)) |operation| try std.testing.expect(seen[operation.busId()]);
    }
    const add = B.project(.ADD, 1, 2, 3, 4, false).?;
    const immediate = B.project(.ADDI, 1, 2, 3, 4, false).?;
    const binary = B.project(.AND, 1, 2, 3, 4, false).?;
    const shift = B.project(.SLL, 1, 2, 3, 4, false).?;
    try std.testing.expectEqual(@as(u16, 0), add.values[0]);
    try std.testing.expectEqual(add.values[0], immediate.values[0]);
    try std.testing.expectEqual(@as(u16, 16), binary.values[0]);
    try std.testing.expectEqual(@as(u16, 32), shift.values[0]);
}
