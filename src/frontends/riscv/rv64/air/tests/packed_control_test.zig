const std = @import("std");
const E = @import("../evaluation.zig");
const C = @import("../full/packed_control_constraints.zig");
const Q = E.Q;
const L = E.L;

fn pack(value: u64) C.Word {
    return .{ E.q(@intCast(value & 0xffffff)), E.q(@intCast((value >> 24) & 0xffffff)), E.q(@intCast(value >> 48)) };
}
fn put(main: *E.Main, word: L.Word, value: u64) void {
    for (0..8) |i| main[L.byte(word, i)] = E.q(@intCast((value >> @as(u6, @intCast(8 * i))) & 255));
    for (0..64) |i| main[L.bit(word, i)] = E.q(@intCast((value >> @as(u6, @intCast(i))) & 1));
}
fn clean(values: []const Q) bool {
    for (values) |value| if (!value.isZero()) return false;
    return true;
}
fn qualify(op: E.O, increment: u64, target: u64, next: u64, result: u64, address: u64, taken: bool) !void {
    var fixed: E.Fixed = @splat(Q.zero());
    fixed[L.fixed.active] = Q.one();
    fixed[L.fixed.opcode_start + @intFromEnum(op)] = Q.one();
    var main: E.Main = @splat(Q.zero());
    put(&main, .result, result);
    put(&main, .address, address);
    main[L.taken] = E.q(@intFromBool(taken));
    const view = E.View{ .f = &fixed, .m = &main };
    var output: [C.CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &output };
    C.evaluate(view, pack(increment), pack(target), pack(next), &sink);
    try std.testing.expectEqual(C.CONSTRAINTS, sink.count);
    try std.testing.expect(clean(&output));
    // Every limb of the receiver-visible next PC is constrained separately.
    for (0..3) |i| {
        var forged = pack(next);
        forged[i] = forged[i].add(Q.one());
        sink.count = 0;
        C.evaluate(view, pack(increment), pack(target), forged, &sink);
        try std.testing.expect(!clean(&output));
    }
    const branch = switch (op) {
        .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => true,
        else => false,
    };
    for (0..3) |i| {
        if (op == .AUIPC or op == .JAL or (branch and taken)) {
            var forged = pack(target);
            forged[i] = forged[i].add(Q.one());
            sink.count = 0;
            C.evaluate(view, pack(increment), forged, pack(next), &sink);
            try std.testing.expect(!clean(&output));
        }
        if (!branch or !taken) {
            var forged = pack(increment);
            forged[i] = forged[i].add(Q.one());
            sink.count = 0;
            C.evaluate(view, forged, pack(target), pack(next), &sink);
            try std.testing.expect(!clean(&output));
        }
    }
    if (op == .AUIPC or op == .JAL or op == .JALR) for (0..8) |i| {
        main[L.byte(.result, i)] = main[L.byte(.result, i)].add(Q.one());
        sink.count = 0;
        C.evaluate(view, pack(increment), pack(target), pack(next), &sink);
        try std.testing.expect(!clean(&output));
        main[L.byte(.result, i)] = main[L.byte(.result, i)].sub(Q.one());
    };
}

test "packed control preserves full64 wrap targets links and JALR low bits" {
    try qualify(.ADDI, 0xfedcba9876543210, 0, 0xfedcba9876543210, 0, 0, false);
    try qualify(.AUIPC, 0, 0xfffffffffffff004, 0, 0xfffffffffffff004, 0, false);
    try qualify(.JAL, 0, 0xfffffffffffff000, 0xfffffffffffff000, 0, 0, true); // pc+4 wraps
    try qualify(.JAL, 0x100000004, 0, 0, 0x100000004, 0, true); // negative immediate wraps target
    try qualify(.JALR, 0xfffffffffffffff0, 0, 0xffffffffffffffff & ~@as(u64, 3), 0xfffffffffffffff0, 0xffffffffffffffff & ~@as(u64, 2), true);
    try qualify(.JALR, 0x100000004, 0, 0x100000000, 0x100000004, 0x100000001, true);
    for ([_]E.O{ .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU }) |op| {
        try qualify(op, 0x100000000, 0xfffffffffffff000, 0xfffffffffffff000, 0, 0, true);
        try qualify(op, 0x100000000, 0xfffffffffffff000, 0x100000000, 0, 0, false);
    }
    var fixed: E.Fixed = @splat(Q.zero());
    fixed[L.fixed.active] = Q.one();
    fixed[L.fixed.opcode_start + @intFromEnum(E.O.JALR)] = Q.one();
    var main: E.Main = @splat(Q.zero());
    put(&main, .address, 0x100000003);
    var output: [C.CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &output };
    C.evaluate(.{ .f = &fixed, .m = &main }, pack(0), pack(0), pack(0x100000002), &sink);
    try std.testing.expect(!output[C.CONSTRAINTS - 1].isZero()); // retains ISA alignment trap
}

fn dense(x: u32) Q {
    const m = @import("stwo_core").fields.m31.M31;
    return Q.fromM31Array(.{ m.fromCanonical(x), m.fromCanonical(x + 3), m.fromCanonical(x + 7), m.fromCanonical(x + 11) });
}
fn packedBytes(bytes: []const Q) C.Word {
    var result: C.Word = @splat(Q.zero());
    for (bytes, 0..) |value, i| result[i / 3] = result[i / 3].add(value.mul(E.q(@as(u32, 1) << @as(u5, @intCast(8 * (i % 3))))));
    return result;
}
/// Independent historical per-byte equations; grouping them is an exact
/// identity even for non-Boolean selectors and arbitrary extension samples.
fn oracle(v: E.View) [49]Q {
    var result: [49]Q = undefined;
    var sink = E.Sink{ .values = &result };
    const jumps = v.sum(&.{ .JAL, .JALR });
    const branch = v.sum(&.{ .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU });
    for (0..8) |i| {
        sink.emit(v.op(.AUIPC).mul(v.byte(.result, i).sub(v.f[L.fixed.target + i])));
        sink.emit(jumps.mul(v.byte(.result, i).sub(v.f[L.fixed.increment + i])));
    }
    for (0..8) |i| {
        const next = v.f[L.fixed.next_pc + i];
        const inc = v.f[L.fixed.increment + i];
        const target = v.f[L.fixed.target + i];
        sink.emit(v.f[L.fixed.active].sub(branch).sub(jumps).mul(next.sub(inc)));
        sink.emit(branch.mul(next.sub(inc).sub(v.m[L.taken].mul(target.sub(inc)))));
        sink.emit(v.op(.JAL).mul(next.sub(target)));
        sink.emit(v.op(.JALR).mul(next.sub(v.byte(.address, i)).add(if (i == 0) v.bit(.address, 0) else Q.zero())));
    }
    sink.emit(v.op(.JALR).mul(v.bit(.address, 1)));
    return result;
}

test "packed control equals grouped historical polynomials and has degree at most three" {
    var values: [7][C.CONSTRAINTS]Q = undefined;
    for (&values, 0..) |*row, t| {
        var fixed: E.Fixed = undefined;
        var main: E.Main = undefined;
        for (&fixed, 0..) |*x, i| x.* = dense(@intCast(i + 1)).add(dense(@intCast(i + 19)).mul(E.q(@intCast(t))));
        for (&main, 0..) |*x, i| x.* = dense(@intCast(i + 101)).add(dense(@intCast(i + 307)).mul(E.q(@intCast(t))));
        const view = E.View{ .f = &fixed, .m = &main };
        var sink = E.Sink{ .values = row };
        C.evaluate(view, packedBytes(fixed[L.fixed.increment..][0..8]), packedBytes(fixed[L.fixed.target..][0..8]), packedBytes(fixed[L.fixed.next_pc..][0..8]), &sink);
        const old = oracle(view);
        var grouped: [C.CONSTRAINTS]Q = @splat(Q.zero());
        for (0..8) |i| {
            const power = E.q(@as(u32, 1) << @as(u5, @intCast(8 * (i % 3))));
            for (0..2) |kind| grouped[(i / 3) * 2 + kind] = grouped[(i / 3) * 2 + kind].add(old[i * 2 + kind].mul(power));
            for (0..4) |kind| grouped[6 + (i / 3) * 4 + kind] = grouped[6 + (i / 3) * 4 + kind].add(old[16 + i * 4 + kind].mul(power));
        }
        grouped[18] = old[48];
        for (row, grouped) |actual, expected| try std.testing.expect(actual.eql(expected));
    }
    for (0..C.CONSTRAINTS) |c| {
        var diffs: [7]Q = undefined;
        for (&diffs, values) |*value, row| value.* = row[c];
        for (0..4) |order| for (0..6 - order) |i| {
            diffs[i] = diffs[i + 1].sub(diffs[i]);
        };
        for (diffs[0..3]) |value| try std.testing.expect(value.isZero());
    }
}

test "arithmetic legacy wrappers retain every residual and packed policy omits exactly49" {
    const arithmetic = @import("../arithmetic_constraints.zig");
    var fixed: E.Fixed = undefined;
    var main: E.Main = undefined;
    for (&fixed, 0..) |*value, i| value.* = dense(@intCast(i + 13));
    for (&main, 0..) |*value, i| value.* = dense(@intCast(i + 37));
    const view = E.View{ .f = &fixed, .m = &main };
    var legacy: [1024]Q = undefined;
    var explicit: [1024]Q = undefined;
    for ([_]bool{ false, true }) |byte_operations| {
        var old = E.Sink{ .values = &legacy };
        var selected = E.Sink{ .values = &explicit };
        arithmetic.evaluateProfile(view, &old, byte_operations);
        arithmetic.evaluateProfileWithControl(view, &selected, byte_operations, .bytes_v1);
        try std.testing.expectEqual(old.count, selected.count);
        for (legacy[0..old.count], explicit[0..selected.count]) |before, after| try std.testing.expect(before.eql(after));
        selected.count = 0;
        arithmetic.evaluateProfileWithControl(view, &selected, byte_operations, .limbs24_v2);
        try std.testing.expectEqual(old.count - 49, selected.count);
    }
}
