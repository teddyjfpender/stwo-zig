const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const W = frontend.rv64_air.word16_cpu;
const E = frontend.rv64_air.evaluation;
const L = W.layout;
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
fn instruction(funct3: u32, rd: u32, rs1: u32, rs2: u32) u32 {
    return 0x33 | (rd << 7) | (funct3 << 12) | (rs1 << 15) | (rs2 << 20);
}
const words = [_]u32{ instruction(7, 3, 1, 2), instruction(6, 1, 3, 1), instruction(4, 0, 1, 2), instruction(4, 2, 1, 3) };
fn public() W.public.Public {
    var result = W.public.Public{ .steps = 4, .initial_pc = 4096, .final_pc = 4112, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    result.initial_registers[1] = 0xffff000180007fff;
    result.initial_registers[2] = 0x7fffffff8000ffff;
    result.final_registers[1] = result.initial_registers[1];
    result.final_registers[3] = result.initial_registers[1] & result.initial_registers[2];
    result.final_registers[2] = result.initial_registers[1] ^ result.final_registers[3];
    result.register_clocks[1] = 13;
    result.register_clocks[2] = 15;
    result.register_clocks[3] = 14;
    return result;
}
fn dense(value: u32) Q {
    return Q.fromPartialEvals(.{ E.q(value), E.q(value + 1), E.q(value + 3), E.q(value + 7) });
}
fn challenges() W.lookup.Challenges {
    const offset = Q.fromPartialEvals(.{ E.q(1000003), Q.one(), Q.zero(), Q.zero() });
    var result: W.lookup.Challenges = undefined;
    result.register.offset = offset;
    result.function.offset = offset;
    result.rom.offset = offset;
    for (&result.register.coefficients, 0..) |*v, i| v.* = E.q(@intCast(i + 2));
    for (&result.function.coefficients, 0..) |*v, i| v.* = E.q(@intCast(i + 17));
    for (&result.rom.coefficients, 0..) |*v, i| v.* = E.q(@intCast(i + 41));
    result.range16 = .{ .offset = offset, .coefficient = E.q(3) };
    result.range8 = .{ .offset = offset, .coefficient = E.q(5) };
    return result;
}
fn dictionary(count: usize, ch: W.lookup.RangeChallenges) ![]Q {
    const input = try a.alloc(Q, count);
    defer a.free(input);
    const result = try a.alloc(Q, count);
    errdefer a.free(result);
    for (input, 0..) |*v, i| v.* = ch.offset.sub(ch.coefficient.mulM31(M.fromCanonical(@intCast(i))));
    try core.fields.batchInverseInPlace(Q, input, result);
    return result;
}
fn fill(values: []Q, t: Q, seed: u32) void {
    for (values, 0..) |*value, i| value.* = dense(seed + @as(u32, @intCast(2 * i))).add(t.mul(dense(seed + @as(u32, @intCast(2 * i + 1)))));
}
test "thin CPU every emitted polynomial is degree at most three on dense QM31 lines" {
    const ch = challenges();
    const claim = W.public.Claims{ .register = dense(3), .function = dense(7), .rom = dense(13), .range16 = dense(17), .range8 = dense(23) };
    var samples: [5][L.CONSTRAINTS]Q = undefined;
    var fixed: [3]Q = undefined;
    var main: [L.main.COUNT]Q = undefined;
    var previous_main: [L.main.COUNT]Q = undefined;
    var current: [L.inter.COUNT]Q = undefined;
    var previous: [L.inter.COUNT]Q = undefined;
    for (0..5) |sample| {
        const t = E.q(@intCast(sample));
        fill(&fixed, t, 1);
        fill(&main, t, 19);
        fill(&previous_main, t, 113);
        fill(&current, t, 211);
        fill(&previous, t, 337);
        var sink = E.Sink{ .values = &samples[sample] };
        W.equations.emitFor(Q, &fixed, &main, &previous_main, &current, &previous, public(), claim, ch, &sink);
        try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
    }
    var has_cubic = false;
    for (0..L.CONSTRAINTS) |index| {
        const fourth = samples[4][index].sub(samples[3][index].mul(E.q(4))).add(samples[2][index].mul(E.q(6))).sub(samples[1][index].mul(E.q(4))).add(samples[0][index]);
        try std.testing.expect(fourth.isZero());
        has_cubic = has_cubic or !samples[3][index].sub(samples[2][index].mul(E.q(3))).add(samples[1][index].mul(E.q(3))).sub(samples[0][index]).isZero();
    }
    try std.testing.expect(has_cubic);
}
test "thin CPU projection closes real aliasing x0 full64 register and range relations" {
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 4096, .size = 16, .permissions = .{ .read = true, .execute = true } });
    for (words, 0..) |raw, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(4096 + 4 * i, &bytes);
    }
    var cpu = rv.machine.Cpu.init(4096, 0);
    cpu.regs = public().initial_registers;
    var records: [4]rv.machine.Retirement = undefined;
    for (&records) |*record| record.* = try cpu.step(&memory);
    try std.testing.expectEqualSlices(u64, &public().final_registers, &cpu.regs);
    var rom = try W.rom.Setup.init(a, .{ .base = 4096, .words = &words });
    defer rom.deinit();
    var source = try W.trace.Source.init(a, &rom, public(), 5, &records);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(W.trace.Metadata));
    const facts = try source.binaryFacts(a);
    defer a.free(facts);
    try std.testing.expect(facts[2].c != 0); // rd=x0 still proves the true result.
    const ch = challenges();
    const low = try dictionary(65536, ch.range16);
    defer a.free(low);
    const high = try dictionary(256, ch.range8);
    defer a.free(high);
    const claims = try source.generate(ch, low, high);
    var total_low = Q.zero();
    var total_high = Q.zero();
    for (source.range16_counts, low) |count, inverse| total_low = total_low.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
    for (source.range8_counts, high) |count, inverse| total_high = total_high.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
    try std.testing.expect(claims.range16.eql(total_low) and claims.range8.eql(total_high));
    const boundary_fixed = try W.fixed.boundary(a);
    defer a.free(boundary_fixed);
    var boundary_claim = Q.zero();
    for (0..32) |row| {
        const pos = L.physical(row, 5);
        var fixed: [34]Q = undefined;
        for (&fixed, 0..) |*v, c| v.* = Q.fromBase(boundary_fixed[c * 32 + pos]);
        const before = try ch.register.denominatorFor(Q, W.boundary.tupleFor(Q, &fixed, public(), false)).inv();
        const after = try ch.register.denominatorFor(Q, W.boundary.tupleFor(Q, &fixed, public(), true)).inv();
        boundary_claim = boundary_claim.add(after).sub(before);
    }
    try std.testing.expect(claims.register.add(boundary_claim).isZero());
    for (0..32) |row| {
        const pos = L.physical(row, 5);
        const prev_pos = L.physical((row + 31) % 32, 5);
        var fixed = [_]Q{ E.q(@intCast(row)), E.q(@intFromBool(row == 0)), E.q(@intFromBool(row == 31)) };
        var main: [L.main.COUNT]Q = undefined;
        var prior: [L.main.COUNT]Q = undefined;
        var current: [L.inter.COUNT]Q = undefined;
        var previous: [L.inter.COUNT]Q = undefined;
        for (&main, &prior, 0..) |*v, *p, c| {
            v.* = Q.fromBase(source.main[c * 32 + pos]);
            p.* = Q.fromBase(source.main[c * 32 + prev_pos]);
        }
        for (&current, &previous, 0..) |*v, *p, c| {
            v.* = Q.fromBase(source.interaction[c * 32 + pos]);
            p.* = Q.fromBase(source.interaction[c * 32 + prev_pos]);
        }
        var residuals: [L.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        W.equations.emitFor(Q, &fixed, &main, &prior, &current, &previous, public(), claims, ch, &sink);
        for (residuals) |residual| try std.testing.expect(residual.isZero());
    }
}
test "thin immutable ROM preserves high PC carries wrap and rejects unsupported opcodes" {
    const top = std.math.maxInt(u64) - 3;
    var rom = try W.rom.Setup.init(a, .{ .base = 0, .words = &.{ words[0], words[1] }, .addresses = &.{ 0, top } });
    defer rom.deinit();
    const pos = L.physical(try rom.lookup(top), rom.log_size);
    const n = rom.size();
    const expected = W.public.word(M, top);
    for (0..4) |i| {
        try std.testing.expectEqual(expected[i].v, rom.fixed[(1 + i) * n + pos].v);
        try std.testing.expectEqual(@as(u32, 0), rom.fixed[(5 + i) * n + pos].v);
    }
    for ([_]u64{ 0xfffc, 0xffff_fffc, 0xffff_ffff_fffc }) |pc| {
        var carry = try W.rom.Setup.init(a, .{ .base = pc, .words = &.{words[0]} });
        defer carry.deinit();
        const next = W.public.word(M, pc + 4);
        for (0..4) |i| try std.testing.expectEqual(next[i].v, carry.fixed[(5 + i) * carry.size() + L.physical(0, carry.log_size)].v);
    }
}
test "thin statement rejects oversized clocks and fixed data excludes request endpoints" {
    var invalid = public();
    invalid.register_clocks[1] = 17;
    try std.testing.expectError(error.InvalidWord16CpuClock, invalid.validate(5));
    invalid = public();
    invalid.steps = 32;
    try std.testing.expectError(error.InvalidWord16CpuStatement, invalid.validate(5));
    var rom = try W.rom.Setup.init(a, .{ .base = 4096, .words = &words });
    defer rom.deinit();
    var other = try W.rom.Setup.init(a, .{ .base = 4096, .words = &words });
    defer other.deinit();
    try std.testing.expectEqualSlices(u8, &rom.identity, &other.identity);
    try std.testing.expectEqualSlices(M, rom.fixed, other.fixed);
    try std.testing.expectError(error.UnsupportedWord16CpuOpcode, W.rom.Setup.init(a, .{ .base = 0, .words = &.{0x00000013} }));
}

test "thin PC wrapping follows real native CPU at highest executable word" {
    const top = std.math.maxInt(u64) - 3;
    const high_raw = instruction(7, 3, 1, 2);
    const low_raw = instruction(4, 3, 3, 1);
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    for ([_]u64{ 0, top }, [_]u32{ low_raw, high_raw }) |pc, raw| {
        try memory.map(.{ .start = pc, .size = 4, .permissions = .{ .read = true, .execute = true } });
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc, &bytes);
    }
    var state = W.public.Public{ .steps = 2, .initial_pc = top, .final_pc = 4, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    state.initial_registers[1] = 0x8877665544332211;
    state.initial_registers[2] = 0xfedcba9876543210;
    state.final_registers = state.initial_registers;
    state.final_registers[3] = (state.initial_registers[1] & state.initial_registers[2]) ^ state.initial_registers[1];
    state.register_clocks[1] = 6;
    state.register_clocks[2] = 2;
    state.register_clocks[3] = 7;
    var cpu = rv.machine.Cpu.init(top, 0);
    cpu.regs = state.initial_registers;
    const records = [_]rv.machine.Retirement{ try cpu.step(&memory), try cpu.step(&memory) };
    try std.testing.expectEqual(@as(u64, 0), records[0].next_pc.toInt());
    try std.testing.expectEqual(@as(u64, 4), cpu.pc);
    try std.testing.expectEqualSlices(u64, &state.final_registers, &cpu.regs);
    var rom = try W.rom.Setup.init(a, .{ .base = 0, .words = &.{ low_raw, high_raw }, .addresses = &.{ 0, top } });
    defer rom.deinit();
    var source = try W.trace.Source.init(a, &rom, state, 5, &records);
    defer source.deinit();
    const row = source.rowValues(0);
    for (row[L.main.next_pc..][0..4]) |limb| try std.testing.expect(limb.isZero());
    try std.testing.expectEqual(@as(u32, 65535), row[L.main.pc + 3].v);
    var bad = records;
    bad[0].next_pc = rv.Word.fromInt(4);
    try std.testing.expectError(error.InvalidWord16CpuRecords, W.trace.Source.init(a, &rom, state, 5, &bad));
    bad = records;
    bad[0].pc = rv.Word.fromInt(top & 0x0000ffffffffffff);
    try std.testing.expectError(error.InvalidWord16CpuRecords, W.trace.Source.init(a, &rom, state, 5, &bad));
}
