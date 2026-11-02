const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64_air;
const D = rv.arithmetic.division;
const E = rv.evaluation;
const L = E.L;
const Encoding = rv.encoding;
const a = std.testing.allocator;

test "division CPU policy preserves legacy and DIV-only state boundary support" {
    const original = Encoding.Plan.fromOpcodes(&D.layout.OPCODES);
    const legacy = Encoding.Plan.fromOpcodesWithPolicy(&D.layout.OPCODES, .inline_v4);
    const lean = Encoding.Plan.fromOpcodesWithPolicy(&D.layout.OPCODES, .division_service_v2);
    try std.testing.expectEqual(original.main_count, legacy.main_count);
    try std.testing.expectEqualSlices(u16, &original.main_map, &legacy.main_map);
    try std.testing.expectEqualSlices(bool, &original.allowed_opcodes, &legacy.allowed_opcodes);
    try std.testing.expectEqualSlices(bool, &original.allowed_opcodes, &lean.allowed_opcodes);
    for ([_]L.Word{ .a, .b, .result, .previous_rd }) |word| try std.testing.expect(lean.support.words[@intFromEnum(word)]);
    for (lean.support.slots[0..3]) |enabled| try std.testing.expect(enabled);
    try std.testing.expect(!lean.support.product);
    for (D.layout.SCALARS) |field| try std.testing.expectEqual(Encoding.omitted, lean.main_map[field]);
    const duplicate = [_]E.O{.DIVU} ** 100;
    const duplicate_lean = Encoding.Plan.fromOpcodesWithPolicy(&duplicate, .division_service_v2);
    try std.testing.expect(duplicate_lean.allowed_opcodes[@intFromEnum(E.O.DIVU)]);
}

test "division CPU policy fixed substitution is linear and preserves canonical DIV state" {
    const program = [_]u32{0x0220c1bb}; // DIVW x3,x1,x2
    var initial: [32]u64 = @splat(0);
    initial[1] = 0x1234567880000001;
    initial[2] = 0xabcdef0000000002;
    var final = initial;
    final[3] = 0xffffffffc0000001;
    const public = rv.statement.Statement{ .program_base = 0x1000, .program = &program, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 1 };
    var witness = try rv.witness.Witness.build(a, public);
    defer witness.deinit();
    const plan = Encoding.Plan.fromOpcodesWithPolicy(&.{.DIVW}, .division_service_v2);
    D.cpu.canonicalizeAdvice(&witness.rows[0], .DIVW, plan.arithmetic_policy);
    var physical: [L.MAIN]E.Q = undefined;
    for (0..plan.main_count) |i| physical[i] = E.Q.fromBase(plan.projectValue(&witness.rows[0], i));
    const logical = plan.inflateMain(physical[0..plan.main_count]);
    const fixed_native = try rv.rows.fixedRow(public, witness.metadata, 0, 32);
    var fixed: E.Fixed = undefined;
    for (&fixed, fixed_native) |*value, native| value.* = E.Q.fromBase(native);
    const local = D.cpu.inlineFixed(&fixed, .division_service_v2);
    try std.testing.expect(local[L.fixed.opcode_start + @intFromEnum(E.O.DIVW)].isZero());
    for ([_]L.Word{ .a, .b, .result, .previous_rd }) |word| {
        try std.testing.expect(local[L.fixed.word_start + @intFromEnum(word)].eql(fixed[L.fixed.word_start + @intFromEnum(word)]));
        for (0..8) |i| try std.testing.expect(logical[L.byte(word, i)].eql(E.Q.fromBase(witness.rows[0][L.byte(word, i)])));
    }
    var residuals: [10000]E.Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    D.cpu.local(.{ .f = &fixed, .m = &logical }, &sink, &plan, physical[0..plan.main_count]);
    for (residuals[0..sink.count], 0..) |residual, index| if (!residual.isZero()) {
        std.debug.print("lean CPU constraint{d}\n", .{index});
        return error.InvalidLeanCpuResidual;
    };
    const factor = E.Q.fromU32Unchecked(13, 17, 19, 23);
    var scaled = fixed;
    for (&scaled) |*value| value.* = value.mul(factor);
    const scaled_local = D.cpu.inlineFixed(&scaled, .division_service_v2);
    for (local, scaled_local) |value, other| try std.testing.expect(value.mul(factor).eql(other));
}

test "division CPU policy quantifies row-width and range interaction removal" {
    var operations: [63]E.O = undefined;
    for (&operations, 0..) |*op, i| op.* = @enumFromInt(i); // ECALL/EBREAK excluded
    const inline_plan = Encoding.Plan.fromOpcodes(&operations);
    const lean = Encoding.Plan.fromOpcodesWithPolicy(&operations, .division_service_v2);
    const bytes = rv.range.cpu;
    try std.testing.expect(lean.main_count < inline_plan.main_count);
    try std.testing.expect(bytes.interactionCount(&lean) < bytes.interactionCount(&inline_plan));
    std.debug.print("DIV cost all63: CPUmain{d}->{d}, range{d}->{d}, byteinter{d}->{d}, typedbus+8\n", .{ inline_plan.main_count, lean.main_count, inline_plan.range_count, lean.range_count, bytes.interactionCount(&inline_plan), bytes.interactionCount(&lean) });
}

test "division CPU cost for independently executed Ethereum opcode support" {
    // Positive opcode inventory of block24628607, ELF9f0bd99274eafa7b...;
    // this is a public support policy, never a per-row/path selector omission.
    const opcodes = [_]E.O{ .ADD, .SUB, .SLL, .SLT, .SLTU, .XOR, .SRL, .OR, .AND, .ADDI, .SLTIU, .XORI, .ORI, .ANDI, .SLLI, .SRLI, .SRAI, .SUBW, .ADDIW, .SRLIW, .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU, .SB, .SH, .SW, .SD, .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU, .JAL, .JALR, .LUI, .AUIPC, .MUL, .MULHU, .DIVU, .REMU, .FENCE };
    const inline_plan = Encoding.Plan.fromOpcodes(&opcodes);
    const lean = Encoding.Plan.fromOpcodesWithPolicy(&opcodes, .division_service_v2);
    const bytes = rv.range.cpu;
    try std.testing.expectEqual(@as(usize, 110), inline_plan.main_count - lean.main_count);
    std.debug.print("DIV cost ETH: CPUmain{d}->{d}, range{d}->{d}, byteinter{d}->{d}, typedbus+8\n", .{ inline_plan.main_count, lean.main_count, inline_plan.range_count, lean.range_count, bytes.interactionCount(&inline_plan), bytes.interactionCount(&lean) });
}
