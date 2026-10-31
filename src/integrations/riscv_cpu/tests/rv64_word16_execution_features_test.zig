const std = @import("std");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const isa = front.rv64.decode;
const execution = front.rv64.execution_profile;
const M = @import("stwo_core").fields.m31.M31;
const L = X.layout;
fn word(values: []const M) u64 {
    var out: u64 = 0;
    for (values, 0..) |v, i| out |= @as(u64, v.v) << @as(u6, @intCast(16 * i));
    return out;
}
test "full CPU feature authority explicitly partitions every decoded opcode and true architectural effects" {
    for (std.enums.values(isa.Opcode)) |opcode| {
        const instruction = isa.Instruction{ .opcode = opcode, .rs1 = 2, .rs2 = 3, .rd = 4, .imm = -16 };
        const entry = X.Entry.fromInstruction(0, 0x1000, instruction);
        try std.testing.expectEqual(opcode != .EBREAK, entry.valid);
        if (!entry.valid) continue;
        const effects = execution.effects(.ethereum_services_v2, opcode);
        const rs1: u5 = if (opcode == .ECALL) 10 else 2;
        const rs2: u5 = if (opcode == .ECALL) 17 else 3;
        try std.testing.expectEqual([3]u5{ if (effects.reads_rs1) rs1 else 0, if (effects.reads_rs2) rs2 else 0, if (effects.writes_rd) 4 else 0 }, entry.ids);
        const owned = (opcode == .ECALL or (@intFromEnum(opcode) >= 28 and @intFromEnum(opcode) <= 38));
        try std.testing.expectEqual(!owned, entry.function);
        const tuple = entry.romTuple(false);
        try std.testing.expectEqual(@as(u32, 1), tuple[0].v);
        try std.testing.expectEqual(entry.pc, word(tuple[L.rom.pc..][0..4]));
        if (owned) try std.testing.expectEqual(@as(u32, @intFromEnum(opcode)), tuple[L.rom.operation].v);
        if (entry.hasTakenEdge()) try std.testing.expectEqual(@as(u32, 1), entry.romTuple(true)[L.rom.taken].v);
    }
}
test "full CPU raw decode normalizes static results services and dynamic links with full64 wrap" {
    const high = std.math.maxInt(u64) - 3;
    const jal = X.Entry.fromDecoded(0x008000ef, high);
    try std.testing.expect(jal.valid and jal.use_pc and jal.use_immediate);
    try std.testing.expectEqual(@as(u64, 4), jal.immediate);
    try std.testing.expectEqual(@as(u64, 4), jal.staticNext(false));
    const jalr = X.Entry.fromDecoded(0x000080e7, high);
    try std.testing.expect(jalr.valid and jalr.dynamic_next);
    try std.testing.expectEqual(@as(u8, 16), jalr.operation);
    try std.testing.expectEqual(~@as(u64, 1), jalr.immediate);
    const composed = X.Entry.fromDecoded(0x008080e7, high);
    try std.testing.expectEqual(@as(u8, 10), composed.operation);
    try std.testing.expectEqual(@as(u64, 8), composed.immediate);
    const tuple = jalr.romTuple(false);
    try std.testing.expectEqual(@as(u64, 0), word(tuple[L.rom.link..][0..4]));
    try std.testing.expectEqual(@as(u64, 0), word(tuple[L.rom.next_pc..][0..4]));
    const service = X.Entry.fromDecoded(0x73, 0x1000);
    try std.testing.expect(!service.function);
    try std.testing.expectEqual([3]u5{ 10, 17, 0 }, service.ids);
    try std.testing.expect(!X.Entry.fromDecoded(0x00100073, 0x1000).valid);
    try std.testing.expect(!X.Entry.fromDecoded(0, 0x1000).valid);
    const fence = X.Entry.fromDecoded(0x0ff4838f, 0x1000);
    try std.testing.expect(fence.valid);
    try std.testing.expectEqual([3]u5{ 0, 0, 0 }, fence.ids);
    const bad_jump = X.Entry.fromInstruction(0, 0x1000, .{ .opcode = .JAL, .rs1 = 0, .rs2 = 0, .rd = 1, .imm = 2 });
    try std.testing.expect(!bad_jump.valid);
    const branch = X.Entry.fromInstruction(0, 0x1000, .{ .opcode = .BEQ, .rs1 = 1, .rs2 = 2, .rd = 0, .imm = 2 });
    try std.testing.expect(branch.valid and !branch.hasTakenEdge());
}
test "full CPU projection preserves store B separate from signed immediate and binds branch and JALR ROM fields" {
    const entry = X.Entry.fromInstruction(0, 0x1000, .{ .opcode = .SD, .rs1 = 1, .rs2 = 2, .rd = 0, .imm = -8 });
    const row = try X.row.active(entry, 0, 0x1004, .{ .a = 0x100000020, .b = 0xfedcba9876543210, .c = 0, .previous_rd = 0 }, .{ 0, 0, 0 });
    const fixed = [_]M{ M.zero(), M.one(), M.zero() };
    const owner = X.tuples.owner(M, &fixed, &row, M.fromCanonical(2));
    try std.testing.expectEqual(@as(u64, 0xfedcba9876543210), word(owner[9..13]));
    try std.testing.expectEqual(@as(u64, @bitCast(@as(i64, -8))), word(owner[5..9]));
    try std.testing.expectEqual(@as(u32, 2), owner[17].v);
    try std.testing.expectEqual(@as(u32, 4), owner[18].v);
    const jalr = X.Entry.fromDecoded(0x000080e7, 0x1000);
    const jr = try X.row.active(jalr, 0, 0x1234567800001000, .{ .a = 0x1234567800001001, .b = 0, .c = 0x1004, .previous_rd = 7 }, .{ 0, 0, 0 });
    const fn_tuple = X.tuples.function(M, &jr);
    try std.testing.expectEqual(@as(u64, 0x1234567800001000), word(fn_tuple[9..13]));
    try std.testing.expectEqualSlices(M, &jalr.romTuple(false), &X.tuples.rom(M, &jr));
    var forged = jr;
    forged[L.main.c] = M.zero();
    try std.testing.expect(!std.meta.eql(jalr.romTuple(false), X.tuples.rom(M, &forged)));
    try std.testing.expectError(error.InvalidExecutionClock, X.row.active(entry, 0, 0x1004, .{ .a = 1, .b = 2, .c = 0, .previous_rd = 0 }, .{ 1, 0, 0 }));
}

/// Independent canonical encoding specimens, not an ISA execution model.
fn specimen(op: isa.Opcode) u32 {
    const base: u32 = switch (op) {
        .ADD => 0x33,
        .SUB => 0x40000033,
        .SLL => 0x1033,
        .SLT => 0x2033,
        .SLTU => 0x3033,
        .XOR => 0x4033,
        .SRL => 0x5033,
        .SRA => 0x40005033,
        .OR => 0x6033,
        .AND => 0x7033,
        .ADDI => 0x13,
        .SLTI => 0x2013,
        .SLTIU => 0x3013,
        .XORI => 0x4013,
        .ORI => 0x6013,
        .ANDI => 0x7013,
        .SLLI => 0x1013,
        .SRLI => 0x5013,
        .SRAI => 0x40005013,
        .ADDW => 0x3b,
        .SUBW => 0x4000003b,
        .SLLW => 0x103b,
        .SRLW => 0x503b,
        .SRAW => 0x4000503b,
        .ADDIW => 0x1b,
        .SLLIW => 0x101b,
        .SRLIW => 0x501b,
        .SRAIW => 0x4000501b,
        .LB => 0x03,
        .LH => 0x1003,
        .LW => 0x2003,
        .LD => 0x3003,
        .LBU => 0x4003,
        .LHU => 0x5003,
        .LWU => 0x6003,
        .SB => 0x23,
        .SH => 0x1023,
        .SW => 0x2023,
        .SD => 0x3023,
        .BEQ => 0x63,
        .BNE => 0x1063,
        .BLT => 0x4063,
        .BGE => 0x5063,
        .BLTU => 0x6063,
        .BGEU => 0x7063,
        .JAL => 0x6f,
        .JALR => 0x67,
        .LUI => 0x37,
        .AUIPC => 0x17,
        .MUL => 0x02000033,
        .MULH => 0x02001033,
        .MULHSU => 0x02002033,
        .MULHU => 0x02003033,
        .DIV => 0x02004033,
        .DIVU => 0x02005033,
        .REM => 0x02006033,
        .REMU => 0x02007033,
        .MULW => 0x0200003b,
        .DIVW => 0x0200403b,
        .DIVUW => 0x0200503b,
        .REMW => 0x0200603b,
        .REMUW => 0x0200703b,
        .FENCE => 0x0f,
        .ECALL => 0x73,
        .EBREAK => 0x00100073,
    };
    const effects = isa.effects(op);
    return base | (if (effects.writes_rd) @as(u32, 1) << 7 else 0) | (if (effects.reads_rs1) @as(u32, 1) << 15 else 0) | (if (effects.reads_rs2) @as(u32, 2) << 20 else 0);
}
test "full CPU all65 raw encodings and cached independent decode have identical admission and ROM projection" {
    for (std.enums.values(isa.Opcode)) |op| {
        const raw = specimen(op);
        const decoded = try execution.decode(.ethereum_services_v2, raw);
        try std.testing.expectEqual(op, decoded.opcode);
        const direct = X.Entry.fromDecoded(raw, 0x100000000001000);
        const cached = X.Entry.fromInstruction(raw, 0x100000000001000, decoded);
        try std.testing.expectEqualDeep(direct, cached);
        try std.testing.expectEqual(op != .EBREAK, direct.valid);
        if (@intFromEnum(op) >= 49 and @intFromEnum(op) <= 61) try std.testing.expectEqual(@as(u8, @intFromEnum(op)), direct.operation);
    }
    try std.testing.expect(!std.meta.eql(X.features.identity(), @as([32]u8, @splat(0))));
}
