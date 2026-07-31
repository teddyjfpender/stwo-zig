const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const branch = @import("branch.zig");
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const opcodes = [_]u8{
    0x18, 0x20, 0x28, 0x30, 0x38,
    0xc0, 0xc2, 0xc3, 0xc4, 0xc7,
    0xc8, 0xc9, 0xca, 0xcc, 0xcd,
    0xcf, 0xd0, 0xd2, 0xd4, 0xd7,
    0xd8, 0xda, 0xdc, 0xdf, 0xe7,
    0xe9, 0xef, 0xf7, 0xff,
};

const Kind = enum { jr, jp_imm, jp_hl, call, ret, restart };

fn kindOf(instruction: isa.Instruction) Kind {
    return switch (instruction.operation) {
        .jump_relative => .jr,
        .jump => if (instruction.src == .hl) .jp_hl else .jp_imm,
        .call => .call,
        .ret => .ret,
        .restart => .restart,
        else => unreachable,
    };
}

fn pathIndex(opcode_index: usize, taken: bool) usize {
    var result: usize = 0;
    for (opcodes[0..opcode_index]) |opcode|
        result += if (isa.base_table[opcode].condition == .always) 1 else 2;
    if (isa.base_table[opcodes[opcode_index]].condition != .always and taken)
        result += 1;
    return result;
}

fn flagsFor(condition: isa.Condition, taken: bool) u8 {
    return switch (condition) {
        .always => 0xf0,
        .nonzero => if (taken) 0x70 else 0xf0,
        .zero => if (taken) 0xf0 else 0x70,
        .no_carry => if (taken) 0xe0 else 0xf0,
        .carry => if (taken) 0xf0 else 0xe0,
    };
}

test "branch authority contains exactly 29 opcodes and 45 execution paths" {
    var count: usize = 0;
    for (isa.base_table, 0..) |instruction, opcode| {
        if (instruction.family() != .branch) continue;
        try std.testing.expect(std.mem.indexOfScalar(u8, &opcodes, @intCast(opcode)) != null);
        count += 1;
    }
    try std.testing.expectEqual(opcodes.len, count);
    try std.testing.expectEqual(@as(usize, 45), pathIndex(opcodes.len - 1, false) + 1);
}

test "branch AIR binds 360 edge-stratified opcode paths" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const pcs = [_]u16{ 0, 0xfffd, 0xfffe, 0xffff, 0x4000, 0x4000, 0x4000, 0x4000 };
    const sps = [_]u16{ 0x8000, 0x8000, 0x8000, 0x8000, 0, 1, 0xfffe, 0xffff };
    const offsets = [_]u8{ 0x80, 0xff, 0, 0x7f, 0x80, 0xff, 0, 0x7f };
    const targets = [_]u16{ 0, 1, 0x7fff, 0x8000, 0xff00, 0xfffe, 0xffff, 0x1234 };
    var checked: usize = 0;

    for (opcodes) |opcode| {
        const instruction = isa.base_table[opcode];
        const kind = kindOf(instruction);
        const path_count: usize = if (instruction.condition == .always) 1 else 2;
        for (0..path_count) |path| {
            const taken = instruction.condition == .always or path == 1;
            for (pcs, sps, offsets, targets) |pc, sp, offset, target| {
                @memset(memory.bytes, 0);
                memory.write(pc, opcode);
                switch (kind) {
                    .jr => memory.write(pc +% 1, offset),
                    .jp_imm, .call => {
                        memory.write(pc +% 1, @truncate(target));
                        memory.write(pc +% 2, @truncate(target >> 8));
                    },
                    .ret => {
                        memory.write(sp, @truncate(target));
                        memory.write(sp +% 1, @truncate(target >> 8));
                    },
                    .jp_hl, .restart => {},
                }
                var cpu = runner.Cpu{
                    .a = 0x11,
                    .b = 0x22,
                    .c = 0x33,
                    .d = 0x44,
                    .e = 0x55,
                    .f = flagsFor(instruction.condition, taken),
                    .h = @truncate(target >> 8),
                    .l = @truncate(target),
                    .sp = sp,
                    .pc = pc,
                    .ime = true,
                    .ime_enable_pending = true,
                };
                const trace = try runner.step(&cpu, &memory);
                const witness = branch.columns(try branch.ValidatedStep.init(trace));
                try std.testing.expect((try branch.evaluate(witness)).allZero());
                try std.testing.expect((try branch.evaluateBound(
                    witness,
                    execution.columns(trace, 17),
                )).allZero());
                checked += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 360), checked);
}

test "branch AIR rejects target condition timing state bus metadata and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xffff, 0x20);
    memory.write(0, 0x80);
    var cpu = runner.Cpu{ .a = 0x11, .f = 0x70, .sp = 0, .pc = 0xffff, .ime = true };
    const trace = try runner.step(&cpu, &memory);
    var witness = branch.columns(try branch.ValidatedStep.init(trace));
    const machine = execution.columns(trace, 9);
    try std.testing.expect((try branch.evaluateBound(witness, machine)).allZero());

    witness[45] = if (witness[45].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try branch.evaluateBound(witness, machine)).allZero());
    witness = branch.columns(try branch.ValidatedStep.init(trace));
    witness[pathIndex(1, true)] = M31.zero();
    witness[pathIndex(1, false)] = M31.one();
    try std.testing.expect(!(try branch.evaluateBound(witness, machine)).allZero());
    witness = branch.columns(try branch.ValidatedStep.init(trace));

    var forged = machine;
    forged[2 * execution.N_STATE_COLUMNS + 1] = M31.fromCanonical(0x21);
    try std.testing.expect(!(try branch.evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.pc)] = M31.zero();
    try std.testing.expect(!(try branch.evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.a)] =
        M31.fromCanonical(0x12);
    try std.testing.expect(!(try branch.evaluateBound(witness, forged)).allZero());
    forged = machine;
    const clock_after = 2 * execution.N_STATE_COLUMNS +
        execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS + 1;
    forged[clock_after] = forged[clock_after].add(M31.one());
    try std.testing.expect(!(try branch.evaluateBound(witness, forged)).allZero());

    var lifted: [branch.N_MAIN_COLUMNS]QM31 = undefined;
    var lifted_machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, witness) |*destination, value| destination.* = QM31.fromBase(value);
    for (&lifted_machine, machine) |*destination, value| destination.* = QM31.fromBase(value);
    try std.testing.expect(!(branch.Shipped.evaluateBound(
        try branch.Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&lifted_machine),
        QM31.zero(),
    )).allZero());

    const zero_witness = [_]QM31{QM31.zero()} ** branch.N_MAIN_COLUMNS;
    const zero_machine = [_]QM31{QM31.zero()} ** execution.N_MAIN_COLUMNS;
    try std.testing.expect((branch.Shipped.evaluateBound(
        try branch.Shipped.Row.fromColumns(&zero_witness),
        try execution.Row(QM31).fromColumns(&zero_machine),
        QM31.zero(),
    )).allZero());

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0x28;
    try std.testing.expectError(error.NotBranch, branch.ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.decoded.immediate ^= 1;
    try std.testing.expectError(error.NotBranch, branch.ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.decoded.instruction.taken_m_cycles -= 1;
    try std.testing.expectError(error.NotBranch, branch.ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.cycle_count -= 1;
    try std.testing.expectError(error.NotBranch, branch.ValidatedStep.init(forged_trace));
}
