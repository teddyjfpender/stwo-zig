//! Complete Sharp SM83 instruction decoding.
//!
//! Timing is expressed in M-cycles. One M-cycle is four T-states.

const std = @import("std");

pub const Operation = enum {
    illegal,
    nop,
    load,
    increment8,
    decrement8,
    increment16,
    decrement16,
    rotate_left_circular_a,
    rotate_right_circular_a,
    rotate_left_a,
    rotate_right_a,
    add8,
    add_carry8,
    subtract8,
    subtract_carry8,
    and8,
    xor8,
    or8,
    compare8,
    add16,
    add_sp_e8,
    load_hl_sp_e8,
    jump_relative,
    jump,
    call,
    ret,
    reti,
    restart,
    push,
    pop,
    decimal_adjust,
    complement_a,
    set_carry,
    complement_carry,
    stop,
    halt,
    disable_interrupts,
    enable_interrupts,
    prefix,
    rotate_left_circular,
    rotate_right_circular,
    rotate_left,
    rotate_right,
    shift_left_arithmetic,
    shift_right_arithmetic,
    swap,
    shift_right_logical,
    bit,
    reset_bit,
    set_bit,
};

pub const Family = enum {
    illegal,
    misc,
    load8,
    load16,
    increment_decrement8,
    increment_decrement16,
    alu8,
    alu16,
    rotate_accumulator,
    branch,
    stack,
    interrupt,
    rotate_shift,
    bit,
    reset_set,
};

pub const Operand = enum {
    none,
    a,
    b,
    c,
    d,
    e,
    f,
    h,
    l,
    af,
    bc,
    de,
    hl,
    sp,
    indirect_bc,
    indirect_de,
    indirect_hl,
    indirect_hl_increment,
    indirect_hl_decrement,
    indirect_imm16,
    high_imm8,
    high_c,
    imm8,
    imm16,
    rel8,

    pub fn is16Bit(self: Operand) bool {
        return switch (self) {
            .af, .bc, .de, .hl, .sp, .imm16 => true,
            else => false,
        };
    }
};

pub const Condition = enum {
    always,
    nonzero,
    zero,
    no_carry,
    carry,
};

pub const Instruction = struct {
    operation: Operation,
    dst: Operand = .none,
    src: Operand = .none,
    condition: Condition = .always,
    length: u2,
    m_cycles: u3,
    taken_m_cycles: u3,
    parameter: u8 = 0,

    pub fn family(self: Instruction) Family {
        return switch (self.operation) {
            .illegal => .illegal,
            .nop,
            .decimal_adjust,
            .complement_a,
            .set_carry,
            .complement_carry,
            .stop,
            .halt,
            .prefix,
            => .misc,
            .load => if (self.dst.is16Bit() or self.src.is16Bit()) .load16 else .load8,
            .increment8, .decrement8 => .increment_decrement8,
            .increment16, .decrement16 => .increment_decrement16,
            .rotate_left_circular_a,
            .rotate_right_circular_a,
            .rotate_left_a,
            .rotate_right_a,
            => .rotate_accumulator,
            .add8,
            .add_carry8,
            .subtract8,
            .subtract_carry8,
            .and8,
            .xor8,
            .or8,
            .compare8,
            => .alu8,
            .add16, .add_sp_e8, .load_hl_sp_e8 => .alu16,
            .jump_relative, .jump, .call, .ret, .restart => .branch,
            .push, .pop => .stack,
            .reti, .disable_interrupts, .enable_interrupts => .interrupt,
            .rotate_left_circular,
            .rotate_right_circular,
            .rotate_left,
            .rotate_right,
            .shift_left_arithmetic,
            .shift_right_arithmetic,
            .swap,
            .shift_right_logical,
            => .rotate_shift,
            .bit => .bit,
            .reset_bit, .set_bit => .reset_set,
        };
    }

    pub fn isLegal(self: Instruction) bool {
        return self.operation != .illegal;
    }
};

pub const DecodeError = error{
    IllegalOpcode,
    TruncatedInstruction,
};

/// A validated instruction. Callers cannot construct one from an illegal or
/// truncated byte sequence without going through `decode`.
pub const DecodedOpcode = struct {
    instruction: Instruction,
    raw_opcode: u16,
    immediate: u16,
};

const illegal = Instruction{
    .operation = .illegal,
    .length = 1,
    .m_cycles = 0,
    .taken_m_cycles = 0,
};

fn op(
    operation: Operation,
    dst: Operand,
    src: Operand,
    length: u2,
    m_cycles: u3,
) Instruction {
    return .{
        .operation = operation,
        .dst = dst,
        .src = src,
        .length = length,
        .m_cycles = m_cycles,
        .taken_m_cycles = m_cycles,
    };
}

fn conditional(
    operation: Operation,
    condition: Condition,
    src: Operand,
    length: u2,
    m_cycles: u3,
    taken_m_cycles: u3,
) Instruction {
    return .{
        .operation = operation,
        .src = src,
        .condition = condition,
        .length = length,
        .m_cycles = m_cycles,
        .taken_m_cycles = taken_m_cycles,
    };
}

fn parameterized(
    operation: Operation,
    dst: Operand,
    parameter: u8,
    length: u2,
    m_cycles: u3,
) Instruction {
    return .{
        .operation = operation,
        .dst = dst,
        .length = length,
        .m_cycles = m_cycles,
        .taken_m_cycles = m_cycles,
        .parameter = parameter,
    };
}

const r8_operands = [_]Operand{
    .b,
    .c,
    .d,
    .e,
    .h,
    .l,
    .indirect_hl,
    .a,
};

pub const base_table = buildBaseTable();
pub const cb_table = buildCbTable();

fn buildBaseTable() [256]Instruction {
    var table = [_]Instruction{illegal} ** 256;

    table[0x00] = op(.nop, .none, .none, 1, 1);
    table[0x01] = op(.load, .bc, .imm16, 3, 3);
    table[0x02] = op(.load, .indirect_bc, .a, 1, 2);
    table[0x03] = op(.increment16, .bc, .none, 1, 2);
    table[0x04] = op(.increment8, .b, .none, 1, 1);
    table[0x05] = op(.decrement8, .b, .none, 1, 1);
    table[0x06] = op(.load, .b, .imm8, 2, 2);
    table[0x07] = op(.rotate_left_circular_a, .a, .none, 1, 1);
    table[0x08] = op(.load, .indirect_imm16, .sp, 3, 5);
    table[0x09] = op(.add16, .hl, .bc, 1, 2);
    table[0x0a] = op(.load, .a, .indirect_bc, 1, 2);
    table[0x0b] = op(.decrement16, .bc, .none, 1, 2);
    table[0x0c] = op(.increment8, .c, .none, 1, 1);
    table[0x0d] = op(.decrement8, .c, .none, 1, 1);
    table[0x0e] = op(.load, .c, .imm8, 2, 2);
    table[0x0f] = op(.rotate_right_circular_a, .a, .none, 1, 1);

    table[0x10] = op(.stop, .none, .imm8, 2, 1);
    table[0x11] = op(.load, .de, .imm16, 3, 3);
    table[0x12] = op(.load, .indirect_de, .a, 1, 2);
    table[0x13] = op(.increment16, .de, .none, 1, 2);
    table[0x14] = op(.increment8, .d, .none, 1, 1);
    table[0x15] = op(.decrement8, .d, .none, 1, 1);
    table[0x16] = op(.load, .d, .imm8, 2, 2);
    table[0x17] = op(.rotate_left_a, .a, .none, 1, 1);
    table[0x18] = op(.jump_relative, .none, .rel8, 2, 3);
    table[0x19] = op(.add16, .hl, .de, 1, 2);
    table[0x1a] = op(.load, .a, .indirect_de, 1, 2);
    table[0x1b] = op(.decrement16, .de, .none, 1, 2);
    table[0x1c] = op(.increment8, .e, .none, 1, 1);
    table[0x1d] = op(.decrement8, .e, .none, 1, 1);
    table[0x1e] = op(.load, .e, .imm8, 2, 2);
    table[0x1f] = op(.rotate_right_a, .a, .none, 1, 1);

    table[0x20] = conditional(.jump_relative, .nonzero, .rel8, 2, 2, 3);
    table[0x21] = op(.load, .hl, .imm16, 3, 3);
    table[0x22] = op(.load, .indirect_hl_increment, .a, 1, 2);
    table[0x23] = op(.increment16, .hl, .none, 1, 2);
    table[0x24] = op(.increment8, .h, .none, 1, 1);
    table[0x25] = op(.decrement8, .h, .none, 1, 1);
    table[0x26] = op(.load, .h, .imm8, 2, 2);
    table[0x27] = op(.decimal_adjust, .a, .none, 1, 1);
    table[0x28] = conditional(.jump_relative, .zero, .rel8, 2, 2, 3);
    table[0x29] = op(.add16, .hl, .hl, 1, 2);
    table[0x2a] = op(.load, .a, .indirect_hl_increment, 1, 2);
    table[0x2b] = op(.decrement16, .hl, .none, 1, 2);
    table[0x2c] = op(.increment8, .l, .none, 1, 1);
    table[0x2d] = op(.decrement8, .l, .none, 1, 1);
    table[0x2e] = op(.load, .l, .imm8, 2, 2);
    table[0x2f] = op(.complement_a, .a, .none, 1, 1);

    table[0x30] = conditional(.jump_relative, .no_carry, .rel8, 2, 2, 3);
    table[0x31] = op(.load, .sp, .imm16, 3, 3);
    table[0x32] = op(.load, .indirect_hl_decrement, .a, 1, 2);
    table[0x33] = op(.increment16, .sp, .none, 1, 2);
    table[0x34] = op(.increment8, .indirect_hl, .none, 1, 3);
    table[0x35] = op(.decrement8, .indirect_hl, .none, 1, 3);
    table[0x36] = op(.load, .indirect_hl, .imm8, 2, 3);
    table[0x37] = op(.set_carry, .none, .none, 1, 1);
    table[0x38] = conditional(.jump_relative, .carry, .rel8, 2, 2, 3);
    table[0x39] = op(.add16, .hl, .sp, 1, 2);
    table[0x3a] = op(.load, .a, .indirect_hl_decrement, 1, 2);
    table[0x3b] = op(.decrement16, .sp, .none, 1, 2);
    table[0x3c] = op(.increment8, .a, .none, 1, 1);
    table[0x3d] = op(.decrement8, .a, .none, 1, 1);
    table[0x3e] = op(.load, .a, .imm8, 2, 2);
    table[0x3f] = op(.complement_carry, .none, .none, 1, 1);

    for (0..64) |index| {
        const opcode = 0x40 + index;
        if (opcode == 0x76) {
            table[opcode] = op(.halt, .none, .none, 1, 1);
            continue;
        }
        const dst = r8_operands[(index >> 3) & 7];
        const src = r8_operands[index & 7];
        table[opcode] = op(
            .load,
            dst,
            src,
            1,
            if (dst == .indirect_hl or src == .indirect_hl) 2 else 1,
        );
    }

    const alu_operations = [_]Operation{
        .add8,
        .add_carry8,
        .subtract8,
        .subtract_carry8,
        .and8,
        .xor8,
        .or8,
        .compare8,
    };
    for (0..64) |index| {
        const src = r8_operands[index & 7];
        table[0x80 + index] = op(
            alu_operations[index >> 3],
            .a,
            src,
            1,
            if (src == .indirect_hl) 2 else 1,
        );
    }

    table[0xc0] = conditional(.ret, .nonzero, .none, 1, 2, 5);
    table[0xc1] = op(.pop, .bc, .none, 1, 3);
    table[0xc2] = conditional(.jump, .nonzero, .imm16, 3, 3, 4);
    table[0xc3] = op(.jump, .none, .imm16, 3, 4);
    table[0xc4] = conditional(.call, .nonzero, .imm16, 3, 3, 6);
    table[0xc5] = op(.push, .none, .bc, 1, 4);
    table[0xc6] = op(.add8, .a, .imm8, 2, 2);
    table[0xc7] = parameterized(.restart, .none, 0x00, 1, 4);
    table[0xc8] = conditional(.ret, .zero, .none, 1, 2, 5);
    table[0xc9] = op(.ret, .none, .none, 1, 4);
    table[0xca] = conditional(.jump, .zero, .imm16, 3, 3, 4);
    table[0xcb] = op(.prefix, .none, .none, 1, 1);
    table[0xcc] = conditional(.call, .zero, .imm16, 3, 3, 6);
    table[0xcd] = op(.call, .none, .imm16, 3, 6);
    table[0xce] = op(.add_carry8, .a, .imm8, 2, 2);
    table[0xcf] = parameterized(.restart, .none, 0x08, 1, 4);

    table[0xd0] = conditional(.ret, .no_carry, .none, 1, 2, 5);
    table[0xd1] = op(.pop, .de, .none, 1, 3);
    table[0xd2] = conditional(.jump, .no_carry, .imm16, 3, 3, 4);
    table[0xd4] = conditional(.call, .no_carry, .imm16, 3, 3, 6);
    table[0xd5] = op(.push, .none, .de, 1, 4);
    table[0xd6] = op(.subtract8, .a, .imm8, 2, 2);
    table[0xd7] = parameterized(.restart, .none, 0x10, 1, 4);
    table[0xd8] = conditional(.ret, .carry, .none, 1, 2, 5);
    table[0xd9] = op(.reti, .none, .none, 1, 4);
    table[0xda] = conditional(.jump, .carry, .imm16, 3, 3, 4);
    table[0xdc] = conditional(.call, .carry, .imm16, 3, 3, 6);
    table[0xde] = op(.subtract_carry8, .a, .imm8, 2, 2);
    table[0xdf] = parameterized(.restart, .none, 0x18, 1, 4);

    table[0xe0] = op(.load, .high_imm8, .a, 2, 3);
    table[0xe1] = op(.pop, .hl, .none, 1, 3);
    table[0xe2] = op(.load, .high_c, .a, 1, 2);
    table[0xe5] = op(.push, .none, .hl, 1, 4);
    table[0xe6] = op(.and8, .a, .imm8, 2, 2);
    table[0xe7] = parameterized(.restart, .none, 0x20, 1, 4);
    table[0xe8] = op(.add_sp_e8, .sp, .rel8, 2, 4);
    table[0xe9] = op(.jump, .none, .hl, 1, 1);
    table[0xea] = op(.load, .indirect_imm16, .a, 3, 4);
    table[0xee] = op(.xor8, .a, .imm8, 2, 2);
    table[0xef] = parameterized(.restart, .none, 0x28, 1, 4);

    table[0xf0] = op(.load, .a, .high_imm8, 2, 3);
    table[0xf1] = op(.pop, .af, .none, 1, 3);
    table[0xf2] = op(.load, .a, .high_c, 1, 2);
    table[0xf3] = op(.disable_interrupts, .none, .none, 1, 1);
    table[0xf5] = op(.push, .none, .af, 1, 4);
    table[0xf6] = op(.or8, .a, .imm8, 2, 2);
    table[0xf7] = parameterized(.restart, .none, 0x30, 1, 4);
    table[0xf8] = op(.load_hl_sp_e8, .hl, .rel8, 2, 3);
    table[0xf9] = op(.load, .sp, .hl, 1, 2);
    table[0xfa] = op(.load, .a, .indirect_imm16, 3, 4);
    table[0xfb] = op(.enable_interrupts, .none, .none, 1, 1);
    table[0xfe] = op(.compare8, .a, .imm8, 2, 2);
    table[0xff] = parameterized(.restart, .none, 0x38, 1, 4);

    return table;
}

fn buildCbTable() [256]Instruction {
    var table: [256]Instruction = undefined;
    const rotations = [_]Operation{
        .rotate_left_circular,
        .rotate_right_circular,
        .rotate_left,
        .rotate_right,
        .shift_left_arithmetic,
        .shift_right_arithmetic,
        .swap,
        .shift_right_logical,
    };

    for (0..256) |opcode| {
        const group = opcode >> 6;
        const selector = (opcode >> 3) & 7;
        const target = r8_operands[opcode & 7];
        const operation: Operation = switch (group) {
            0 => rotations[selector],
            1 => .bit,
            2 => .reset_bit,
            3 => .set_bit,
            else => unreachable,
        };
        const cycles: u3 = if (target != .indirect_hl)
            2
        else if (operation == .bit)
            3
        else
            4;
        table[opcode] = parameterized(operation, target, @intCast(selector), 2, cycles);
    }
    return table;
}

pub fn decode(bytes: []const u8) DecodeError!DecodedOpcode {
    if (bytes.len == 0) return error.TruncatedInstruction;
    const first = bytes[0];
    const base = base_table[first];
    if (!base.isLegal()) return error.IllegalOpcode;

    if (base.operation == .prefix) {
        if (bytes.len < 2) return error.TruncatedInstruction;
        return .{
            .instruction = cb_table[bytes[1]],
            .raw_opcode = 0xcb00 | @as(u16, bytes[1]),
            .immediate = 0,
        };
    }
    if (bytes.len < base.length) return error.TruncatedInstruction;

    const immediate: u16 = switch (base.length) {
        1 => 0,
        2 => bytes[1],
        3 => @as(u16, bytes[1]) | (@as(u16, bytes[2]) << 8),
        else => unreachable,
    };
    return .{
        .instruction = base,
        .raw_opcode = first,
        .immediate = immediate,
    };
}

test "all 500 executable encodings are represented" {
    var base_count: usize = 0;
    for (base_table, 0..) |instruction, opcode| {
        if (instruction.operation == .prefix) continue;
        if (instruction.isLegal()) {
            base_count += 1;
            try std.testing.expect(instruction.length >= 1 and instruction.length <= 3);
            try std.testing.expect(instruction.m_cycles >= 1);
            try std.testing.expect(instruction.taken_m_cycles >= instruction.m_cycles);
        } else {
            try std.testing.expect(switch (opcode) {
                0xd3, 0xdb, 0xdd, 0xe3, 0xe4, 0xeb, 0xec, 0xed, 0xf4, 0xfc, 0xfd => true,
                else => false,
            });
        }
    }
    try std.testing.expectEqual(@as(usize, 244), base_count);
    for (cb_table) |instruction| {
        try std.testing.expect(instruction.isLegal());
        try std.testing.expectEqual(@as(u2, 2), instruction.length);
    }
}

test "decoder validates illegal, truncated, immediate, and CB encodings" {
    try std.testing.expectError(error.TruncatedInstruction, decode(&.{}));
    try std.testing.expectError(error.TruncatedInstruction, decode(&.{0xcb}));
    try std.testing.expectError(error.TruncatedInstruction, decode(&.{ 0x01, 0x34 }));
    try std.testing.expectError(error.IllegalOpcode, decode(&.{0xd3}));

    const load_bc = try decode(&.{ 0x01, 0x34, 0x12 });
    try std.testing.expectEqual(Operation.load, load_bc.instruction.operation);
    try std.testing.expectEqual(Operand.bc, load_bc.instruction.dst);
    try std.testing.expectEqual(@as(u16, 0x1234), load_bc.immediate);

    const bit_hl = try decode(&.{ 0xcb, 0x7e });
    try std.testing.expectEqual(Operation.bit, bit_hl.instruction.operation);
    try std.testing.expectEqual(Operand.indirect_hl, bit_hl.instruction.dst);
    try std.testing.expectEqual(@as(u8, 7), bit_hl.instruction.parameter);
    try std.testing.expectEqual(@as(u3, 3), bit_hl.instruction.m_cycles);
    try std.testing.expectEqual(@as(u16, 0xcb7e), bit_hl.raw_opcode);
}

test "families preserve the selector-shaped AIR boundary" {
    try std.testing.expectEqual(Family.load8, (try decode(&.{0x78})).instruction.family());
    try std.testing.expectEqual(Family.load16, (try decode(&.{ 0x31, 0, 0 })).instruction.family());
    try std.testing.expectEqual(Family.alu8, (try decode(&.{0x86})).instruction.family());
    try std.testing.expectEqual(Family.rotate_shift, (try decode(&.{ 0xcb, 0x16 })).instruction.family());
    try std.testing.expectEqual(Family.bit, (try decode(&.{ 0xcb, 0x7e })).instruction.family());
    try std.testing.expectEqual(Family.reset_set, (try decode(&.{ 0xcb, 0xc7 })).instruction.family());
}
