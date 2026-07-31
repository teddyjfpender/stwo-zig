//! Deterministic SM83 instruction runner and cycle-level bus trace.
//!
//! The CPU transition semantics are address-space independent. `Memory`
//! supplies the owned flat image plus optional device overlays; MBC3 execution
//! uses the metadata-preserving cartridge path below.

const std = @import("std");
const isa = @import("../isa/mod.zig");
pub const apu_mmio = @import("apu_mmio.zig");
pub const cartridge_memory = @import("cartridge_memory.zig");
pub const dma = @import("dma.zig");
pub const flat_memory = @import("flat_memory.zig");
pub const joypad = @import("joypad.zig");
pub const ppu_mmio = @import("ppu_mmio.zig");
pub const ppu_timing = @import("ppu_timing.zig");
pub const rom_only_memory = @import("rom_only_memory.zig");
pub const timer = @import("timer.zig");

pub const cpu = @import("cpu.zig");
pub const Cpu = cpu.Cpu;
pub const Flag = cpu.Flag;
pub const Memory = flat_memory.Memory;

pub const MAX_BUS_CYCLES: usize = 6;

pub const BusAction = enum {
    idle,
    read,
    write,
};

pub const BusCycle = struct {
    address: u16,
    value: u8,
    action: BusAction,
};

pub const StepTrace = struct {
    before: Cpu,
    after: Cpu,
    decoded: isa.DecodedOpcode,
    cycles: [MAX_BUS_CYCLES]BusCycle = undefined,
    cycle_count: u3 = 0,
    branch_taken: bool = false,
    result: ?u8 = null,

    pub fn activeCycles(self: *const StepTrace) []const BusCycle {
        return self.cycles[0..self.cycle_count];
    }
};

pub const StepError = isa.DecodeError || error{TraceOverflow};
pub const CartridgeStepError =
    StepError || cartridge_memory.ReadError || cartridge_memory.WriteError;

pub const CartridgeStepTrace = struct {
    instruction: StepTrace,
    accesses: [MAX_BUS_CYCLES]?cartridge_memory.Access,

    pub fn activeAccesses(self: *const CartridgeStepTrace) []const ?cartridge_memory.Access {
        return self.accesses[0..self.instruction.cycle_count];
    }
};

fn Bus(comptime AddressSpace: type) type {
    return struct {
        const Self = @This();

        memory: *AddressSpace,
        trace: *StepTrace,
        cartridge_accesses: ?*[MAX_BUS_CYCLES]?cartridge_memory.Access,
        last_address: u16 = 0,
        last_value: u8 = 0,

        fn append(
            self: *Self,
            address: u16,
            value: u8,
            action: BusAction,
        ) StepError!void {
            if (self.trace.cycle_count == self.trace.cycles.len)
                return error.TraceOverflow;
            self.trace.cycles[self.trace.cycle_count] = .{
                .address = address,
                .value = value,
                .action = action,
            };
            self.trace.cycle_count += 1;
            self.last_address = address;
            self.last_value = value;
            if (AddressSpace == Memory) self.memory.tickMcycle();
            if (AddressSpace == cartridge_memory.Memory)
                self.memory.tickMcycle();
        }

        fn read(self: *Self, address: u16) !u8 {
            const cycle = self.trace.cycle_count;
            const value = if (AddressSpace == Memory)
                self.memory.read(address)
            else if (AddressSpace == cartridge_memory.Memory) cartridge: {
                const result = try self.memory.read(address);
                self.cartridge_accesses.?[cycle] = result.access;
                break :cartridge result.value;
            } else @compileError("unsupported SM83 address space");
            try self.append(address, value, .read);
            return value;
        }

        fn write(self: *Self, address: u16, value: u8) !void {
            const cycle = self.trace.cycle_count;
            if (AddressSpace == Memory) {
                self.memory.write(address, value);
            } else if (AddressSpace == cartridge_memory.Memory) {
                self.cartridge_accesses.?[cycle] =
                    try self.memory.write(address, value);
            } else {
                @compileError("unsupported SM83 address space");
            }
            try self.append(address, value, .write);
        }

        fn idle(self: *Self) StepError!void {
            try self.append(self.last_address, self.last_value, .idle);
        }
    };
}

pub fn step(state: *Cpu, memory: *Memory) StepError!StepTrace {
    return stepWithFetch(Memory, state, memory, null, false);
}

/// Executes the one fetch affected by the HALT bug: the opcode read does not
/// increment PC, so a following immediate byte is read from the same address.
pub fn stepWithHaltBug(state: *Cpu, memory: *Memory) StepError!StepTrace {
    return stepWithFetch(Memory, state, memory, null, true);
}

pub fn stepCartridge(
    state: *Cpu,
    memory: *cartridge_memory.Memory,
) CartridgeStepError!CartridgeStepTrace {
    return stepCartridgeWithFetch(state, memory, false);
}

/// Cartridge equivalent of `stepWithHaltBug`, preserving every resolved
/// mapper/device access attached to the duplicated opcode fetch.
pub fn stepCartridgeWithHaltBug(
    state: *Cpu,
    memory: *cartridge_memory.Memory,
) CartridgeStepError!CartridgeStepTrace {
    return stepCartridgeWithFetch(state, memory, true);
}

fn stepCartridgeWithFetch(
    state: *Cpu,
    memory: *cartridge_memory.Memory,
    suppress_opcode_increment: bool,
) CartridgeStepError!CartridgeStepTrace {
    var accesses = [_]?cartridge_memory.Access{null} ** 6;
    return .{
        .instruction = try stepWithFetch(
            cartridge_memory.Memory,
            state,
            memory,
            &accesses,
            suppress_opcode_increment,
        ),
        .accesses = accesses,
    };
}

fn stepWithFetch(
    comptime AddressSpace: type,
    state: *Cpu,
    memory: *AddressSpace,
    cartridge_accesses: ?*[MAX_BUS_CYCLES]?cartridge_memory.Access,
    suppress_opcode_increment: bool,
) !StepTrace {
    var trace: StepTrace = undefined;
    trace.before = state.*;
    trace.cycle_count = 0;
    trace.branch_taken = false;
    trace.result = null;
    var bus = Bus(AddressSpace){
        .memory = memory,
        .trace = &trace,
        .cartridge_accesses = cartridge_accesses,
    };

    if (state.ime_enable_pending) {
        state.ime = true;
        state.ime_enable_pending = false;
    }

    var bytes = [_]u8{ 0, 0, 0 };
    bytes[0] = try bus.read(state.pc);
    if (!suppress_opcode_increment) state.pc +%= 1;
    const encoded = isa.base_table[bytes[0]];
    if (!encoded.isLegal()) return error.IllegalOpcode;
    const length: usize = if (bytes[0] == 0xcb) 2 else encoded.length;
    for (1..length) |index| {
        bytes[index] = try bus.read(state.pc);
        state.pc +%= 1;
    }
    trace.decoded = try isa.decode(bytes[0..length]);

    try execute(state, &bus, &trace);
    trace.after = state.*;
    return trace;
}

fn execute(state: *Cpu, bus: anytype, trace: *StepTrace) !void {
    const instruction = trace.decoded.instruction;
    const immediate = trace.decoded.immediate;
    switch (instruction.operation) {
        .illegal, .prefix => unreachable,
        .nop => {},
        .load => {
            if (instruction.src == .sp and instruction.dst == .indirect_imm16) {
                try bus.write(immediate, @truncate(state.sp));
                try bus.write(immediate +% 1, @truncate(state.sp >> 8));
            } else if (instruction.src.is16Bit() or instruction.dst.is16Bit()) {
                write16(state, instruction.dst, immediate, read16(state, instruction.src, immediate));
                if (instruction.dst == .sp and instruction.src == .hl) try bus.idle();
            } else {
                const value = try read8(state, bus, instruction.src, immediate);
                try write8(state, bus, instruction.dst, immediate, value);
            }
        },
        .increment8 => {
            const carry = state.flag(.carry);
            const value = try read8(state, bus, instruction.dst, immediate);
            const result = value +% 1;
            try write8(state, bus, instruction.dst, immediate, result);
            state.f = flags(result == 0, false, (value & 0xf) == 0xf, carry);
        },
        .decrement8 => {
            const carry = state.flag(.carry);
            const value = try read8(state, bus, instruction.dst, immediate);
            const result = value -% 1;
            try write8(state, bus, instruction.dst, immediate, result);
            state.f = flags(result == 0, true, (value & 0xf) == 0, carry);
        },
        .increment16, .decrement16 => {
            const value = read16(state, instruction.dst, immediate);
            write16(
                state,
                instruction.dst,
                immediate,
                if (instruction.operation == .increment16) value +% 1 else value -% 1,
            );
            try bus.idle();
        },
        .rotate_left_circular_a => rotateAccumulator(state, .rotate_left_circular),
        .rotate_right_circular_a => rotateAccumulator(state, .rotate_right_circular),
        .rotate_left_a => rotateAccumulator(state, .rotate_left),
        .rotate_right_a => rotateAccumulator(state, .rotate_right),
        .add8,
        .add_carry8,
        .subtract8,
        .subtract_carry8,
        .and8,
        .xor8,
        .or8,
        .compare8,
        => trace.result = try alu8(state, bus, instruction.operation, instruction.src, immediate),
        .add16 => {
            const left = state.hl();
            const right = read16(state, instruction.src, immediate);
            const result = left +% right;
            state.setHl(result);
            state.f = flags(
                state.flag(.zero),
                false,
                @as(u32, left & 0xfff) + @as(u32, right & 0xfff) > 0xfff,
                @as(u32, left) + @as(u32, right) > 0xffff,
            );
            try bus.idle();
        },
        .add_sp_e8, .load_hl_sp_e8 => {
            const unsigned: u8 = @truncate(immediate);
            const result = addSigned(state.sp, unsigned);
            state.f = flags(
                false,
                false,
                @as(u16, state.sp & 0xf) + @as(u16, unsigned & 0xf) > 0xf,
                @as(u16, state.sp & 0xff) + @as(u16, unsigned) > 0xff,
            );
            if (instruction.operation == .add_sp_e8) {
                state.sp = result;
                try bus.idle();
                try bus.idle();
            } else {
                state.setHl(result);
                try bus.idle();
            }
        },
        .jump_relative => {
            if (conditionHolds(state.*, instruction.condition)) {
                state.pc = addSigned(state.pc, @truncate(immediate));
                trace.branch_taken = true;
                try bus.idle();
            }
        },
        .jump => {
            if (conditionHolds(state.*, instruction.condition)) {
                state.pc = if (instruction.src == .hl) state.hl() else immediate;
                trace.branch_taken = true;
                if (instruction.src != .hl) try bus.idle();
            }
        },
        .call => {
            if (conditionHolds(state.*, instruction.condition)) {
                trace.branch_taken = true;
                try bus.idle();
                try push(state, bus, state.pc);
                state.pc = immediate;
            }
        },
        .ret => {
            if (instruction.condition != .always) try bus.idle();
            if (conditionHolds(state.*, instruction.condition)) {
                trace.branch_taken = true;
                state.pc = try pop(state, bus);
                try bus.idle();
            }
        },
        .reti => {
            state.pc = try pop(state, bus);
            state.ime = true;
            state.ime_enable_pending = false;
            try bus.idle();
        },
        .restart => {
            try bus.idle();
            try push(state, bus, state.pc);
            state.pc = instruction.parameter;
        },
        .push => {
            try bus.idle();
            try push(state, bus, read16(state, instruction.src, immediate));
        },
        .pop => write16(state, instruction.dst, immediate, try pop(state, bus)),
        .decimal_adjust => decimalAdjust(state),
        .complement_a => {
            state.a = ~state.a;
            state.setFlag(.subtract, true);
            state.setFlag(.half_carry, true);
        },
        .set_carry => state.f = flags(state.flag(.zero), false, false, true),
        .complement_carry => state.f = flags(
            state.flag(.zero),
            false,
            false,
            !state.flag(.carry),
        ),
        .stop => state.stopped = true,
        .halt => state.halted = true,
        .disable_interrupts => {
            state.ime = false;
            state.ime_enable_pending = false;
        },
        .enable_interrupts => {
            if (!state.ime) state.ime_enable_pending = true;
        },
        .rotate_left_circular,
        .rotate_right_circular,
        .rotate_left,
        .rotate_right,
        .shift_left_arithmetic,
        .shift_right_arithmetic,
        .swap,
        .shift_right_logical,
        => {
            const value = try read8(state, bus, instruction.dst, immediate);
            const result = rotateShift(state, instruction.operation, value);
            try write8(state, bus, instruction.dst, immediate, result);
        },
        .bit => {
            const value = try read8(state, bus, instruction.dst, immediate);
            state.f = flags(
                value & (@as(u8, 1) << @intCast(instruction.parameter)) == 0,
                false,
                true,
                state.flag(.carry),
            );
        },
        .reset_bit, .set_bit => {
            const value = try read8(state, bus, instruction.dst, immediate);
            const mask = @as(u8, 1) << @intCast(instruction.parameter);
            try write8(
                state,
                bus,
                instruction.dst,
                immediate,
                if (instruction.operation == .set_bit) value | mask else value & ~mask,
            );
        },
    }
}

fn read8(state: *Cpu, bus: anytype, operand: isa.Operand, immediate: u16) !u8 {
    return switch (operand) {
        .a => state.a,
        .b => state.b,
        .c => state.c,
        .d => state.d,
        .e => state.e,
        .f => state.f,
        .h => state.h,
        .l => state.l,
        .imm8, .rel8 => @truncate(immediate),
        .indirect_bc => bus.read(state.bc()),
        .indirect_de => bus.read(state.de()),
        .indirect_hl => bus.read(state.hl()),
        .indirect_hl_increment => blk: {
            const address = state.hl();
            const value = try bus.read(address);
            state.setHl(address +% 1);
            break :blk value;
        },
        .indirect_hl_decrement => blk: {
            const address = state.hl();
            const value = try bus.read(address);
            state.setHl(address -% 1);
            break :blk value;
        },
        .indirect_imm16 => bus.read(immediate),
        .high_imm8 => bus.read(0xff00 | @as(u16, @truncate(immediate))),
        .high_c => bus.read(0xff00 | @as(u16, state.c)),
        else => unreachable,
    };
}

fn write8(
    state: *Cpu,
    bus: anytype,
    operand: isa.Operand,
    immediate: u16,
    value: u8,
) !void {
    switch (operand) {
        .a => state.a = value,
        .b => state.b = value,
        .c => state.c = value,
        .d => state.d = value,
        .e => state.e = value,
        .f => state.f = value & 0xf0,
        .h => state.h = value,
        .l => state.l = value,
        .indirect_bc => try bus.write(state.bc(), value),
        .indirect_de => try bus.write(state.de(), value),
        .indirect_hl => try bus.write(state.hl(), value),
        .indirect_hl_increment => {
            const address = state.hl();
            try bus.write(address, value);
            state.setHl(address +% 1);
        },
        .indirect_hl_decrement => {
            const address = state.hl();
            try bus.write(address, value);
            state.setHl(address -% 1);
        },
        .indirect_imm16 => try bus.write(immediate, value),
        .high_imm8 => try bus.write(0xff00 | @as(u16, @truncate(immediate)), value),
        .high_c => try bus.write(0xff00 | @as(u16, state.c), value),
        else => unreachable,
    }
}

fn read16(state: *const Cpu, operand: isa.Operand, immediate: u16) u16 {
    return switch (operand) {
        .af => state.af(),
        .bc => state.bc(),
        .de => state.de(),
        .hl => state.hl(),
        .sp => state.sp,
        .imm16 => immediate,
        else => unreachable,
    };
}

fn write16(state: *Cpu, operand: isa.Operand, _: u16, value: u16) void {
    switch (operand) {
        .af => state.setAf(value),
        .bc => state.setBc(value),
        .de => state.setDe(value),
        .hl => state.setHl(value),
        .sp => state.sp = value,
        else => unreachable,
    }
}

fn push(state: *Cpu, bus: anytype, value: u16) !void {
    state.sp -%= 1;
    try bus.write(state.sp, @truncate(value >> 8));
    state.sp -%= 1;
    try bus.write(state.sp, @truncate(value));
}

fn pop(state: *Cpu, bus: anytype) !u16 {
    const low = try bus.read(state.sp);
    state.sp +%= 1;
    const high = try bus.read(state.sp);
    state.sp +%= 1;
    return @as(u16, low) | (@as(u16, high) << 8);
}

fn conditionHolds(state: Cpu, condition: isa.Condition) bool {
    return switch (condition) {
        .always => true,
        .nonzero => !state.flag(.zero),
        .zero => state.flag(.zero),
        .no_carry => !state.flag(.carry),
        .carry => state.flag(.carry),
    };
}

fn flags(zero: bool, subtract: bool, half_carry: bool, carry: bool) u8 {
    return (@as(u8, @intFromBool(zero)) << 7) |
        (@as(u8, @intFromBool(subtract)) << 6) |
        (@as(u8, @intFromBool(half_carry)) << 5) |
        (@as(u8, @intFromBool(carry)) << 4);
}

fn addSigned(base: u16, encoded: u8) u16 {
    const signed: i8 = @bitCast(encoded);
    const widened: i16 = signed;
    return base +% @as(u16, @bitCast(widened));
}

fn alu8(
    state: *Cpu,
    bus: anytype,
    operation: isa.Operation,
    operand: isa.Operand,
    immediate: u16,
) !u8 {
    const value = try read8(state, bus, operand, immediate);
    const left = state.a;
    switch (operation) {
        .add8, .add_carry8 => {
            const carry: u8 = if (operation == .add_carry8 and state.flag(.carry)) 1 else 0;
            const wide = @as(u16, left) + @as(u16, value) + carry;
            const result: u8 = @truncate(wide);
            state.a = result;
            state.f = flags(
                result == 0,
                false,
                @as(u16, left & 0xf) + @as(u16, value & 0xf) + carry > 0xf,
                wide > 0xff,
            );
        },
        .subtract8, .subtract_carry8, .compare8 => {
            const carry: u8 = if (operation == .subtract_carry8 and state.flag(.carry)) 1 else 0;
            const result = left -% value -% carry;
            if (operation != .compare8) state.a = result;
            state.f = flags(
                result == 0,
                true,
                @as(u16, left & 0xf) < @as(u16, value & 0xf) + carry,
                @as(u16, left) < @as(u16, value) + carry,
            );
        },
        .and8 => {
            state.a &= value;
            state.f = flags(state.a == 0, false, true, false);
        },
        .xor8 => {
            state.a ^= value;
            state.f = flags(state.a == 0, false, false, false);
        },
        .or8 => {
            state.a |= value;
            state.f = flags(state.a == 0, false, false, false);
        },
        else => unreachable,
    }
    return switch (operation) {
        .compare8 => left -% value,
        else => state.a,
    };
}

fn rotateAccumulator(state: *Cpu, operation: isa.Operation) void {
    state.a = rotateShift(state, operation, state.a);
    state.setFlag(.zero, false);
}

fn rotateShift(state: *Cpu, operation: isa.Operation, value: u8) u8 {
    var carry = false;
    const result: u8 = switch (operation) {
        .rotate_left_circular, .rotate_left_circular_a => blk: {
            carry = value & 0x80 != 0;
            break :blk (value << 1) | @intFromBool(carry);
        },
        .rotate_right_circular, .rotate_right_circular_a => blk: {
            carry = value & 1 != 0;
            break :blk (value >> 1) | (@as(u8, @intFromBool(carry)) << 7);
        },
        .rotate_left, .rotate_left_a => blk: {
            const old_carry = state.flag(.carry);
            carry = value & 0x80 != 0;
            break :blk (value << 1) | @intFromBool(old_carry);
        },
        .rotate_right, .rotate_right_a => blk: {
            const old_carry = state.flag(.carry);
            carry = value & 1 != 0;
            break :blk (value >> 1) | (@as(u8, @intFromBool(old_carry)) << 7);
        },
        .shift_left_arithmetic => blk: {
            carry = value & 0x80 != 0;
            break :blk value << 1;
        },
        .shift_right_arithmetic => blk: {
            carry = value & 1 != 0;
            break :blk (value >> 1) | (value & 0x80);
        },
        .swap => (value << 4) | (value >> 4),
        .shift_right_logical => blk: {
            carry = value & 1 != 0;
            break :blk value >> 1;
        },
        else => unreachable,
    };
    state.f = flags(result == 0, false, false, carry);
    return result;
}

fn decimalAdjust(state: *Cpu) void {
    var correction: u8 = 0;
    var carry = state.flag(.carry);
    if (state.flag(.subtract)) {
        if (state.flag(.half_carry)) correction |= 0x06;
        if (carry) correction |= 0x60;
        state.a -%= correction;
    } else {
        if (state.flag(.half_carry) or (state.a & 0x0f) > 9) correction |= 0x06;
        if (carry or state.a > 0x99) {
            correction |= 0x60;
            carry = true;
        }
        state.a +%= correction;
    }
    state.f = flags(state.a == 0, state.flag(.subtract), false, carry);
}

test "runner pins half-carry and DAA semantics" {
    var memory = try Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0xc6); // ADD A,n8
    memory.write(1, 0x01);
    memory.write(2, 0x27); // DAA
    var state = Cpu{ .a = 0x0f };

    _ = try step(&state, &memory);
    try std.testing.expectEqual(@as(u8, 0x10), state.a);
    try std.testing.expect(state.flag(.half_carry));
    state.a = 0x0a;
    state.f = 0;
    _ = try step(&state, &memory);
    try std.testing.expectEqual(@as(u8, 0x10), state.a);
    try std.testing.expectEqual(@as(u8, 0), state.f);
}

test "runner retires the EI delay before ordinary DI and makes consecutive EI a no-op" {
    var memory = try Memory.init(std.testing.allocator);
    defer memory.deinit();

    memory.write(0, 0xfb); // EI
    memory.write(1, 0x00); // NOP
    var state = Cpu{};
    const ei_before_nop = try step(&state, &memory);
    try std.testing.expect(!ei_before_nop.after.ime);
    try std.testing.expect(ei_before_nop.after.ime_enable_pending);
    const nop = try step(&state, &memory);
    try std.testing.expect(nop.before.ime_enable_pending);
    try std.testing.expect(nop.after.ime);
    try std.testing.expect(!nop.after.ime_enable_pending);

    memory.write(0, 0xfb); // EI
    memory.write(1, 0xf3); // DI
    state = .{};
    _ = try step(&state, &memory);
    const disable = try step(&state, &memory);
    try std.testing.expect(disable.before.ime_enable_pending);
    try std.testing.expect(!disable.after.ime);
    try std.testing.expect(!disable.after.ime_enable_pending);

    memory.write(0, 0xfb); // EI
    memory.write(1, 0xfb); // EI
    state = .{};
    _ = try step(&state, &memory);
    const second_enable = try step(&state, &memory);
    try std.testing.expect(second_enable.before.ime_enable_pending);
    try std.testing.expect(second_enable.after.ime);
    try std.testing.expect(!second_enable.after.ime_enable_pending);

    memory.write(0, 0xfb); // EI with IME already enabled
    state = .{ .ime = true };
    const enabled_enable = try step(&state, &memory);
    try std.testing.expect(enabled_enable.after.ime);
    try std.testing.expect(!enabled_enable.after.ime_enable_pending);
}

test "HALT bug fetch covers one-byte immediate word and CB encodings" {
    var memory = try Memory.init(std.testing.allocator);
    defer memory.deinit();

    memory.write(0x1200, 0x00);
    var state = Cpu{ .pc = 0x1200 };
    _ = try stepWithHaltBug(&state, &memory);
    try std.testing.expectEqual(@as(u16, 0x1200), state.pc);
    _ = try step(&state, &memory);
    try std.testing.expectEqual(@as(u16, 0x1201), state.pc);

    memory.write(0x1234, 0x06); // LD B,d8
    memory.write(0x1235, 0x99);
    state = .{ .pc = 0x1234 };

    var trace = try stepWithHaltBug(&state, &memory);
    try std.testing.expectEqual(@as(u8, 0x06), state.b);
    try std.testing.expectEqual(@as(u16, 0x1235), state.pc);
    try std.testing.expectEqual(@as(u3, 2), trace.cycle_count);
    try std.testing.expectEqual(@as(u16, 0x1234), trace.cycles[0].address);
    try std.testing.expectEqual(@as(u16, 0x1234), trace.cycles[1].address);

    memory.write(0x1300, 0x01); // LD BC,d16
    memory.write(0x1301, 0x99);
    state = .{ .pc = 0x1300 };
    trace = try stepWithHaltBug(&state, &memory);
    try std.testing.expectEqual(@as(u16, 0x9901), state.bc());
    try std.testing.expectEqual(@as(u16, 0x1302), state.pc);
    try std.testing.expectEqual(@as(u16, 0x1300), trace.cycles[1].address);
    try std.testing.expectEqual(@as(u16, 0x1301), trace.cycles[2].address);

    memory.write(0x1400, 0xcb);
    memory.write(0x1401, 0x11);
    state = .{ .pc = 0x1400 };
    trace = try stepWithHaltBug(&state, &memory);
    try std.testing.expectEqual(@as(u16, 0x1401), state.pc);
    try std.testing.expectEqual(@as(u16, 0x1400), trace.cycles[0].address);
    try std.testing.expectEqual(@as(u16, 0x1400), trace.cycles[1].address);
}

test {
    _ = @import("cartridge_runner_test.zig");
}
