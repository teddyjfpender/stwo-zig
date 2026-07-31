//! Owned family selectors and witnesses in bit-reversed circle-domain order.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const alu16 = @import("alu16.zig");
const alu8 = @import("alu8.zig");
const branch = @import("branch.zig");
const cb_bit = @import("cb_bit.zig");
const cb_res_set = @import("cb_res_set.zig");
const cb_rotate_shift = @import("cb_rotate_shift.zig");
const daa = @import("daa.zig");
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const incdec16 = @import("incdec16.zig");
const incdec8 = @import("incdec8.zig");
const interrupt = @import("interrupt.zig");
const interrupt_service = @import("interrupt_service.zig");
const load16 = @import("load16.zig");
const load8 = @import("load8.zig");
const misc = @import("misc.zig");
const rotate_accumulator = @import("rotate_accumulator.zig");
const stack = @import("stack.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");

pub const ALU8_SELECTOR: usize = 0;
pub const DAA_SELECTOR: usize = 1;
pub const INCDEC8_SELECTOR: usize = 2;
pub const INCDEC16_SELECTOR: usize = 3;
pub const ROTATE_ACCUMULATOR_SELECTOR: usize = 4;
pub const LOAD8_SELECTOR: usize = 5;
pub const ALU16_SELECTOR: usize = 6;
pub const CB_ROTATE_SHIFT_SELECTOR: usize = 7;
pub const CB_BIT_SELECTOR: usize = 8;
pub const CB_RES_SET_SELECTOR: usize = 9;
pub const LOAD16_SELECTOR: usize = 10;
pub const MISC_SELECTOR: usize = 11;
pub const BRANCH_SELECTOR: usize = 12;
pub const STACK_SELECTOR: usize = 13;
pub const INTERRUPT_SELECTOR: usize = 14;
pub const INTERRUPT_SERVICE_SELECTOR: usize = 15;
pub const ALU8_OFFSET: usize = execution.N_FAMILY_SELECTORS;
pub const DAA_OFFSET: usize = ALU8_OFFSET + alu8.N_MAIN_COLUMNS;
pub const INCDEC8_OFFSET: usize = DAA_OFFSET + daa.N_MAIN_COLUMNS;
pub const INCDEC16_OFFSET: usize = INCDEC8_OFFSET + incdec8.N_MAIN_COLUMNS;
pub const ROTATE_ACCUMULATOR_OFFSET: usize =
    INCDEC16_OFFSET + incdec16.N_MAIN_COLUMNS;
pub const LOAD8_OFFSET: usize =
    ROTATE_ACCUMULATOR_OFFSET + rotate_accumulator.N_MAIN_COLUMNS;
pub const ALU16_OFFSET: usize = LOAD8_OFFSET + load8.N_MAIN_COLUMNS;
pub const CB_ROTATE_SHIFT_OFFSET: usize =
    ALU16_OFFSET + alu16.N_MAIN_COLUMNS;
pub const CB_BIT_OFFSET: usize =
    CB_ROTATE_SHIFT_OFFSET + cb_rotate_shift.N_MAIN_COLUMNS;
pub const CB_RES_SET_OFFSET: usize = CB_BIT_OFFSET + cb_bit.N_MAIN_COLUMNS;
pub const LOAD16_OFFSET: usize =
    CB_RES_SET_OFFSET + cb_res_set.N_MAIN_COLUMNS;
pub const MISC_OFFSET: usize = LOAD16_OFFSET + load16.N_MAIN_COLUMNS;
pub const BRANCH_OFFSET: usize = MISC_OFFSET + misc.N_MAIN_COLUMNS;
pub const STACK_OFFSET: usize = BRANCH_OFFSET + branch.N_MAIN_COLUMNS;
pub const INTERRUPT_OFFSET: usize = STACK_OFFSET + stack.N_MAIN_COLUMNS;
pub const INTERRUPT_SERVICE_OFFSET: usize =
    INTERRUPT_OFFSET + interrupt.N_MAIN_COLUMNS;
pub const N_MAIN_COLUMNS: usize =
    INTERRUPT_SERVICE_OFFSET + interrupt_service.N_MAIN_COLUMNS;

pub const Trace = struct {
    log_size: u32,
    main: [N_MAIN_COLUMNS][]M31,
    allocator: std.mem.Allocator,
    main_owned: bool = true,

    pub fn disownMain(self: *Trace) void {
        self.main_owned = false;
    }

    pub fn deinit(self: *Trace) void {
        if (self.main_owned) {
            for (self.main) |column| self.allocator.free(column);
        }
        self.* = undefined;
    }
};

pub fn generate(allocator: std.mem.Allocator, steps: anytype) !Trace {
    if (steps.len < 16 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidTraceLength;
    const log_size: u32 = @intCast(std.math.log2_int(usize, steps.len));
    var result = Trace{
        .log_size = log_size,
        .main = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.main[0..initialized]) |column| allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    const Step = @TypeOf(steps[0]);
    for (steps, 0..) |input, row| {
        const storage = try core_air_utils.circleBitReversedIndex(log_size, row);
        const step = instructionFrom(Step, input) orelse {
            const service = serviceFrom(Step, input) orelse {
                if (schedulerOnly(Step, input)) continue;
                return error.UnsupportedProvenFamily;
            };
            result.main[INTERRUPT_SERVICE_SELECTOR][storage] = M31.one();
            const witness = interrupt_service.columns(
                try interrupt_service.ValidatedStep.init(service),
            );
            for (
                result.main[INTERRUPT_SERVICE_OFFSET..][0..interrupt_service.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
            continue;
        };
        if (step.decoded.instruction.family() == .alu8) {
            result.main[ALU8_SELECTOR][storage] = M31.one();
            const witness = alu8.columns(try alu8.ValidatedStep.init(step));
            for (
                result.main[ALU8_OFFSET..][0..alu8.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.operation == .decimal_adjust) {
            result.main[DAA_SELECTOR][storage] = M31.one();
            const witness = daa.columns(try daa.ValidatedStep.init(step));
            for (
                result.main[DAA_OFFSET..][0..daa.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .increment_decrement8) {
            result.main[INCDEC8_SELECTOR][storage] = M31.one();
            const witness = incdec8.columns(try incdec8.ValidatedStep.init(step));
            for (
                result.main[INCDEC8_OFFSET..][0..incdec8.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .increment_decrement16) {
            result.main[INCDEC16_SELECTOR][storage] = M31.one();
            const witness = incdec16.columns(
                try incdec16.ValidatedStep.init(step),
            );
            for (
                result.main[INCDEC16_OFFSET..][0..incdec16.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .rotate_accumulator) {
            result.main[ROTATE_ACCUMULATOR_SELECTOR][storage] = M31.one();
            const witness = rotate_accumulator.columns(
                try rotate_accumulator.ValidatedStep.init(step),
            );
            for (
                result.main[ROTATE_ACCUMULATOR_OFFSET..][0..rotate_accumulator.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .load8) {
            result.main[LOAD8_SELECTOR][storage] = M31.one();
            const witness = load8.columns(try load8.ValidatedStep.init(step));
            for (
                result.main[LOAD8_OFFSET..][0..load8.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .alu16) {
            result.main[ALU16_SELECTOR][storage] = M31.one();
            const witness = alu16.columns(try alu16.ValidatedStep.init(step));
            for (
                result.main[ALU16_OFFSET..][0..alu16.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .rotate_shift) {
            result.main[CB_ROTATE_SHIFT_SELECTOR][storage] = M31.one();
            const witness = cb_rotate_shift.columns(
                try cb_rotate_shift.ValidatedStep.init(step),
            );
            for (
                result.main[CB_ROTATE_SHIFT_OFFSET..][0..cb_rotate_shift.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .bit) {
            result.main[CB_BIT_SELECTOR][storage] = M31.one();
            const witness = cb_bit.columns(try cb_bit.ValidatedStep.init(step));
            for (
                result.main[CB_BIT_OFFSET..][0..cb_bit.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .reset_set) {
            result.main[CB_RES_SET_SELECTOR][storage] = M31.one();
            const witness = cb_res_set.columns(
                try cb_res_set.ValidatedStep.init(step),
            );
            for (
                result.main[CB_RES_SET_OFFSET..][0..cb_res_set.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .load16) {
            result.main[LOAD16_SELECTOR][storage] = M31.one();
            const witness = load16.columns(try load16.ValidatedStep.init(step));
            for (
                result.main[LOAD16_OFFSET..][0..load16.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .misc) {
            result.main[MISC_SELECTOR][storage] = M31.one();
            const witness = misc.columns(try misc.ValidatedStep.init(step));
            for (
                result.main[MISC_OFFSET..][0..misc.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .branch) {
            result.main[BRANCH_SELECTOR][storage] = M31.one();
            const witness = branch.columns(try branch.ValidatedStep.init(step));
            for (
                result.main[BRANCH_OFFSET..][0..branch.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .stack) {
            result.main[STACK_SELECTOR][storage] = M31.one();
            const witness = stack.columns(try stack.ValidatedStep.init(step));
            for (
                result.main[STACK_OFFSET..][0..stack.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else if (step.decoded.instruction.family() == .interrupt) {
            result.main[INTERRUPT_SELECTOR][storage] = M31.one();
            const witness = interrupt.columns(
                try interrupt.ValidatedStep.init(step),
            );
            for (
                result.main[INTERRUPT_OFFSET..][0..interrupt.N_MAIN_COLUMNS],
                witness,
            ) |column, value| column[storage] = value;
        } else {
            return error.UnsupportedProvenFamily;
        }
    }
    return result;
}

fn instructionFrom(comptime Step: type, value: Step) ?runner.StepTrace {
    if (Step == runner.StepTrace) return value;
    if (Step == runner.CartridgeStepTrace) return value.instruction;
    if (Step == execution_input.Step) return execution_input.instruction(value);
    if (Step == execution_input.CartridgeStep)
        return if (execution_input.cartridgeInstruction(value)) |trace|
            trace.instruction
        else
            null;
    if (Step == machine.CartridgeStepResult)
        return if (value.instruction) |trace| trace.instruction else null;
    @compileError("unsupported SM83 proof input");
}

fn serviceFrom(
    comptime Step: type,
    value: Step,
) ?machine.CartridgeStepResult {
    if (Step == runner.StepTrace or Step == runner.CartridgeStepTrace)
        return null;
    if (Step == execution_input.Step) return null;
    if (Step == execution_input.CartridgeStep)
        return if (value.result.event == .interrupt_service)
            value.result
        else
            null;
    if (Step == machine.CartridgeStepResult)
        return if (value.event == .interrupt_service) value else null;
    @compileError("unsupported SM83 proof input");
}

fn schedulerOnly(comptime Step: type, value: Step) bool {
    const event = if (Step == execution_input.CartridgeStep)
        value.result.event
    else if (Step == machine.CartridgeStepResult)
        value.event
    else
        return false;
    return event == .halt_idle or event == .halt_wake;
}

test "family trace selects exactly one supported AIR per row" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const opcodes = [_]u16{
        0x80,   0x27,   0x04, 0x03, 0x07, 0x41, 0x09, 0xcb00,
        0xcb40, 0xcb80, 0x01, 0x2f, 0x18, 0xc5, 0xf3, 0x27,
    };
    var address: u16 = 0;
    for (opcodes) |opcode| {
        if (opcode > 0xff) {
            memory.write(address, @intCast(opcode >> 8));
            address +%= 1;
        }
        memory.write(address, @truncate(opcode));
        address +%= 1;
        if (opcode == 0x01) {
            memory.write(address, 0x34);
            memory.write(address +% 1, 0x12);
            address +%= 2;
        } else if (opcode == 0x18) {
            memory.write(address, 0);
            address +%= 1;
        }
    }
    var state = runner.Cpu{ .a = 2, .b = 3, .h = 0x80 };
    var steps: [16]runner.StepTrace = undefined;
    for (&steps) |*step| step.* = try runner.step(&state, &memory);

    var trace = try generate(std.testing.allocator, &steps);
    defer trace.deinit();
    const leaves = [_][3]usize{
        .{ ALU8_SELECTOR, ALU8_OFFSET, DAA_OFFSET },
        .{ DAA_SELECTOR, DAA_OFFSET, INCDEC8_OFFSET },
        .{ INCDEC8_SELECTOR, INCDEC8_OFFSET, INCDEC16_OFFSET },
        .{
            INCDEC16_SELECTOR,
            INCDEC16_OFFSET,
            ROTATE_ACCUMULATOR_OFFSET,
        },
        .{
            ROTATE_ACCUMULATOR_SELECTOR,
            ROTATE_ACCUMULATOR_OFFSET,
            LOAD8_OFFSET,
        },
        .{
            LOAD8_SELECTOR,
            LOAD8_OFFSET,
            ALU16_OFFSET,
        },
        .{
            ALU16_SELECTOR,
            ALU16_OFFSET,
            CB_ROTATE_SHIFT_OFFSET,
        },
        .{
            CB_ROTATE_SHIFT_SELECTOR,
            CB_ROTATE_SHIFT_OFFSET,
            CB_BIT_OFFSET,
        },
        .{
            CB_BIT_SELECTOR,
            CB_BIT_OFFSET,
            CB_RES_SET_OFFSET,
        },
        .{
            CB_RES_SET_SELECTOR,
            CB_RES_SET_OFFSET,
            LOAD16_OFFSET,
        },
        .{
            LOAD16_SELECTOR,
            LOAD16_OFFSET,
            MISC_OFFSET,
        },
        .{
            MISC_SELECTOR,
            MISC_OFFSET,
            BRANCH_OFFSET,
        },
        .{
            BRANCH_SELECTOR,
            BRANCH_OFFSET,
            STACK_OFFSET,
        },
        .{
            STACK_SELECTOR,
            STACK_OFFSET,
            INTERRUPT_OFFSET,
        },
        .{
            INTERRUPT_SELECTOR,
            INTERRUPT_OFFSET,
            INTERRUPT_SERVICE_OFFSET,
        },
        .{
            INTERRUPT_SERVICE_SELECTOR,
            INTERRUPT_SERVICE_OFFSET,
            N_MAIN_COLUMNS,
        },
    };
    for (0..16) |row| {
        const storage = try core_air_utils.circleBitReversedIndex(4, row);
        const expected = switch (opcodes[row]) {
            0x80 => ALU8_SELECTOR,
            0x27 => DAA_SELECTOR,
            0x04 => INCDEC8_SELECTOR,
            0x03 => INCDEC16_SELECTOR,
            0x07 => ROTATE_ACCUMULATOR_SELECTOR,
            0x41 => LOAD8_SELECTOR,
            0x09 => ALU16_SELECTOR,
            0xcb00 => CB_ROTATE_SHIFT_SELECTOR,
            0xcb40 => CB_BIT_SELECTOR,
            0xcb80 => CB_RES_SET_SELECTOR,
            0x01 => LOAD16_SELECTOR,
            0x2f => MISC_SELECTOR,
            0x18 => BRANCH_SELECTOR,
            0xc5 => STACK_SELECTOR,
            0xf3 => INTERRUPT_SELECTOR,
            else => unreachable,
        };
        for (0..execution.N_FAMILY_SELECTORS) |selector| {
            try std.testing.expectEqual(
                M31.fromCanonical(@intFromBool(selector == expected)),
                trace.main[selector][storage],
            );
        }
        for (leaves) |leaf| {
            if (leaf[0] == expected) continue;
            for (trace.main[leaf[1]..leaf[2]]) |column| {
                try std.testing.expectEqual(M31.zero(), column[storage]);
            }
        }
    }
}

test "family trace accepts cartridge-wrapped instruction rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memset(memory.bytes[0..16], 0x80);
    var cpu = runner.Cpu{ .a = 1, .b = 2 };
    var steps: [16]runner.CartridgeStepTrace = undefined;
    for (&steps) |*step| step.* = .{
        .instruction = try runner.step(&cpu, &memory),
        .accesses = [_]?runner.cartridge_memory.Access{null} ** 6,
    };
    var trace = try generate(std.testing.allocator, &steps);
    trace.deinit();
}
