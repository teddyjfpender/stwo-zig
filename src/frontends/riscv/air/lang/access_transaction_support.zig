//! Register and memory event construction for access transactions.

const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const decode = @import("../../isa/decode.zig");
const state_chain = @import("../../runner/state_chain.zig");
const types = @import("types.zig");

const StateChainTracker = state_chain.StateChainTracker;
const MAX_EVENTS: usize = 3;
const MAX_ALIGNED_DATA_ADDRESS: u32 = ((@as(u32, 1) << 20) - 1) * 4;
const M31_MODULUS: u32 = 0x7fff_ffff;

pub const RegisterRole = enum { rs1, rs2, rd };

pub fn appendRegister(
    transaction: anytype,
    tracker: anytype,
    kind: anytype,
    logical_ordinal: types.AccessOrdinal,
    physical_phase: types.AccessPhase,
    register: u5,
    previous_value: u32,
    next_value: u32,
    role: RegisterRole,
) !void {
    std.debug.assert(kind == .register_read or kind == .register_write);
    std.debug.assert(transaction.event_count < MAX_EVENTS);
    if (register == 0 and (previous_value != 0 or next_value != 0))
        return error.ZeroRegisterValue;

    var raw_previous_clock = tracker.reg_last_clk[register];
    var expected_previous_value: ?u32 = null;
    var prior_index: usize = transaction.event_count;
    while (prior_index > 0) {
        prior_index -= 1;
        const prior = transaction.events[prior_index];
        if (prior.addressSpace() == 0 and prior.address == register) {
            raw_previous_clock = prior.current_clock;
            expected_previous_value = prior.next_value;
            break;
        }
    }
    if (expected_previous_value) |expected| {
        if (previous_value != expected)
            return error.AliasedRegisterValueMismatch;
    }

    const current_clock = phaseClock(
        transaction.instruction_clock,
        physical_phase,
    );
    if (raw_previous_clock >= current_clock)
        return error.NonIncreasingClock;
    const previous_clock = StateChainTracker.effectivePreviousClock(
        raw_previous_clock,
        current_clock,
    );
    const gap_count = StateChainTracker.clockGapCount(
        raw_previous_clock,
        current_clock,
    );
    transaction.reservation.register_clock_update_count += gap_count;
    transaction.reservation.access_count += 1;

    transaction.events[transaction.event_count] = .{
        .kind = kind,
        .logical_ordinal = logical_ordinal,
        .physical_phase = physical_phase,
        .address = register,
        .raw_previous_clock = raw_previous_clock,
        .previous_clock = previous_clock,
        .current_clock = current_clock,
        .previous_value = previous_value,
        .next_value = next_value,
        .read_mask = if (kind == .register_read) 0b1111 else 0,
        .write_mask = if (kind == .register_write) 0b1111 else 0,
    };
    transaction.event_count += 1;
    switch (role) {
        .rs1 => transaction.row_projection.rs1_previous_clock = previous_clock,
        .rs2 => transaction.row_projection.rs2_previous_clock = previous_clock,
        .rd => transaction.row_projection.rd_previous_clock = previous_clock,
    }
}

pub fn appendMemory(
    transaction: anytype,
    tracker: anytype,
    input: anytype,
    words: anytype,
) !void {
    std.debug.assert(transaction.event_count == 2);
    const opcode = input.instruction.opcode;
    const is_load = decode.isLoad(opcode);
    const is_store = decode.isStore(opcode);
    std.debug.assert(is_load or is_store);
    const width = decode.memoryWidthBytes(opcode).?;
    const effective_address = input.rs1_value +%
        @as(u32, @bitCast(input.instruction.imm));
    if (input.rs1_value >= M31_MODULUS)
        return error.MemoryBaseOutOfRange;
    if (effective_address & (@as(u32, width) - 1) != 0)
        return error.MemoryAddressMisaligned;
    const aligned_address = effective_address & ~@as(u32, 3);
    if (aligned_address > MAX_ALIGNED_DATA_ADDRESS)
        return error.MemoryAddressOutOfRange;

    const byte_offset: u2 = @truncate(effective_address);
    const addressed_mask: u4 = @intCast((@as(u8, 1) << @intCast(width)) - 1);
    const word_mask: u4 = @intCast(
        @as(u8, addressed_mask) << @intCast(byte_offset),
    );
    const value_mask = transferValueMask(width);
    const shift: u5 = @intCast(@as(u6, byte_offset) * 8);
    const transferred_value = if (is_load)
        (words.previous >> shift) & value_mask
    else
        input.rs2_value;
    const expected_next = if (is_load)
        words.previous
    else
        (words.previous & ~(value_mask << shift)) |
            ((input.rs2_value & value_mask) << shift);
    if (words.next != expected_next)
        return error.MemoryTransitionMismatch;

    if (is_load) {
        const expected_result = loadResult(opcode, transferred_value);
        const architectural_result = if (input.instruction.rd == 0)
            0
        else
            expected_result;
        if (input.rd_next_value != architectural_result)
            return error.LoadResultMismatch;
    }

    const current_clock = phaseClock(transaction.instruction_clock, .third);
    const tracked_previous_clock = tracker.mem_last_clk.get(aligned_address);
    const raw_previous_clock = tracked_previous_clock orelse 0;
    if (raw_previous_clock >= current_clock)
        return error.NonIncreasingClock;
    const previous_clock = StateChainTracker.effectivePreviousClock(
        raw_previous_clock,
        current_clock,
    );
    transaction.reservation.memory_address_count += @intFromBool(
        !tracker.mem_initial.contains(aligned_address) or
            tracked_previous_clock == null,
    );
    transaction.reservation.access_count += 1;
    transaction.reservation.memory_clock_update_count +=
        StateChainTracker.clockGapCount(raw_previous_clock, current_clock);

    transaction.events[transaction.event_count] = .{
        .kind = if (is_load) .memory_read else .memory_write,
        .logical_ordinal = if (is_load) .second else .third,
        .physical_phase = .third,
        .address = aligned_address,
        .raw_previous_clock = raw_previous_clock,
        .previous_clock = previous_clock,
        .current_clock = current_clock,
        .previous_value = words.previous,
        .next_value = words.next,
        .read_mask = if (is_load) word_mask else 0,
        .write_mask = if (is_store) word_mask else 0,
    };
    transaction.event_count += 1;
    transaction.row_projection.memory = .{
        .effective_address = effective_address,
        .aligned_address = aligned_address,
        .width_bytes = width,
        .byte_offset = byte_offset,
        .addressed_mask = addressed_mask,
        .word_read_mask = if (is_load) word_mask else 0,
        .word_write_mask = if (is_store) word_mask else 0,
        .transferred_value = transferred_value,
        .previous_word = words.previous,
        .next_word = words.next,
        .previous_clock = previous_clock,
        .current_clock = current_clock,
    };
}

pub inline fn phaseClock(
    instruction_clock: u32,
    phase: types.AccessPhase,
) u32 {
    const ordinal: access_clock.Ordinal = @enumFromInt(
        @intFromEnum(phase) - 1,
    );
    return access_clock.encode(instruction_clock, ordinal);
}

inline fn transferValueMask(width: u3) u32 {
    return switch (width) {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        else => unreachable,
    };
}

inline fn loadResult(opcode: decode.Opcode, value: u32) u32 {
    return switch (opcode) {
        .LB => @bitCast(@as(i32, @as(i8, @bitCast(@as(u8, @truncate(value)))))),
        .LH => @bitCast(@as(i32, @as(i16, @bitCast(@as(u16, @truncate(value)))))),
        .LBU, .LHU, .LW => value,
        else => unreachable,
    };
}
