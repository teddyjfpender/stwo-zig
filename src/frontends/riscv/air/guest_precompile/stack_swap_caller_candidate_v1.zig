//! Fixed-register caller AIR for the non-production U256 swap candidate.
//!
//! The caller proves the registry-owned program tuple, one external state
//! transition, unchanged a0/a1 register chains, aligned/disjoint 32-byte
//! spans, and an exact call into the eight-row word provider.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const words = @import("stack_swap_word_candidate_v1.zig");

pub const production_active = false;
pub const preprocessed_column_count: usize = 3;
pub const main_column_count: usize = Layout.end;
pub const interaction_column_count: usize = 32;
pub const maximum_constraint_degree: u8 = 3;

pub const Error = words.Error || error{
    InvalidStackSwapCallerRecord,
    TraceShapeMismatch,
};

pub const Record = struct {
    execution_clock: u32,
    pc: u32,
    lhs_previous_clock: u32,
    rhs_previous_clock: u32,
    lhs_pointer: u32,
    rhs_pointer: u32,
    call_index: u32,

    pub fn call(self: Record) words.Call {
        return .{
            .execution_clock = self.execution_clock,
            .call_index = self.call_index,
            .pc = self.pc,
            .lhs_first_word = self.lhs_pointer / abi.word_bytes,
            .rhs_first_word = self.rhs_pointer / abi.word_bytes,
        };
    }

    pub fn validate(self: Record) Error!void {
        if (self.lhs_pointer & (abi.word_bytes - 1) != 0 or
            self.rhs_pointer & (abi.word_bytes - 1) != 0 or
            self.lhs_pointer >= abi.data_address_limit or
            self.rhs_pointer >= abi.data_address_limit)
        {
            return error.InvalidStackSwapCallerRecord;
        }
        try self.call().validate();
        const register_clock = access_clock.encode(self.execution_clock, .first);
        if (self.lhs_previous_clock >= register_clock or
            self.rhs_previous_clock >= register_clock)
        {
            return error.InvalidStackSwapCallerRecord;
        }
    }
};

pub const Row = struct {
    active: bool,
    execution_clock: u32,
    pc: u32,
    previous_clocks: [2]u32,
    pointer_bytes: [2][4]u8,
    word_indices: [2]u32,
    lhs_before_rhs: bool,
    gap_bytes: [4]u8,
    pointer_high_bits: [2][6]bool,
    gap_high_bits: [4]bool,
    call_index: u32,

    pub fn padding() Row {
        return std.mem.zeroes(Row);
    }

    pub fn encode(self: Row) [main_column_count]M31 {
        var result = [_]M31{M31.zero()} ** main_column_count;
        result[Layout.active] = feltBool(self.active);
        result[Layout.execution_clock] = M31.fromCanonical(self.execution_clock);
        result[Layout.pc] = M31.fromCanonical(self.pc);
        for (self.previous_clocks, 0..) |clock, index|
            result[Layout.previousClock(index)] = M31.fromCanonical(clock);
        for (self.pointer_bytes, 0..) |pointer, side| {
            for (pointer, 0..) |byte, index|
                result[Layout.pointerByte(side, index)] = M31.fromCanonical(byte);
        }
        for (self.word_indices, 0..) |word_index, side|
            result[Layout.wordIndex(side)] = M31.fromCanonical(word_index);
        result[Layout.lhs_before_rhs] = feltBool(self.lhs_before_rhs);
        for (self.gap_bytes, 0..) |byte, index|
            result[Layout.gapByte(index)] = M31.fromCanonical(byte);
        for (self.pointer_high_bits, 0..) |bits, side| {
            for (bits, 0..) |bit, index|
                result[Layout.pointerHighBit(side, index)] = feltBool(bit);
        }
        for (self.gap_high_bits, 0..) |bit, index|
            result[Layout.gapHighBit(index)] = feltBool(bit);
        result[Layout.call_index] = M31.fromCanonical(self.call_index);
        return result;
    }

    pub fn call(self: Row) Error!words.Call {
        if (!self.active) return error.InvalidStackSwapCallerRecord;
        return .{
            .execution_clock = self.execution_clock,
            .call_index = self.call_index,
            .pc = self.pc,
            .lhs_first_word = self.word_indices[0],
            .rhs_first_word = self.word_indices[1],
        };
    }

    pub fn relationEvents(self: Row, authority: abi.Authority) !RelationEvents {
        try authority.validate();
        const call_value = try self.call();
        try call_value.validate();
        const register_clock = access_clock.encode(self.execution_clock, .first);
        var range_pairs: [6]RangePair = undefined;
        for (self.pointer_bytes, 0..) |pointer, side| {
            range_pairs[side * 2] = .{ .left = pointer[0], .right = pointer[1] };
            range_pairs[side * 2 + 1] = .{ .left = pointer[2], .right = pointer[3] };
        }
        range_pairs[4] = .{ .left = self.gap_bytes[0], .right = self.gap_bytes[1] };
        range_pairs[5] = .{ .left = self.gap_bytes[2], .right = self.gap_bytes[3] };
        return .{
            .program = try authority.programTuple(self.pc),
            .state_before = .{ self.pc, self.execution_clock },
            .state_after = .{ self.pc +% 4, self.execution_clock +% 1 },
            .registers = .{
                RegisterChain.init(
                    abi.lhs_pointer_register,
                    self.previous_clocks[0],
                    register_clock,
                    self.pointer_bytes[0],
                ),
                RegisterChain.init(
                    abi.rhs_pointer_register,
                    self.previous_clocks[1],
                    register_clock,
                    self.pointer_bytes[1],
                ),
            },
            .range_pairs = range_pairs,
            .call = call_value.tuple(),
        };
    }
};

pub const RegisterTuple = struct {
    address_space: u1 = 0,
    register: u5,
    clock: u32,
    bytes: [4]u8,
};

pub const RegisterChain = struct {
    before: RegisterTuple,
    after: RegisterTuple,
    gap: u32,

    fn init(register: u5, before: u32, after: u32, bytes: [4]u8) RegisterChain {
        return .{
            .before = .{ .register = register, .clock = before, .bytes = bytes },
            .after = .{ .register = register, .clock = after, .bytes = bytes },
            .gap = after - before - 1,
        };
    }
};

pub const RangePair = struct { left: u8, right: u8 };

pub const RelationEvents = struct {
    program: [5]u32,
    state_before: [2]u32,
    state_after: [2]u32,
    registers: [2]RegisterChain,
    range_pairs: [6]RangePair,
    call: [5]u32,
};

pub fn materialize(record: Record) Error!Row {
    try record.validate();
    const pointers = [2]u32{ record.lhs_pointer, record.rhs_pointer };
    const word_indices = [2]u32{
        record.lhs_pointer / abi.word_bytes,
        record.rhs_pointer / abi.word_bytes,
    };
    const lhs_before_rhs = word_indices[0] < word_indices[1];
    const gap = if (lhs_before_rhs)
        word_indices[1] - word_indices[0] - @as(u32, @intCast(words.lane_count))
    else
        word_indices[0] - word_indices[1] - @as(u32, @intCast(words.lane_count));
    var pointer_bytes: [2][4]u8 = undefined;
    var pointer_high_bits: [2][6]bool = undefined;
    for (pointers, 0..) |pointer, side| {
        pointer_bytes[side] = littleEndianBytes(pointer);
        for (0..6) |bit|
            pointer_high_bits[side][bit] = pointer >> @intCast(24 + bit) & 1 != 0;
    }
    var gap_high_bits: [4]bool = undefined;
    for (0..4) |bit| gap_high_bits[bit] = gap >> @intCast(24 + bit) & 1 != 0;
    return .{
        .active = true,
        .execution_clock = record.execution_clock,
        .pc = record.pc,
        .previous_clocks = .{ record.lhs_previous_clock, record.rhs_previous_clock },
        .pointer_bytes = pointer_bytes,
        .word_indices = word_indices,
        .lhs_before_rhs = lhs_before_rhs,
        .gap_bytes = littleEndianBytes(gap),
        .pointer_high_bits = pointer_high_bits,
        .gap_high_bits = gap_high_bits,
        .call_index = record.call_index,
    };
}

pub const Layout = struct {
    pub const active: usize = 0;
    pub const execution_clock: usize = 1;
    pub const pc: usize = 2;
    pub const previous_clocks: usize = 3;
    pub const pointer_bytes: usize = previous_clocks + 2;
    pub const word_indices: usize = pointer_bytes + 8;
    pub const lhs_before_rhs: usize = word_indices + 2;
    pub const gap_bytes: usize = lhs_before_rhs + 1;
    pub const pointer_high_bits: usize = gap_bytes + 4;
    pub const gap_high_bits: usize = pointer_high_bits + 12;
    pub const call_index: usize = gap_high_bits + 4;
    pub const end: usize = call_index + 1;

    pub fn previousClock(index: usize) usize {
        return previous_clocks + index;
    }
    pub fn pointerByte(side: usize, index: usize) usize {
        return pointer_bytes + side * 4 + index;
    }
    pub fn wordIndex(side: usize) usize {
        return word_indices + side;
    }
    pub fn gapByte(index: usize) usize {
        return gap_bytes + index;
    }
    pub fn pointerHighBit(side: usize, index: usize) usize {
        return pointer_high_bits + side * 6 + index;
    }
    pub fn gapHighBit(index: usize) usize {
        return gap_high_bits + index;
    }
};

pub fn evaluateDirect(comptime S: type, row: []const S, sink: anytype) Error!void {
    if (row.len != main_column_count) return error.TraceShapeMismatch;
    const active = row[Layout.active];
    const one = S.one();
    boolean(sink, active);
    const padding = one.sub(active);
    for (row[1..]) |value| sink.add(padding.mul(value), 2);
    const side = row[Layout.lhs_before_rhs];
    boolean(sink, side);

    for (0..2) |pointer| {
        var reconstructed = S.zero();
        for (0..6) |bit| {
            const value = row[Layout.pointerHighBit(pointer, bit)];
            boolean(sink, value);
            reconstructed = reconstructed.add(
                value.mul(scalar(S, @as(u32, 1) << @intCast(bit))),
            );
        }
        sink.add(row[Layout.pointerByte(pointer, 3)].sub(reconstructed), 1);
        sink.add(
            composeBytes(S, row, Layout.pointer_bytes + pointer * 4).sub(
                row[Layout.wordIndex(pointer)].mul(scalar(S, abi.word_bytes)),
            ),
            1,
        );
    }
    var reconstructed_gap_high = S.zero();
    for (0..4) |bit| {
        const value = row[Layout.gapHighBit(bit)];
        boolean(sink, value);
        reconstructed_gap_high = reconstructed_gap_high.add(
            value.mul(scalar(S, @as(u32, 1) << @intCast(bit))),
        );
    }
    sink.add(row[Layout.gapByte(3)].sub(reconstructed_gap_high), 1);
    const gap = composeBytes(S, row, Layout.gap_bytes);
    const lhs = row[Layout.wordIndex(0)];
    const rhs = row[Layout.wordIndex(1)];
    sink.add(active.mul(side).mul(
        rhs.sub(lhs).sub(scalar(S, @intCast(words.lane_count))).sub(gap),
    ), 3);
    sink.add(active.mul(one.sub(side)).mul(
        lhs.sub(rhs).sub(scalar(S, @intCast(words.lane_count))).sub(gap),
    ), 3);
}

fn littleEndianBytes(value: u32) [4]u8 {
    return .{ @truncate(value), @truncate(value >> 8), @truncate(value >> 16), @truncate(value >> 24) };
}

fn composeBytes(comptime S: type, row: []const S, start: usize) S {
    return row[start]
        .add(row[start + 1].mul(scalar(S, 1 << 8)))
        .add(row[start + 2].mul(scalar(S, 1 << 16)))
        .add(row[start + 3].mul(scalar(S, 1 << 24)));
}

fn boolean(sink: anytype, value: anytype) void {
    sink.add(value.mul(value.sub(@TypeOf(value).one())), 2);
}

fn scalar(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

fn feltBool(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

comptime {
    if (production_active or
        preprocessed_column_count != 3 or
        main_column_count != 37 or
        interaction_column_count != 32)
    {
        @compileError("stack-swap caller geometry drifted");
    }
}
