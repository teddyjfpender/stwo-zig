//! Eight-lane field witness for a non-production atomic U256 swap.
//!
//! Each active call occupies exactly eight rows. A row advances two distinct
//! aligned guest-memory words at one authenticated subclock, emitting the
//! opposite row's bytes at each address. Caller and runner integration remain
//! disabled until a registry allocation and fresh proof path exist.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/stack_swap_candidate_v1.zig");

pub const production_active = false;
pub const preprocessed_column_count: usize = 3;
pub const main_column_count: usize = Layout.end;
pub const interaction_column_count: usize = 16;
pub const maximum_constraint_degree: u8 = 3;
pub const lane_count: usize = abi.words_per_value;
pub const maximum_word_address: u32 = abi.data_address_limit / abi.word_bytes;

pub const Error = error{
    InvalidStackSwapCall,
    InvalidStackSwapWordRow,
    InvalidStackSwapLaneSchedule,
    TraceShapeMismatch,
};

pub const Call = struct {
    execution_clock: u32,
    call_index: u32,
    pc: u32,
    lhs_first_word: u32,
    rhs_first_word: u32,

    pub fn validate(self: Call) Error!void {
        if (self.execution_clock == 0 or
            access_clock.maximum(self.execution_clock) > std.math.maxInt(u32) or
            self.lhs_first_word >= maximum_word_address or
            self.rhs_first_word >= maximum_word_address)
        {
            return error.InvalidStackSwapCall;
        }
        const lhs_end = std.math.add(
            u32,
            self.lhs_first_word,
            @intCast(lane_count),
        ) catch
            return error.InvalidStackSwapCall;
        const rhs_end = std.math.add(
            u32,
            self.rhs_first_word,
            @intCast(lane_count),
        ) catch
            return error.InvalidStackSwapCall;
        if (lhs_end > maximum_word_address or
            rhs_end > maximum_word_address or
            !(lhs_end <= self.rhs_first_word or rhs_end <= self.lhs_first_word))
        {
            return error.InvalidStackSwapCall;
        }
    }

    pub fn tuple(self: Call) [5]u32 {
        return .{
            self.execution_clock,
            self.call_index,
            self.pc,
            self.lhs_first_word,
            self.rhs_first_word,
        };
    }
};

pub const Lane = struct {
    index: u3,
    is_first: bool,
    is_last: bool,

    pub fn at(index: u3) Lane {
        return .{
            .index = index,
            .is_first = index == 0,
            .is_last = index == @as(u3, @intCast(lane_count - 1)),
        };
    }

    pub fn validate(self: Lane) Error!void {
        if (self.is_first != (self.index == 0) or
            self.is_last != (self.index == @as(u3, @intCast(lane_count - 1))))
        {
            return error.InvalidStackSwapLaneSchedule;
        }
    }

    pub fn validateNext(self: Lane, next: Lane) Error!void {
        try self.validate();
        try next.validate();
        const expected: u3 = @intCast(
            (@as(usize, self.index) + 1) % lane_count,
        );
        if (next.index != expected)
            return error.InvalidStackSwapLaneSchedule;
    }
};

pub const WordInput = struct {
    lhs_previous_clock: u32,
    rhs_previous_clock: u32,
    lhs_before: [4]u8,
    rhs_before: [4]u8,
};

pub const Row = struct {
    active: bool,
    execution_clock: u32,
    call_index: u32,
    pc: u32,
    lhs_word_address: u32,
    rhs_word_address: u32,
    lhs_previous_clock: u32,
    rhs_previous_clock: u32,
    lhs_before: [4]u8,
    rhs_before: [4]u8,

    pub fn padding() Row {
        return std.mem.zeroes(Row);
    }

    pub fn encode(self: Row) [main_column_count]M31 {
        var result = [_]M31{M31.zero()} ** main_column_count;
        result[Layout.active] = feltBool(self.active);
        result[Layout.execution_clock] = M31.fromCanonical(self.execution_clock);
        result[Layout.call_index] = M31.fromCanonical(self.call_index);
        result[Layout.pc] = M31.fromCanonical(self.pc);
        result[Layout.lhs_word_address] = M31.fromCanonical(self.lhs_word_address);
        result[Layout.rhs_word_address] = M31.fromCanonical(self.rhs_word_address);
        result[Layout.lhs_previous_clock] = M31.fromCanonical(self.lhs_previous_clock);
        result[Layout.rhs_previous_clock] = M31.fromCanonical(self.rhs_previous_clock);
        for (self.lhs_before, 0..) |value, index|
            result[Layout.lhsByte(index)] = M31.fromCanonical(value);
        for (self.rhs_before, 0..) |value, index|
            result[Layout.rhsByte(index)] = M31.fromCanonical(value);
        return result;
    }

    pub fn callTuple(self: Row, lane: Lane) Error![5]u32 {
        try lane.validate();
        if (!self.active or !lane.is_first)
            return error.InvalidStackSwapWordRow;
        return .{
            self.execution_clock,
            self.call_index,
            self.pc,
            self.lhs_word_address,
            self.rhs_word_address,
        };
    }

    pub fn memoryEvents(self: Row) Error![6]MemoryEvent {
        if (!self.active) return error.InvalidStackSwapWordRow;
        const clock = access_clock.encode(self.execution_clock, .second);
        if (self.lhs_previous_clock >= clock or self.rhs_previous_clock >= clock)
            return error.InvalidStackSwapWordRow;
        const lhs_byte_address = std.math.mul(
            u32,
            self.lhs_word_address,
            abi.word_bytes,
        ) catch return error.InvalidStackSwapWordRow;
        const rhs_byte_address = std.math.mul(
            u32,
            self.rhs_word_address,
            abi.word_bytes,
        ) catch return error.InvalidStackSwapWordRow;
        return .{
            .requestEvent(lhs_byte_address, self.lhs_previous_clock, self.lhs_before),
            .emitEvent(lhs_byte_address, clock, self.rhs_before),
            .requestEvent(rhs_byte_address, self.rhs_previous_clock, self.rhs_before),
            .emitEvent(rhs_byte_address, clock, self.lhs_before),
            .gapEvent(clock - self.lhs_previous_clock - 1),
            .gapEvent(clock - self.rhs_previous_clock - 1),
        };
    }
};

pub const MemoryTuple = struct {
    address_space: u1 = 1,
    address: u32,
    clock: u32,
    bytes: [4]u8,
};

pub const MemoryEvent = union(enum) {
    request: MemoryTuple,
    emit: MemoryTuple,
    range_gap: u32,

    pub fn requestEvent(address: u32, clock: u32, bytes: [4]u8) MemoryEvent {
        return .{ .request = .{ .address = address, .clock = clock, .bytes = bytes } };
    }

    pub fn emitEvent(address: u32, clock: u32, bytes: [4]u8) MemoryEvent {
        return .{ .emit = .{ .address = address, .clock = clock, .bytes = bytes } };
    }

    pub fn gapEvent(value: u32) MemoryEvent {
        return .{ .range_gap = value };
    }
};

pub fn materializeRow(call: Call, lane: Lane, input: WordInput) Error!Row {
    try call.validate();
    try lane.validate();
    const memory_clock = access_clock.encode(call.execution_clock, .second);
    if (input.lhs_previous_clock >= memory_clock or
        input.rhs_previous_clock >= memory_clock)
    {
        return error.InvalidStackSwapWordRow;
    }
    return .{
        .active = true,
        .execution_clock = call.execution_clock,
        .call_index = call.call_index,
        .pc = call.pc,
        .lhs_word_address = call.lhs_first_word + @as(u32, lane.index),
        .rhs_word_address = call.rhs_first_word + @as(u32, lane.index),
        .lhs_previous_clock = input.lhs_previous_clock,
        .rhs_previous_clock = input.rhs_previous_clock,
        .lhs_before = input.lhs_before,
        .rhs_before = input.rhs_before,
    };
}

pub const Layout = struct {
    pub const active: usize = 0;
    pub const execution_clock: usize = 1;
    pub const call_index: usize = 2;
    pub const pc: usize = 3;
    pub const lhs_word_address: usize = 4;
    pub const rhs_word_address: usize = 5;
    pub const lhs_previous_clock: usize = 6;
    pub const rhs_previous_clock: usize = 7;
    pub const lhs_bytes: usize = 8;
    pub const rhs_bytes: usize = lhs_bytes + 4;
    pub const end: usize = rhs_bytes + 4;

    pub fn lhsByte(index: usize) usize {
        return lhs_bytes + index;
    }

    pub fn rhsByte(index: usize) usize {
        return rhs_bytes + index;
    }
};

pub fn evaluateDirect(
    comptime S: type,
    current: []const S,
    next: []const S,
    current_lane: Lane,
    next_lane: Lane,
    domain_last: S,
    sink: anytype,
) Error!void {
    if (current.len != main_column_count or next.len != main_column_count)
        return error.TraceShapeMismatch;
    try current_lane.validateNext(next_lane);
    const one = S.one();
    const active = current[Layout.active];
    const next_active = next[Layout.active];
    boolean(sink, active);
    boolean(sink, next_active);
    boolean(sink, domain_last);
    const padding = one.sub(active);
    for (current[1..]) |value| sink.add(padding.mul(value), 2);
    sink.add(padding.mul(next_active).mul(one.sub(domain_last)), 3);

    if (!current_lane.is_last) {
        sink.add(active.mul(next_active.sub(one)), 2);
        inline for (.{
            Layout.execution_clock,
            Layout.call_index,
            Layout.pc,
        }) |column| sink.add(active.mul(next[column].sub(current[column])), 2);
        inline for (.{ Layout.lhs_word_address, Layout.rhs_word_address }) |column|
            sink.add(active.mul(next[column].sub(current[column]).sub(one)), 2);
    } else {
        // The circle-domain successor of the deterministic final row is row
        // zero. Subtracting its selector disables only that cyclic edge while
        // preserving degree three and every nonterminal cross-call check.
        const boundary = active.mul(next_active.sub(domain_last));
        sink.add(boundary.mul(
            next[Layout.call_index].sub(current[Layout.call_index]).sub(one),
        ), 3);
    }
}

fn boolean(sink: anytype, value: anytype) void {
    sink.add(value.mul(value.sub(@TypeOf(value).one())), 2);
}

fn feltBool(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

comptime {
    if (production_active or
        lane_count != 8 or
        preprocessed_column_count != 3 or
        main_column_count != 16 or
        interaction_column_count != 16)
    {
        @compileError("stack-swap word geometry drifted");
    }
}
