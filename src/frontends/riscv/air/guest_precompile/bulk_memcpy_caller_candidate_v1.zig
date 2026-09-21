//! Non-production fixed-register caller AIR for word-granular bulk memcpy.
//!
//! The caller reads a0/a1/a2, proves the same-mod-four and non-overlap fast
//! path, range-constrains every 30-bit span value, and emits one call tuple for
//! the first word row.  Native event construction mirrors the existing
//! program/state/register/range relations.  A full LogUp component and live
//! CUSTOM-0 dispatch are deliberately absent, so production activation is
//! false.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");

pub const production_active = false;
pub const main_column_count: usize = Layout.end;
pub const maximum_constraint_degree: u8 = 3;

pub const Error = words.Error || error{
    InvalidCallerRecord,
    TraceShapeMismatch,
};

pub const Record = struct {
    execution_clock: u32,
    pc: u32,
    destination_previous_clock: u32,
    source_previous_clock: u32,
    length_previous_clock: u32,
    destination: u32,
    source: u32,
    length: u32,
    call_index: u32,

    pub fn call(self: Record) words.Call {
        return .{
            .execution_clock = self.execution_clock,
            .call_index = self.call_index,
            .pc = self.pc,
            .source = self.source,
            .destination = self.destination,
            .length = self.length,
        };
    }

    pub fn validate(self: Record) Error!void {
        try self.call().validate();
        const register_clock = access_clock.encode(self.execution_clock, .first);
        if (self.destination_previous_clock >= register_clock or
            self.source_previous_clock >= register_clock or
            self.length_previous_clock >= register_clock)
        {
            return error.InvalidCallerRecord;
        }
    }
};

const ValueGroup = enum(usize) {
    destination,
    source,
    length,
    source_end,
    destination_end,
    gap,
    aligned_word_gap,
    length_minus_minimum,
};

const value_group_count = std.meta.fields(ValueGroup).len;

pub const Row = struct {
    active: bool,
    execution_clock: u32,
    pc: u32,
    previous_clocks: [3]u32,
    values: [value_group_count]u32,
    destination_before_source: bool,
    start_selectors: [4]bool,
    end_selectors: [4]bool,
    destination_word_index: u32,
    source_word_index: u32,
    expected_word_count: u32,
    high_bits: [value_group_count][6]bool,
    call_index: u32,

    pub fn padding() Row {
        return std.mem.zeroes(Row);
    }

    pub fn callTuple(self: Row) Error!words.CallTuple {
        if (!self.active) return error.InvalidCallerRecord;
        const start: u2 = @intCast(selectorIndex(self.start_selectors) orelse
            return error.InvalidCallerRecord);
        const end_index = selectorIndex(self.end_selectors) orelse
            return error.InvalidCallerRecord;
        return .{
            .execution_clock = self.execution_clock,
            .call_index = self.call_index,
            .pc = self.pc,
            .source_word_index = self.source_word_index,
            .destination_word_index = self.destination_word_index,
            .length = self.values[@intFromEnum(ValueGroup.length)],
            .expected_word_count = self.expected_word_count,
            .start_offset = start,
            .end_offset = @intCast(end_index + 1),
        };
    }

    pub fn encode(self: Row) [main_column_count]M31 {
        var result = [_]M31{M31.zero()} ** main_column_count;
        result[Layout.active] = feltBool(self.active);
        result[Layout.execution_clock] = M31.fromCanonical(self.execution_clock);
        result[Layout.pc] = M31.fromCanonical(self.pc);
        for (self.previous_clocks, 0..) |clock, index|
            result[Layout.previousClock(index)] = M31.fromCanonical(clock);
        for (self.values, 0..) |value, group| {
            const bytes = littleEndianBytes(value);
            for (bytes, 0..) |byte, index|
                result[Layout.valueByte(group, index)] = M31.fromCanonical(byte);
        }
        result[Layout.disjoint_side] = feltBool(self.destination_before_source);
        for (self.start_selectors, 0..) |value, index|
            result[Layout.startSelector(index)] = feltBool(value);
        for (self.end_selectors, 0..) |value, index|
            result[Layout.endSelector(index)] = feltBool(value);
        result[Layout.destination_word_index] = M31.fromCanonical(
            self.destination_word_index,
        );
        result[Layout.source_word_index] = M31.fromCanonical(self.source_word_index);
        result[Layout.expected_word_count] = M31.fromCanonical(self.expected_word_count);
        for (self.high_bits, 0..) |bits, group| {
            for (bits, 0..) |value, bit|
                result[Layout.highBit(group, bit)] = feltBool(value);
        }
        result[Layout.call_index] = M31.fromCanonical(self.call_index);
        return result;
    }

    pub fn relationEvents(self: Row) Error!RelationEvents {
        if (!self.active) return error.InvalidCallerRecord;
        const register_clock = access_clock.encode(self.execution_clock, .first);
        const destination = littleEndianBytes(
            self.values[@intFromEnum(ValueGroup.destination)],
        );
        const source = littleEndianBytes(self.values[@intFromEnum(ValueGroup.source)]);
        const length = littleEndianBytes(self.values[@intFromEnum(ValueGroup.length)]);
        var range_pairs: [value_group_count * 2]RangePair = undefined;
        for (self.values, 0..) |value, group| {
            const bytes = littleEndianBytes(value);
            range_pairs[group * 2] = .{ .left = bytes[0], .right = bytes[1] };
            range_pairs[group * 2 + 1] = .{ .left = bytes[2], .right = bytes[3] };
        }
        return .{
            .program = abi.programTuple(self.pc),
            .state_before = .{ self.pc, self.execution_clock },
            .state_after = .{ self.pc + 4, self.execution_clock + 1 },
            .registers = .{
                RegisterChain.init(
                    abi.destination_register,
                    self.previous_clocks[0],
                    register_clock,
                    destination,
                ),
                RegisterChain.init(
                    abi.source_register,
                    self.previous_clocks[1],
                    register_clock,
                    source,
                ),
                RegisterChain.init(
                    abi.length_register,
                    self.previous_clocks[2],
                    register_clock,
                    length,
                ),
            },
            .range_pairs = range_pairs,
            .call = try self.callTuple(),
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

pub const RangePair = struct {
    left: u8,
    right: u8,
};

pub const RelationEvents = struct {
    program: [5]u32,
    state_before: [2]u32,
    state_after: [2]u32,
    registers: [3]RegisterChain,
    range_pairs: [value_group_count * 2]RangePair,
    call: words.CallTuple,
};

pub fn materialize(record: Record) Error!Row {
    try record.validate();
    const call = record.call();
    const source_end = record.source + record.length;
    const destination_end = record.destination + record.length;
    const destination_before_source = destination_end <= record.source;
    const gap = if (destination_before_source)
        record.source - destination_end
    else
        record.destination - source_end;
    const aligned_word_gap = if (destination_before_source)
        record.source / 4 - (record.destination / 4 + call.expectedWordCount())
    else
        record.destination / 4 - (record.source / 4 + call.expectedWordCount());
    const values = [value_group_count]u32{
        record.destination,
        record.source,
        record.length,
        source_end,
        destination_end,
        gap,
        aligned_word_gap,
        record.length - words.minimum_admitted_length,
    };
    var high_bits: [value_group_count][6]bool = undefined;
    for (values, 0..) |value, group| {
        for (0..6) |bit|
            high_bits[group][bit] = value >> @intCast(24 + bit) & 1 != 0;
    }
    var start_selectors = [_]bool{false} ** 4;
    start_selectors[call.startOffset()] = true;
    var end_selectors = [_]bool{false} ** 4;
    end_selectors[call.endOffset() - 1] = true;
    return .{
        .active = true,
        .execution_clock = record.execution_clock,
        .pc = record.pc,
        .previous_clocks = .{
            record.destination_previous_clock,
            record.source_previous_clock,
            record.length_previous_clock,
        },
        .values = values,
        .destination_before_source = destination_before_source,
        .start_selectors = start_selectors,
        .end_selectors = end_selectors,
        .destination_word_index = record.destination / 4,
        .source_word_index = record.source / 4,
        .expected_word_count = call.expectedWordCount(),
        .high_bits = high_bits,
        .call_index = record.call_index,
    };
}

pub const Layout = struct {
    pub const active: usize = 0;
    pub const execution_clock: usize = 1;
    pub const pc: usize = 2;
    pub const previous_clocks: usize = 3;
    pub const values: usize = previous_clocks + 3;
    pub const disjoint_side: usize = values + value_group_count * 4;
    pub const start_selectors: usize = disjoint_side + 1;
    pub const end_selectors: usize = start_selectors + 4;
    pub const destination_word_index: usize = end_selectors + 4;
    pub const source_word_index: usize = destination_word_index + 1;
    pub const expected_word_count: usize = source_word_index + 1;
    pub const high_bits: usize = expected_word_count + 1;
    pub const call_index: usize = high_bits + value_group_count * 6;
    pub const end: usize = call_index + 1;

    pub fn previousClock(index: usize) usize {
        return previous_clocks + index;
    }
    pub fn valueByte(group: usize, byte: usize) usize {
        return values + group * 4 + byte;
    }
    pub fn startSelector(index: usize) usize {
        return start_selectors + index;
    }
    pub fn endSelector(index: usize) usize {
        return end_selectors + index;
    }
    pub fn highBit(group: usize, bit: usize) usize {
        return high_bits + group * 6 + bit;
    }
};

pub fn evaluateDirect(comptime S: type, row: []const S, sink: anytype) Error!void {
    if (row.len != main_column_count) return error.TraceShapeMismatch;
    const one = S.one();
    const active = row[Layout.active];
    boolean(sink, active);
    const padding = one.sub(active);
    for (row[1..]) |value| sink.add(padding.mul(value), 2);
    boolean(sink, row[Layout.disjoint_side]);
    for (0..4) |index| {
        boolean(sink, row[Layout.startSelector(index)]);
        boolean(sink, row[Layout.endSelector(index)]);
    }
    sink.add(sum4(S, row, Layout.start_selectors).sub(active), 1);
    sink.add(sum4(S, row, Layout.end_selectors).sub(active), 1);
    for (0..value_group_count) |group| {
        for (0..6) |bit| boolean(sink, row[Layout.highBit(group, bit)]);
        var reconstructed = S.zero();
        for (0..6) |bit| reconstructed = reconstructed.add(
            row[Layout.highBit(group, bit)].mul(scalar(S, @as(u32, 1) << @intCast(bit))),
        );
        sink.add(
            row[Layout.valueByte(group, 3)].sub(reconstructed),
            1,
        );
    }

    const destination = composeBytes(S, row, @intFromEnum(ValueGroup.destination));
    const source = composeBytes(S, row, @intFromEnum(ValueGroup.source));
    const length = composeBytes(S, row, @intFromEnum(ValueGroup.length));
    const source_end = composeBytes(S, row, @intFromEnum(ValueGroup.source_end));
    const destination_end = composeBytes(
        S,
        row,
        @intFromEnum(ValueGroup.destination_end),
    );
    const gap = composeBytes(S, row, @intFromEnum(ValueGroup.gap));
    const aligned_word_gap = composeBytes(
        S,
        row,
        @intFromEnum(ValueGroup.aligned_word_gap),
    );
    const length_minus = composeBytes(
        S,
        row,
        @intFromEnum(ValueGroup.length_minus_minimum),
    );
    const start = weighted4(S, row, Layout.start_selectors, 0);
    const end = weighted4(S, row, Layout.end_selectors, 1);
    sink.add(destination.sub(
        row[Layout.destination_word_index].mul(scalar(S, 4)).add(start),
    ), 1);
    sink.add(source.sub(
        row[Layout.source_word_index].mul(scalar(S, 4)).add(start),
    ), 1);
    sink.add(source.add(length).sub(source_end), 1);
    sink.add(destination.add(length).sub(destination_end), 1);
    sink.add(active.mul(
        length.sub(scalar(S, words.minimum_admitted_length)).sub(length_minus),
    ), 2);
    sink.add(active.mul(length.add(start).sub(
        row[Layout.expected_word_count]
            .sub(one)
            .mul(scalar(S, 4))
            .add(end),
    )), 2);
    const side = row[Layout.disjoint_side];
    sink.add(active.mul(one.sub(side)).mul(
        destination.sub(source_end).sub(gap),
    ), 3);
    sink.add(active.mul(side).mul(source.sub(destination_end).sub(gap)), 3);
    sink.add(active.mul(one.sub(side)).mul(
        row[Layout.destination_word_index]
            .sub(row[Layout.source_word_index])
            .sub(row[Layout.expected_word_count])
            .sub(aligned_word_gap),
    ), 3);
    sink.add(active.mul(side).mul(
        row[Layout.source_word_index]
            .sub(row[Layout.destination_word_index])
            .sub(row[Layout.expected_word_count])
            .sub(aligned_word_gap),
    ), 3);
}

fn littleEndianBytes(value: u32) [4]u8 {
    return .{ @truncate(value), @truncate(value >> 8), @truncate(value >> 16), @truncate(value >> 24) };
}

fn composeBytes(comptime S: type, row: []const S, group: usize) S {
    return row[Layout.valueByte(group, 0)]
        .add(row[Layout.valueByte(group, 1)].mul(scalar(S, 1 << 8)))
        .add(row[Layout.valueByte(group, 2)].mul(scalar(S, 1 << 16)))
        .add(row[Layout.valueByte(group, 3)].mul(scalar(S, 1 << 24)));
}

fn boolean(sink: anytype, value: anytype) void {
    sink.add(value.mul(value.sub(@TypeOf(value).one())), 2);
}

fn sum4(comptime S: type, values: []const S, start: usize) S {
    var result = S.zero();
    for (0..4) |index| result = result.add(values[start + index]);
    return result;
}

fn weighted4(
    comptime S: type,
    values: []const S,
    start: usize,
    comptime offset: u32,
) S {
    var result = S.zero();
    for (0..4) |index| result = result.add(
        values[start + index].mul(scalar(S, @as(u32, @intCast(index)) + offset)),
    );
    return result;
}

fn scalar(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

fn feltBool(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

fn selectorIndex(selectors: [4]bool) ?usize {
    var result: ?usize = null;
    for (selectors, 0..) |selected, index| {
        if (!selected) continue;
        if (result != null) return null;
        result = index;
    }
    return result;
}
