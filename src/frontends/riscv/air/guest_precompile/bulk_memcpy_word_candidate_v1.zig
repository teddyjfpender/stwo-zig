//! Non-production word-granular bulk-memcpy AIR candidate.
//!
//! This profile intentionally admits only non-overlapping calls whose source
//! and destination have the same alignment modulo four. Their aligned word
//! spans must also be disjoint: otherwise byte-disjoint adjacent calls can
//! request and emit the same boundary word at one subclock. That measured fast
//! path needs one source word and one destination word per trace row; general
//! misalignment would require two source reads and is left to a later profile.
//! Trace and call tuples retain word indices, while memory events convert them
//! to the aligned byte addresses required by the existing byte-limbed
//! `memory_access` tuple. Caller/custom-opcode integration is not present yet,
//! so `production_active` remains false.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");

pub const production_active = false;
pub const minimum_admitted_length: u32 = 32;
pub const data_address_limit: u32 = @as(u32, 1) << 30;
pub const main_column_count: usize = Layout.end;
pub const maximum_constraint_degree: u8 = 3;

pub const Error = error{
    InvalidCall,
    InvalidRow,
    TraceShapeMismatch,
};

pub const Call = struct {
    execution_clock: u32,
    call_index: u32,
    pc: u32,
    source: u32,
    destination: u32,
    length: u32,

    pub fn validate(self: Call) Error!void {
        if (self.execution_clock == 0 or
            access_clock.maximum(self.execution_clock) > std.math.maxInt(u32) or
            self.length < minimum_admitted_length or
            (self.source ^ self.destination) & 3 != 0)
        {
            return error.InvalidCall;
        }
        const source_end = std.math.add(u32, self.source, self.length) catch
            return error.InvalidCall;
        const destination_end = std.math.add(u32, self.destination, self.length) catch
            return error.InvalidCall;
        if (source_end > data_address_limit or destination_end > data_address_limit)
            return error.InvalidCall;
        if (!(source_end <= self.destination or destination_end <= self.source))
            return error.InvalidCall;
        const word_count = self.expectedWordCount();
        const source_word_end = std.math.add(
            u32,
            self.source / 4,
            word_count,
        ) catch return error.InvalidCall;
        const destination_word_end = std.math.add(
            u32,
            self.destination / 4,
            word_count,
        ) catch return error.InvalidCall;
        if (!(source_word_end <= self.destination / 4 or
            destination_word_end <= self.source / 4))
        {
            return error.InvalidCall;
        }
    }

    pub fn startOffset(self: Call) u2 {
        return @truncate(self.destination);
    }

    pub fn expectedWordCount(self: Call) u32 {
        std.debug.assert(self.length != 0);
        return (self.length + @as(u32, self.startOffset()) + 3) / 4;
    }

    pub fn endOffset(self: Call) u3 {
        const remainder: u2 = @truncate(self.destination +% self.length);
        return if (remainder == 0) 4 else remainder;
    }

    pub fn tuple(self: Call) CallTuple {
        return .{
            .execution_clock = self.execution_clock,
            .call_index = self.call_index,
            .pc = self.pc,
            .source_word_index = self.source / 4,
            .destination_word_index = self.destination / 4,
            .length = self.length,
            .expected_word_count = self.expectedWordCount(),
            .start_offset = self.startOffset(),
            .end_offset = self.endOffset(),
        };
    }
};

pub const CallTuple = struct {
    execution_clock: u32,
    call_index: u32,
    pc: u32,
    source_word_index: u32,
    destination_word_index: u32,
    length: u32,
    expected_word_count: u32,
    start_offset: u2,
    end_offset: u3,
};

pub const Row = struct {
    active: bool,
    is_first: bool,
    is_last: bool,
    execution_clock: u32,
    call_index: u32,
    pc: u32,
    word_index: u32,
    expected_word_count: u32,
    length: u32,
    source_word_index: u32,
    destination_word_index: u32,
    source_previous_clock: u32,
    destination_previous_clock: u32,
    source_bytes: [4]u8,
    destination_before: [4]u8,
    destination_after: [4]u8,
    byte_mask: [4]bool,
    start_selectors: [4]bool,
    end_selectors: [4]bool,

    pub fn padding() Row {
        return std.mem.zeroes(Row);
    }

    pub fn encode(self: Row) [main_column_count]M31 {
        var result = [_]M31{M31.zero()} ** main_column_count;
        result[Layout.active] = feltBool(self.active);
        result[Layout.is_first] = feltBool(self.is_first);
        result[Layout.is_last] = feltBool(self.is_last);
        result[Layout.execution_clock] = M31.fromCanonical(self.execution_clock);
        result[Layout.call_index] = M31.fromCanonical(self.call_index);
        result[Layout.pc] = M31.fromCanonical(self.pc);
        result[Layout.word_index] = M31.fromCanonical(self.word_index);
        result[Layout.expected_word_count] = M31.fromCanonical(self.expected_word_count);
        result[Layout.length] = M31.fromCanonical(self.length);
        result[Layout.source_word_index] = M31.fromCanonical(self.source_word_index);
        result[Layout.destination_word_index] = M31.fromCanonical(
            self.destination_word_index,
        );
        result[Layout.source_previous_clock] = M31.fromCanonical(
            self.source_previous_clock,
        );
        result[Layout.destination_previous_clock] = M31.fromCanonical(
            self.destination_previous_clock,
        );
        for (self.source_bytes, 0..) |value, index|
            result[Layout.sourceByte(index)] = M31.fromCanonical(value);
        for (self.destination_before, 0..) |value, index|
            result[Layout.destinationBefore(index)] = M31.fromCanonical(value);
        for (self.destination_after, 0..) |value, index|
            result[Layout.destinationAfter(index)] = M31.fromCanonical(value);
        for (self.byte_mask, 0..) |value, index|
            result[Layout.mask(index)] = feltBool(value);
        for (self.start_selectors, 0..) |value, index|
            result[Layout.startSelector(index)] = feltBool(value);
        for (self.end_selectors, 0..) |value, index|
            result[Layout.endSelector(index)] = feltBool(value);
        return result;
    }

    pub fn firstCallTuple(self: Row) Error!CallTuple {
        if (!self.active or !self.is_first) return error.InvalidRow;
        const start: u2 = @intCast(selectorIndex(self.start_selectors) orelse
            return error.InvalidRow);
        const end_remainder: u2 = @truncate(@as(u32, start) +% self.length);
        return .{
            .execution_clock = self.execution_clock,
            .call_index = self.call_index,
            .pc = self.pc,
            .source_word_index = self.source_word_index,
            .destination_word_index = self.destination_word_index,
            .length = self.length,
            .expected_word_count = self.expected_word_count,
            .start_offset = start,
            .end_offset = if (end_remainder == 0) 4 else end_remainder,
        };
    }

    pub fn memoryEvents(self: Row) Error![6]MemoryEvent {
        if (!self.active) return error.InvalidRow;
        const clock = access_clock.encode(self.execution_clock, .second);
        const source_byte_address = std.math.mul(
            u32,
            self.source_word_index,
            4,
        ) catch return error.InvalidRow;
        const destination_byte_address = std.math.mul(
            u32,
            self.destination_word_index,
            4,
        ) catch return error.InvalidRow;
        return .{
            .requestEvent(source_byte_address, self.source_previous_clock, self.source_bytes),
            .emitEvent(source_byte_address, clock, self.source_bytes),
            .requestEvent(
                destination_byte_address,
                self.destination_previous_clock,
                self.destination_before,
            ),
            .emitEvent(destination_byte_address, clock, self.destination_after),
            .gapEvent(clock -| self.source_previous_clock -| 1),
            .gapEvent(clock -| self.destination_previous_clock -| 1),
        };
    }
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

pub const MemoryTuple = struct {
    address_space: u1 = 1,
    address: u32,
    clock: u32,
    bytes: [4]u8,
};

pub const WordInput = struct {
    source_previous_clock: u32,
    destination_previous_clock: u32,
    source_bytes: [4]u8,
    destination_before: [4]u8,
};

pub fn materializeRow(call: Call, word_index: u32, input: WordInput) Error!Row {
    try call.validate();
    const expected = call.expectedWordCount();
    if (word_index >= expected) return error.InvalidRow;
    const is_first = word_index == 0;
    const is_last = word_index + 1 == expected;
    const start: u3 = if (is_first) call.startOffset() else 0;
    const end: u3 = if (is_last) call.endOffset() else 4;
    if (start >= end) return error.InvalidRow;
    var start_selectors = [_]bool{false} ** 4;
    start_selectors[start] = true;
    var end_selectors = [_]bool{false} ** 4;
    end_selectors[end - 1] = true;
    var mask = [_]bool{false} ** 4;
    var after = input.destination_before;
    for (start..end) |byte| {
        mask[byte] = true;
        after[byte] = input.source_bytes[byte];
    }
    return .{
        .active = true,
        .is_first = is_first,
        .is_last = is_last,
        .execution_clock = call.execution_clock,
        .call_index = call.call_index,
        .pc = call.pc,
        .word_index = word_index,
        .expected_word_count = expected,
        .length = call.length,
        .source_word_index = call.source / 4 + word_index,
        .destination_word_index = call.destination / 4 + word_index,
        .source_previous_clock = input.source_previous_clock,
        .destination_previous_clock = input.destination_previous_clock,
        .source_bytes = input.source_bytes,
        .destination_before = input.destination_before,
        .destination_after = after,
        .byte_mask = mask,
        .start_selectors = start_selectors,
        .end_selectors = end_selectors,
    };
}

pub const Layout = struct {
    pub const active: usize = 0;
    pub const is_first: usize = 1;
    pub const is_last: usize = 2;
    pub const execution_clock: usize = 3;
    pub const call_index: usize = 4;
    pub const pc: usize = 5;
    pub const word_index: usize = 6;
    pub const expected_word_count: usize = 7;
    pub const length: usize = 8;
    pub const source_word_index: usize = 9;
    pub const destination_word_index: usize = 10;
    pub const source_previous_clock: usize = 11;
    pub const destination_previous_clock: usize = 12;
    pub const source_bytes: usize = 13;
    pub const destination_before: usize = source_bytes + 4;
    pub const destination_after: usize = destination_before + 4;
    pub const byte_mask: usize = destination_after + 4;
    pub const start_selectors: usize = byte_mask + 4;
    pub const end_selectors: usize = start_selectors + 4;
    pub const end: usize = end_selectors + 4;

    pub fn sourceByte(index: usize) usize {
        return source_bytes + index;
    }
    pub fn destinationBefore(index: usize) usize {
        return destination_before + index;
    }
    pub fn destinationAfter(index: usize) usize {
        return destination_after + index;
    }
    pub fn mask(index: usize) usize {
        return byte_mask + index;
    }
    pub fn startSelector(index: usize) usize {
        return start_selectors + index;
    }
    pub fn endSelector(index: usize) usize {
        return end_selectors + index;
    }
};

/// Evaluate the profile-local transition constraints for `current` and its
/// next committed row.  A padding row must be all-zero and active rows are
/// dense.  Call-boundary tuples are authenticated separately by the future
/// custom-instruction caller component.
pub fn evaluateDirect(
    comptime S: type,
    current: []const S,
    next: []const S,
    sink: anytype,
) Error!void {
    if (current.len != main_column_count or next.len != main_column_count)
        return error.TraceShapeMismatch;
    const zero = S.zero();
    const one = S.one();
    const active = current[Layout.active];
    const first = current[Layout.is_first];
    const last = current[Layout.is_last];
    const next_active = next[Layout.active];
    const next_first = next[Layout.is_first];
    const next_last = next[Layout.is_last];
    boolean(sink, active);
    boolean(sink, first);
    boolean(sink, last);
    boolean(sink, next_active);
    boolean(sink, next_first);
    boolean(sink, next_last);
    sink.add(first.mul(one.sub(active)), 2);
    sink.add(last.mul(one.sub(active)), 2);

    const padding = one.sub(active);
    for (current[1..]) |value| sink.add(padding.mul(value), 2);
    sink.add(padding.mul(next_active), 2);

    for (0..4) |index| {
        boolean(sink, current[Layout.mask(index)]);
        boolean(sink, current[Layout.startSelector(index)]);
        boolean(sink, current[Layout.endSelector(index)]);
    }
    sink.add(sum4(S, current, Layout.start_selectors).sub(active), 1);
    sink.add(sum4(S, current, Layout.end_selectors).sub(active), 1);

    const start = weighted4(S, current, Layout.start_selectors, 0);
    const end = weighted4(S, current, Layout.end_selectors, 1);
    sink.add(active.mul(one.sub(first)).mul(start), 3);
    sink.add(active.mul(one.sub(last)).mul(end.sub(scalar(S, 4))), 3);
    for (1..4) |start_index| for (0..start_index) |end_index| {
        sink.add(current[Layout.startSelector(start_index)].mul(
            current[Layout.endSelector(end_index)],
        ), 2);
    };
    for (0..4) |byte| {
        var starts_before = zero;
        for (0..byte + 1) |index|
            starts_before = starts_before.add(current[Layout.startSelector(index)]);
        var ends_after = zero;
        for (byte..4) |index|
            ends_after = ends_after.add(current[Layout.endSelector(index)]);
        const mask = current[Layout.mask(byte)];
        sink.add(mask.sub(starts_before.mul(ends_after)), 2);
        const source = current[Layout.sourceByte(byte)];
        const before = current[Layout.destinationBefore(byte)];
        const after = current[Layout.destinationAfter(byte)];
        sink.add(after.sub(mask.mul(source).add(one.sub(mask).mul(before))), 2);
    }

    sink.add(first.mul(current[Layout.word_index]), 2);
    sink.add(last.mul(
        current[Layout.word_index]
            .add(one)
            .sub(current[Layout.expected_word_count]),
    ), 2);

    const continues = active.mul(one.sub(last));
    sink.add(continues.mul(next_active.sub(one)), 2);
    sink.add(continues.mul(next_first), 2);
    sink.add(continues.mul(
        next[Layout.execution_clock].sub(current[Layout.execution_clock]),
    ), 2);
    sink.add(continues.mul(next[Layout.call_index].sub(current[Layout.call_index])), 2);
    sink.add(continues.mul(next[Layout.pc].sub(current[Layout.pc])), 2);
    sink.add(continues.mul(
        next[Layout.word_index].sub(current[Layout.word_index]).sub(one),
    ), 2);
    sink.add(continues.mul(
        next[Layout.expected_word_count].sub(current[Layout.expected_word_count]),
    ), 2);
    sink.add(continues.mul(next[Layout.length].sub(current[Layout.length])), 2);
    sink.add(continues.mul(
        next[Layout.source_word_index].sub(current[Layout.source_word_index]).sub(one),
    ), 2);
    sink.add(continues.mul(
        next[Layout.destination_word_index]
            .sub(current[Layout.destination_word_index])
            .sub(one),
    ), 2);

    const boundary = active.mul(last).mul(next_active);
    sink.add(boundary.mul(next_first.sub(one)), 3);
    sink.add(boundary.mul(
        next[Layout.call_index].sub(current[Layout.call_index]).sub(one),
    ), 3);
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
    return S.fromU64(value);
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
