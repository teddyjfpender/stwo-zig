//! Coordinates shared by statement byte exports and native-sum graph inputs.
//! These bytes already have decomposition and range constraints in row 11.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const wire = @import("segment_statement_v2.zig");
const span = @import("span_statement.zig");

pub const Side = enum { entry, exit };
pub const BYTE_COUNT: usize = 2 * 32 * 4;

pub fn byteIndex(side: Side, register: usize, byte: usize) usize {
    std.debug.assert(register < 32 and byte < 4);
    return @as(usize, @intFromEnum(side)) * 128 + register * 4 + byte;
}

pub fn wireWordIndex(byte_index: usize) usize {
    std.debug.assert(byte_index < BYTE_COUNT);
    const state = if (byte_index < 128) span.canonical_layout.entry_state_start else span.canonical_layout.exit_state_start;
    return wire.fixed_layout.base_statement + state +
        span.canonical_layout.machine_state_registers_start_offset + (byte_index % 128) / 2;
}

pub fn firstByteIndexForWireWord(wire_index: usize) ?usize {
    inline for (.{ Side.entry, Side.exit }) |side| {
        const start = wireWordIndex(byteIndex(side, 0, 0));
        if (wire_index >= start and wire_index - start < 64)
            return byteIndex(side, 0, 0) + (wire_index - start) * 2;
    }
    return null;
}

pub fn bridgeIndex(wire_word_count: usize, byte_index: usize) usize {
    std.debug.assert(byte_index < BYTE_COUNT);
    return wire_word_count + byte_index;
}

pub fn inputIndex(existing_input_count: usize, byte_index: usize) usize {
    std.debug.assert(byte_index < BYTE_COUNT);
    return existing_input_count + byte_index;
}

/// Witness extraction only; row 11 supplies the proof of this decomposition.
pub fn value(words: []const M31, byte_index: usize) M31 {
    const word = words[wireWordIndex(byte_index)].toU32();
    std.debug.assert(word <= std.math.maxInt(u16));
    const shift: u5 = @intCast((byte_index % 2) * 8);
    return M31.fromCanonical((word >> shift) & 0xff);
}
