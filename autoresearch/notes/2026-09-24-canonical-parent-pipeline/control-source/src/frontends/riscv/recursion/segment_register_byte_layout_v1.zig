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

/// Value-independent coordinates for retained sparse words. Section membership
/// is admitted geometry; byte values and nonzero selectors are AIR inputs.
pub const MemoryLayout = struct {
    entry: wire.RetainedSectionV2,
    exit: wire.RetainedSectionV2,

    pub fn init(view: *const wire.CanonicalWireViewV2) !MemoryLayout {
        const count = std.math.add(usize, view.entry_snapshot.count, view.exit_snapshot.count) catch return error.ArithmeticOverflow;
        const bytes = std.math.mul(usize, count, 4) catch return error.ArithmeticOverflow;
        _ = std.math.add(usize, BYTE_COUNT, std.math.mul(usize, bytes, 2) catch return error.ArithmeticOverflow) catch return error.ArithmeticOverflow;
        return .{ .entry = view.entry_snapshot, .exit = view.exit_snapshot };
    }

    pub fn memoryByteCount(self: MemoryLayout) usize {
        return (@as(usize, self.entry.count) + self.exit.count) * 4;
    }
    pub fn byteCount(self: MemoryLayout) usize {
        return BYTE_COUNT + self.memoryByteCount();
    }
    pub fn totalBridgeWords(self: MemoryLayout) usize {
        return BYTE_COUNT + 2 * self.memoryByteCount();
    }
    pub fn byteIndex(self: MemoryLayout, side: Side, entry_index: usize, byte: usize) usize {
        const section = if (side == .entry) self.entry else self.exit;
        std.debug.assert(entry_index < section.count and byte < 4);
        return BYTE_COUNT + (if (side == .entry) @as(usize, 0) else @as(usize, self.entry.count) * 4) + entry_index * 4 + byte;
    }
    pub fn firstByteIndexForWireWord(self: MemoryLayout, index: usize) ?usize {
        inline for (.{ Side.entry, Side.exit }) |side| {
            const section = if (side == .entry) self.entry else self.exit;
            if (index >= section.payload_start) {
                const relative = index - section.payload_start;
                const entry_index = relative / wire.RETAINED_ENTRY_WORDS;
                const limb = relative % wire.RETAINED_ENTRY_WORDS;
                if (entry_index < section.count and limb >= 2 and limb < 4)
                    return self.byteIndex(side, entry_index, (limb - 2) * 2);
            }
        }
        return null;
    }
    pub fn wireWordIndex(self: MemoryLayout, global_byte: usize) usize {
        std.debug.assert(global_byte >= BYTE_COUNT and global_byte < self.byteCount());
        const relative = global_byte - BYTE_COUNT;
        const entry_bytes = @as(usize, self.entry.count) * 4;
        const section = if (relative < entry_bytes) self.entry else self.exit;
        const local = if (relative < entry_bytes) relative else relative - entry_bytes;
        return section.payload_start + local / 4 * wire.RETAINED_ENTRY_WORDS + 2 + (local % 4) / 2;
    }
    pub fn value(self: MemoryLayout, words: []const M31, global_byte: usize) M31 {
        const word = words[self.wireWordIndex(global_byte)].toU32();
        std.debug.assert(word <= std.math.maxInt(u16));
        const shift: u5 = @intCast((global_byte % 2) * 8);
        return M31.fromCanonical((word >> shift) & 0xff);
    }
    pub fn selectorIndex(self: MemoryLayout, global_byte: usize) usize {
        std.debug.assert(global_byte >= BYTE_COUNT and global_byte < self.byteCount());
        return self.byteCount() + global_byte - BYTE_COUNT;
    }
};
