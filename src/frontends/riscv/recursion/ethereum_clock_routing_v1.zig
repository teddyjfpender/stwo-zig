//! Fixed Ethereum clock-source coordinates. Native transcript payloads and
//! recursive statement consumers use this same namespace and wire layout.
const wire = @import("segment_statement_v2.zig");

pub const SCHEMA_VERSION: u32 = 1;
pub const STATEMENT_SCOPE: u32 = 5;
pub const WORD_COUNT: usize = 128;
pub const WIRE_START: usize = wire.fixed_layout.entry_register_clocks;

pub fn indexFromWire(word: usize) ?u32 {
    if (word < WIRE_START or word - WIRE_START >= WORD_COUNT) return null;
    return @intCast(word - WIRE_START);
}

/// Each admitted clock word is consumed once, even when its arithmetic
/// destination has no uses, so source and range closure stay exact.
pub fn sourceUses(index: usize) u32 {
    return @intFromBool(index < WORD_COUNT);
}

comptime {
    if (wire.fixed_layout.exit_register_clocks != WIRE_START + WORD_COUNT / 2)
        @compileError("Ethereum register clock layout is not contiguous");
}
