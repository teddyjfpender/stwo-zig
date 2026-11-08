pub const circle = @import("circle/mod.zig");
pub const twiddle_source = @import("twiddle_source.zig");
pub const twiddle_tower = @import("twiddle_tower.zig");
pub const twiddles = @import("twiddles.zig");

/// Bit-reversed evaluation ordering.
pub const BitReversedOrder = struct {};

/// Natural evaluation ordering (same order as domain).
pub const NaturalOrder = struct {};
