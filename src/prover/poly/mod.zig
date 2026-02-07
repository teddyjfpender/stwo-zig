pub const circle = @import("circle/mod.zig");
pub const twiddles = @import("twiddles.zig");

/// Bit-reversed evaluation ordering.
pub const BitReversedOrder = struct {};

/// Natural evaluation ordering (same order as domain).
pub const NaturalOrder = struct {};
