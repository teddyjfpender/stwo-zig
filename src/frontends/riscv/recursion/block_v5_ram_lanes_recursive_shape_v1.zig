//! Genuine original24/54/92 lane geometry+117-equation fixed compiler pieces.
//! No recursive-parent geometry substitution and no proof/capture authority.
const Factory = @import("block_v5_word_recursive_fixed_v1.zig").ForFamily(.ram_lanes);
pub const Shape = Factory.Shape;
pub const Compiled = Factory.Compiled;
pub const Owned = Factory.Owned;
pub const Limits = @import("block_v5_word_recursive_fixed_v1.zig").Limits;
