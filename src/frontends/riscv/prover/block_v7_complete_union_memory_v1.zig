//! Terminal union memory compatibility facade; equations and ownership are
//! shared with the explicit nonterminal state-delta context.
pub const ForMode = @import("block_v7_union_memory_family_v1.zig").ForMode;
const Default = ForMode(false);
pub const Claims = Default.Claims;
pub const Input = Default.Input;
pub const Context = Default.Context;
pub const prepare = Default.prepare;
pub const verifier = Default.verifier;
