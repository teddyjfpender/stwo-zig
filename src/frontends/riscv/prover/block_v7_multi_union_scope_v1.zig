//! Terminal compatibility API. Explicit window mode has its own admitted theorem.
pub const ForMode = @import("block_v7_multi_union_scope_family_v1.zig").ForMode;
const Default = ForMode(false);
pub const Input = Default.Input;
pub const Limits = Default.Limits;
pub const Local = Default.Local;
pub const Owned = Default.Owned;
pub const nativeLogs = Default.nativeLogs;
