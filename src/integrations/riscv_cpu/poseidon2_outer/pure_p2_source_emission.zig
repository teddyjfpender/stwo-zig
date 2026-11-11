//! Borrowed source-emission result. Variable IDs belong to the caller's active
//! context; no statement arena, native proof or captured-value pointer escapes.
const C = @import("full_p2_common.zig");
pub const Emission = struct {
    output: [9]C.Var,
    mutation_ports: [4]C.Var,
};
