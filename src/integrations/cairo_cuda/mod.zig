//! Cairo-to-generic-proof-program integration.
//!
//! No CUDA runtime is exposed yet. The only emitter is explicitly limited to
//! proof-derived development semantics.

pub const identity = @import("identity.zig");
pub const casm_input = @import("casm_input.zig");
pub const lowering_map = @import("lowering_map.zig");
pub const program = @import("program.zig");

test {
    _ = @import("casm_input_test.zig");
    _ = @import("witness_edge_test.zig");
    _ = @import("witness_multi_edge_test.zig");
    _ = lowering_map;
    _ = @import("program_test.zig");
}
