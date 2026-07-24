//! Cairo-to-generic-proof-program integration.
//!
//! No CUDA runtime is exposed yet. The only emitter is explicitly limited to
//! proof-derived development semantics.

pub const identity = @import("identity.zig");
pub const program = @import("program.zig");

test {
    _ = @import("program_test.zig");
}
