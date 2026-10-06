//! `crates/circuit_prover/src/witness`: the circuit prover's base and
//! interaction traces (design §4.3).

pub const components = @import("components.zig");
pub const trace = @import("trace.zig");
pub const sparse_arithmetic = @import("sparse_arithmetic.zig");
pub const sparse_wide = @import("sparse_wide.zig");
pub const direct_arithmetic = @import("direct_arithmetic.zig");

test {
    _ = components;
    _ = trace;
    _ = sparse_arithmetic;
    _ = sparse_wide;
}
