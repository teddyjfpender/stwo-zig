//! `crates/circuit_prover/src/witness`: the circuit prover's base and
//! interaction traces (design §4.3).

pub const components = @import("components.zig");
pub const lookup_repeat2 = @import("lookup_repeat2.zig");
pub const trace = @import("trace.zig");

test {
    _ = components;
    _ = trace;
    _ = lookup_repeat2;
}
