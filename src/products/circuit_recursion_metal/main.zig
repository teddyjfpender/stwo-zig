//! Circuit recursion CLI with Metal Cairo leaf and circuit provers.

pub fn main() !void {
    const metal = @import("stwo_circuit_metal_integration");
    const cairo_metal = @import("stwo_cairo_metal_integration");
    return @import("circuit_recursion_app").mainWith(cairo_metal.prover.leaf_transaction, &metal.provers);
}
