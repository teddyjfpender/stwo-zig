//! Circuit recursion CLI with CPU Cairo/PCS and CUDA proof-of-work grinds.
//!
//! This is a hybrid measurement product. The device handles the interaction
//! and FRI grinds of each circuit proof; Cairo and all other circuit stages
//! stay on CPU until their resident CUDA implementations are qualified.

pub fn main() !void {
    const cuda = @import("stwo_circuit_cuda_integration");
    const cairo_cpu = @import("stwo_cairo_cpu_integration");
    return @import("circuit_recursion_app").mainWith(cairo_cpu.prover.leaf_transaction, &cuda.provers);
}
