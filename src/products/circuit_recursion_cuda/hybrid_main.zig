//! Historical hybrid experiment: CPU Cairo/PCS with CUDA grinds only.
pub fn main() !void {
    const cuda = @import("stwo_circuit_cuda_integration");
    const cairo_cpu = @import("stwo_cairo_cpu_integration");
    return @import("circuit_recursion_app").mainWith(cairo_cpu.prover.leaf_transaction, &cuda.provers);
}
