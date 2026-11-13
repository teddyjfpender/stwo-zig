//! Consumer-owned laws selected for the stwo_cairo_cuda_integration boundary.
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_cairo_cuda_integration native geometry overflow and domain refusal" {
    try laws.nativeGeometry(provider);
}
