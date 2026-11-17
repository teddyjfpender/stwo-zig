//! Consumer-owned laws selected for the stwo_cairo_metal_integration boundary.
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");

test "cdc: stwo_cairo_metal_integration arena admission and unknown binding refusal" {
    try laws.arena(provider);
}
