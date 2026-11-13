//! Consumer-owned laws selected for the stwo_cairo_frontend boundary.
const provider = @import("stwo_backend_contracts");
const laws = @import("waist_consumer_laws");
const core = @import("stwo_core");

test "cdc: stwo_cairo_frontend line geometry rejects invalid storage" {
    try laws.line(provider, core);
}
