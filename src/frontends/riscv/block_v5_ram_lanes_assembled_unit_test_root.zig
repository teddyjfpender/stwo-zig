//! Focused source custody, physical warm commitments and assembled API bodies.
//! No STARK, FRI, segment, recursive proof, driver or CLI is executed.
test {
    _ = @import("prover/block_v5_ram_lanes_lifecycle_unit_test.zig");
    _ = @import("prover/block_v5_ram_lanes_production_unit_test.zig");
}
