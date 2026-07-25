//! Development-only Cairo binding to the resident CASM witness stage.

const implementation =
    @import("../../backends/cuda/runtime/stages/cairo_witness.zig");

pub const Native = implementation.Native;
pub const Geometry = implementation.Geometry;
pub const Columns = implementation.Columns;
pub const SeedGeometry = implementation.SeedGeometry;
pub const OpsFor = implementation.OpsFor;
