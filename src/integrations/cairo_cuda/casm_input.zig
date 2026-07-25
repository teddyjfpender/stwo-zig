//! Development-only Cairo binding to the resident CASM witness stage.

const implementation =
    @import("../../backends/cuda/runtime/stages/cairo_witness.zig");
const plan =
    @import("../../backends/cuda/runtime/stages/cairo_witness_plan.zig");
const abi =
    @import("../../backends/cuda/abi/stages/cairo_witness.zig");

pub const Native = implementation.Native;
pub const Geometry = implementation.Geometry;
pub const Columns = implementation.Columns;
pub const SeedGeometry = implementation.SeedGeometry;
pub const EdgeGeometry = implementation.EdgeGeometry;
pub const OpsFor = implementation.OpsFor;
pub const MultiEdgeDescriptor = abi.MultiEdgeDescriptor;
pub const MultiEdgeTopology = plan.MultiEdgeTopology;
pub const prepareMultiEdgeTopology = plan.prepareMultiEdgeTopology;
