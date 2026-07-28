//! Development-only Cairo binding to the resident CASM witness stage.

const implementation =
    @import("stwo_cuda_backend").runtime.stages.cairo_witness;
const plan =
    @import("stwo_cuda_backend").runtime.stages.cairo_witness_plan;
const abi =
    @import("stwo_cuda_backend").abi.stages.cairo_witness;

pub const Native = implementation.Native;
pub const Geometry = implementation.Geometry;
pub const Columns = implementation.Columns;
pub const SeedGeometry = implementation.SeedGeometry;
pub const EdgeGeometry = implementation.EdgeGeometry;
pub const OpsFor = implementation.OpsFor;
pub const MultiEdgeDescriptor = abi.MultiEdgeDescriptor;
pub const MultiEdgeTopology = plan.MultiEdgeTopology;
pub const prepareMultiEdgeTopology = plan.prepareMultiEdgeTopology;
