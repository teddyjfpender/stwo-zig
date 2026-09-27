//! Existing typed caller equations, sharing tree 3 and one composition/FRI.
const Shared = @import("block_v5_composite_projection_adapter_v1.zig");
pub const Program = Shared.Projection(@import("block_v5_program_extension_component_v1.zig").Component);
pub const Tables = Shared.Projection(@import("block_v5_precompile_lookup_component_v1.zig").Component);
pub const Memory = Shared.Access(@import("block_execution_sidecar_stark_v2.zig").Component);
