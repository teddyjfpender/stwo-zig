//! Product profile/extension binding; recorder and Result stay canonical.
const shared = @import("stwo_riscv_recursion").vm_composition_graph_base;
const Bound = shared.ForProfile(@import("ethereum_variable_boundary_air_profile.zig").ProfileV2, @import("ethereum_vm_composition_graph_support.zig"));
pub const Result = shared.Result;
pub const record = Bound.record;
pub const recordWithFixedProgram = Bound.recordWithFixedProgram;
