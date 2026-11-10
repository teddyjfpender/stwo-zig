//! Product profile/extension binding; recorder and Result stay canonical.
const shared = @import("vm_composition_graph_base.zig");
const Bound = shared.ForProfile(@import("ethereum_vm_air_profile_v2.zig").ProfileV2, @import("ethereum_vm_composition_graph_support.zig"));
pub const Result = shared.Result;
pub const record = Bound.record;
pub const recordWithFixedProgram = Bound.recordWithFixedProgram;
