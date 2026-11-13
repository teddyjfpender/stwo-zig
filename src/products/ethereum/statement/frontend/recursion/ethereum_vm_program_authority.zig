//! Complete program equality used by retained compilation authority.
const std = @import("std");
const ProgramV4 = @import("incremental_ethereum_vm_composition_program.zig").ProgramV4;

pub fn programsEqual(left: *const ProgramV4, right: *const ProgramV4) bool {
    if (left.format_version != right.format_version or
        left.schema_version != right.schema_version or
        !std.meta.eql(left.input_profile, right.input_profile) or
        !std.meta.eql(left.claim_routing, right.claim_routing) or
        !std.meta.eql(left.base_profile_sha256, right.base_profile_sha256) or
        !std.meta.eql(left.base_geometry_sha256, right.base_geometry_sha256) or
        !std.meta.eql(left.extension_geometry_sha256, right.extension_geometry_sha256) or
        !std.meta.eql(left.selected_lookup_compiler_sha256, right.selected_lookup_compiler_sha256) or
        !std.meta.eql(left.bridge_geometry_sha256, right.bridge_geometry_sha256) or
        left.bridge_entry_root != right.bridge_entry_root or
        left.bridge_exit_root != right.bridge_exit_root or
        left.maximum_log_degree_bound != right.maximum_log_degree_bound or
        !std.meta.eql(left.protocol_profile_sha256, right.protocol_profile_sha256) or
        !std.meta.eql(left.graph_sha256, right.graph_sha256) or
        !std.meta.eql(left.reference_sha256, right.reference_sha256) or
        !std.meta.eql(left.schedule_sha256, right.schedule_sha256) or
        !std.meta.eql(left.air_program_identity, right.air_program_identity) or
        !std.meta.eql(left.verifier_program_authority, right.verifier_program_authority) or
        left.nodes.len != right.nodes.len or left.outputs.len != right.outputs.len or
        left.bindings.len != right.bindings.len)
    {
        return false;
    }
    for (left.nodes, right.nodes) |a, b| if (!std.meta.eql(a, b)) return false;
    for (left.outputs, right.outputs) |a, b| if (a != b) return false;
    for (left.bindings, right.bindings) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}
