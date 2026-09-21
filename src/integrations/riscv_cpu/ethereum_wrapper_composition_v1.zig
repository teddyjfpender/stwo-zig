//! Ethereum wrapper composition admission. All local quotient domains share
//! one split depth before composition; q1 contributions are polynomially
//! extended to q2, while q2 contributions retain their original evaluations.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

pub const VERSION: u16 = 1;
pub const LOG_SPLIT: u8 = 2;

fn geometry(degree: u32) !core.air.components.CompositionGeometryOverrideV1 {
    if (degree < 2) return error.InvalidEthereumCompositionDegree;
    const local_split = @max(@as(u32, 1), std.math.log2_int_ceil(u32, degree - 1));
    if (local_split > LOG_SPLIT) return error.InvalidEthereumCompositionDegree;
    return .{
        .max_constraint_log_degree_bound_delta = @intCast(LOG_SPLIT - local_split),
        .composition_log_split = LOG_SPLIT,
    };
}

pub fn admitProver(handle: prover.air.component_prover.ComponentProver, trace_log: u32, degree: u32) !prover.air.component_prover.ComponentProver {
    const selected = try geometry(degree);
    const expected = try std.math.add(u32, trace_log, LOG_SPLIT - selected.max_constraint_log_degree_bound_delta);
    if (handle.composition_geometry_override_v1 != null or handle.maxConstraintLogDegreeBound() != expected)
        return error.InvalidEthereumCompositionGeometry;
    return handle.withCompositionGeometryOverrideV1(selected);
}

pub fn admitVerifier(handle: core.air.components.Component, trace_log: u32, degree: u32) !core.air.components.Component {
    const selected = try geometry(degree);
    const expected = try std.math.add(u32, trace_log, LOG_SPLIT - selected.max_constraint_log_degree_bound_delta);
    if (handle.composition_geometry_override_v1 != null or handle.maxConstraintLogDegreeBound() != expected)
        return error.InvalidEthereumCompositionGeometry;
    return handle.withCompositionGeometryOverrideV1(selected);
}

pub fn admitGate(manifest: anytype, gate: anytype) !void {
    try manifest.validate();
    if (gate.sealed or gate.count != manifest.roster_count or !std.mem.eql(u8, &gate.manifest_seal, &manifest.seal))
        return error.InvalidEthereumCompositionGeometry;
    for (manifest.roster_rows[0..manifest.roster_count], 0..) |row, index| {
        const placement = manifest.placements[row].?;
        if (gate.roster_rows[index] != row) return error.InvalidEthereumCompositionGeometry;
        gate.prover_components[index] = try admitProver(gate.prover_components[index], placement.geometry.log_size, placement.geometry.protocol_constraint_degree);
        gate.verifier_components[index] = try admitVerifier(gate.verifier_components[index], placement.geometry.log_size, placement.geometry.protocol_constraint_degree);
    }
}

test "Ethereum wrapper composition admission selects only reviewed quotient domains" {
    try std.testing.expectEqual(@as(u8, 1), (try geometry(3)).max_constraint_log_degree_bound_delta);
    try std.testing.expectEqual(@as(u8, 0), (try geometry(4)).max_constraint_log_degree_bound_delta);
    try std.testing.expectEqual(@as(u8, LOG_SPLIT), (try geometry(5)).composition_log_split);
    try std.testing.expectError(error.InvalidEthereumCompositionDegree, geometry(1));
    try std.testing.expectError(error.InvalidEthereumCompositionDegree, geometry(6));
}
