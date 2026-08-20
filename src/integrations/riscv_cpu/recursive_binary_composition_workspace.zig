const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const outer = @import("recursive_fri_outer.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const binary = recursion.binary_fri_outer_source;
const composition_circuit = recursion.recursion_air_composition_circuit;
const composition_abi = recursion.air.composition_circuit;
const POSEIDON_INTERACTION_COLUMN_COUNT: usize =
    composition_abi.POSEIDON2_INTERACTION_COLUMN_COUNT;

pub fn validateCaptureGeometry(
    verified: *const outer.VerifiedOuterProofV1,
    trusted: binary.TrustedCompositionProfileV1,
    circuit: *const composition_circuit.Circuit,
) !void {
    if (circuit.input_profile.sampled_value_count !=
        verified.capture.sampled_values.len)
    {
        return error.CaptureIdentityMismatch;
    }
    var flattened_column: usize = 0;
    const start: usize = @intCast(trusted.poseidon2_sample_layout_start);
    const end = std.math.add(
        usize,
        start,
        POSEIDON_INTERACTION_COLUMN_COUNT,
    ) catch return error.PoseidonCaptureGeometryMismatch;
    var matched: usize = 0;
    for (verified.capture.sampled_points) |tree| {
        for (tree) |points| {
            if (flattened_column >= start and flattened_column < end) {
                if (points.len != 2)
                    return error.PoseidonCaptureGeometryMismatch;
                matched += 1;
            }
            flattened_column += 1;
        }
    }
    if (matched != POSEIDON_INTERACTION_COLUMN_COUNT)
        return error.PoseidonCaptureGeometryMismatch;
}

pub fn validateWorkspace(
    destination: *binary.VerifiedChildCompositionAuthority,
    input_scratch: []QM31,
    node_scratch: []QM31,
    verified: *const outer.VerifiedOuterProofV1,
    circuit: *const composition_circuit.Circuit,
) !void {
    if (input_scratch.len != circuit.recorded.input_count or
        node_scratch.len != circuit.recorded.nodes.len)
    {
        return error.InvalidWorkspaceShape;
    }
    const destination_bytes = std.mem.asBytes(destination);
    const input_bytes = std.mem.sliceAsBytes(input_scratch);
    const node_bytes = std.mem.sliceAsBytes(node_scratch);
    const verified_bytes = std.mem.asBytes(verified);
    const circuit_bytes = std.mem.asBytes(circuit);
    const graph_node_bytes = std.mem.sliceAsBytes(circuit.recorded.nodes);
    const graph_output_bytes = std.mem.sliceAsBytes(circuit.recorded.outputs);
    const binding_bytes = std.mem.sliceAsBytes(circuit.bindings);
    const mutable = [_][]const u8{ destination_bytes, input_bytes, node_bytes };
    if (overlap(input_bytes, node_bytes)) return error.AliasedWorkspace;
    for (mutable) |target| {
        if (overlap(target, verified_bytes) or
            overlap(target, circuit_bytes) or
            captureStorageOverlaps(target, &verified.capture) or
            overlap(target, graph_node_bytes) or
            overlap(target, graph_output_bytes) or
            overlap(target, binding_bytes))
        {
            return error.AliasedWorkspace;
        }
    }
    if (overlap(destination_bytes, input_bytes) or
        overlap(destination_bytes, node_bytes))
    {
        return error.AliasedWorkspace;
    }
}

fn captureStorageOverlaps(
    target: []const u8,
    capture: *const outer.OuterProofCapture,
) bool {
    if (overlap(target, std.mem.sliceAsBytes(capture.queries.raw)) or
        overlap(target, std.mem.sliceAsBytes(capture.queries.unique)) or
        overlap(target, std.mem.sliceAsBytes(capture.commitments)) or
        overlap(target, std.mem.sliceAsBytes(capture.column_log_sizes)) or
        overlap(target, std.mem.sliceAsBytes(capture.sampled_points)) or
        overlap(target, std.mem.sliceAsBytes(capture.sampled_values)) or
        overlap(target, std.mem.sliceAsBytes(capture.queried_values)) or
        overlap(target, std.mem.sliceAsBytes(capture.deep_answers)) or
        overlap(target, std.mem.sliceAsBytes(capture.trace_paths)) or
        overlap(target, std.mem.sliceAsBytes(capture.fri.layers)) or
        overlap(target, std.mem.sliceAsBytes(capture.last_layer_coefficients)))
    {
        return true;
    }
    for (capture.column_log_sizes) |logs|
        if (overlap(target, std.mem.sliceAsBytes(logs))) return true;
    for (capture.sampled_points) |columns| {
        if (overlap(target, std.mem.sliceAsBytes(columns))) return true;
        for (columns) |points|
            if (overlap(target, std.mem.sliceAsBytes(points))) return true;
    }
    for (capture.trace_paths) |path| {
        if (overlap(target, std.mem.sliceAsBytes(path.positions)) or
            overlap(target, std.mem.sliceAsBytes(path.siblings))) return true;
    }
    for (capture.fri.layers) |layer| {
        if (overlap(target, std.mem.sliceAsBytes(layer.positions)) or
            overlap(target, std.mem.sliceAsBytes(layer.values)) or
            overlap(target, std.mem.sliceAsBytes(layer.siblings))) return true;
    }
    return false;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}
