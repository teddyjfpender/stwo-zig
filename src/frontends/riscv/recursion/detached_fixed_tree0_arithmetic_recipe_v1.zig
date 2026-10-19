//! Proof-free reconstruction of SegmentV2 shared arithmetic fixed rows.
//! Only admitted key geometry and the canonical verifier programs enter here.
const std = @import("std");
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const layout_mod = @import("segment_statement_v2_transcript_layout.zig");
const native_sum = @import("segment_public_native_sum_authority_v2.zig");
const vm_graph = @import("vm_air_composition_key_graph_v2.zig");
const vm_circuit = @import("vm_air_composition_circuit.zig");
const native_geometry = @import("detached_native_column_geometry_v1.zig");
const pcs_circuit = @import("air/pcs_deep_circuit.zig");
const pcs_ids = @import("detached_pcs_circuit_ids_v1.zig");
const fri_circuit = @import("air/fri_verifier_circuit.zig");
const fri_ids = @import("detached_fri_circuit_ids_v1.zig");
const segment = @import("segment_profile.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const multiply_air = @import("air/qm31_mul_full.zig");
const multiply_witness = @import("air/qm31_mul_full_witness.zig");
const inverse_air = @import("air/qm31_inv.zig");
const inverse_witness = @import("air/qm31_inv_witness.zig");
const linear_air = @import("air/linear_ops.zig");
const linear_witness = @import("air/linear_ops_witness.zig");

/// The plan owns its row vectors. Temporary graph owners are destroyed before
/// return, so no verifier receives a borrowed graph or captured proof value.
pub fn planFromKey(allocator: std.mem.Allocator, key: *const KeyV1) !lowering.Plan {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedArithmeticProfile;
    const topology = key.native_sum_topology orelse return error.MissingPublicNativeSumTopology;
    const retained = try layout_mod.Layout.init(key.retained_section_counts);

    var vm = try vm_graph.buildFromDescriptors(
        allocator,
        key.native_descriptors,
        key.profile.nativePcsConfig(),
    );
    defer vm.deinit();
    var public_authored = try native_sum.buildNativeGraphFromTopology(
        allocator,
        &retained,
        topology,
    );
    defer public_authored.circuit.deinit();
    var public_graph = try native_sum.NativeOwnedGraph.init(
        allocator,
        &public_authored.circuit,
    );
    defer public_graph.deinit();

    var geometry = try native_geometry.init(
        allocator,
        key.native_descriptors,
        key.profile.nativePcsConfig().fri_config.log_blowup_factor,
    );
    defer geometry.deinit();
    const pcs_profile = try geometry.pcsProfile(
        std.math.cast(u32, key.profile.nativePcsConfig().fri_config.n_queries) orelse
            return error.InvalidFixedArithmeticProfile,
    );
    var pcs = try pcs_circuit.Prepared.init(allocator, pcs_profile);
    defer pcs.deinit();
    var fri = try fri_circuit.build(allocator, segment.circuitProfile());
    defer fri.deinit();

    const vm_lane = vm.lane();
    const lanes = [_]lowering.Lane{
        .{
            .circuit_id = vm_circuit.CIRCUIT_ID,
            .active_in = .segment,
            .circuit_identity = vm_lane.graph.identity_digest,
            .graph = vm_lane.graph,
        },
        .{
            .circuit_id = native_sum.CIRCUIT_ID,
            .active_in = .segment,
            .circuit_identity = public_graph.graph.identity_digest,
            .graph = public_graph.graph,
        },
        .{
            .circuit_id = pcs_ids.SEGMENT,
            .active_in = .segment,
            .circuit_identity = pcs.view().identity_digest,
            .graph = pcs.graph(),
        },
        .{
            .circuit_id = fri_ids.SEGMENT,
            .active_in = .segment,
            .circuit_identity = fri.identity_digest,
            .graph = fri.graph(),
        },
        .{
            .circuit_id = 2, // VM binary capacity anchor, inactive for a leaf.
            .active_in = .binary,
            .circuit_identity = vm_lane.graph.identity_digest,
            .graph = vm_lane.graph,
        },
    };
    return lowering.Plan.init(allocator, try lowering.Reference.seal(&lanes));
}

pub fn validateAgainstProduction(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    production: *const lowering.Plan,
) !void {
    var rebuilt = try planFromKey(allocator, key);
    defer rebuilt.deinit();
    if (!std.meta.eql(rebuilt.mode_counts, production.mode_counts) or
        rebuilt.multiply_rows.len != production.multiply_rows.len or
        rebuilt.inverse_rows.len != production.inverse_rows.len or
        rebuilt.linear_rows.len != production.linear_rows.len or
        rebuilt.public_terms.len != production.public_terms.len)
        return error.FixedArithmeticRowsMismatch;
    for (rebuilt.multiply_rows, production.multiply_rows) |left, right|
        if (!std.meta.eql(left, right)) return error.FixedArithmeticRowsMismatch;
    for (rebuilt.inverse_rows, production.inverse_rows) |left, right|
        if (!std.meta.eql(left, right)) return error.FixedArithmeticRowsMismatch;
    for (rebuilt.linear_rows, production.linear_rows) |left, right|
        if (!std.meta.eql(left, right)) return error.FixedArithmeticRowsMismatch;
    for (rebuilt.public_terms, production.public_terms) |left, right|
        if (!std.meta.eql(left, right)) return error.FixedArithmeticRowsMismatch;
}

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    multiply_columns: *[multiply_witness.PREPROCESSED_COLUMN_COUNT][]M31,
    inverse_columns: *[inverse_witness.PREPROCESSED_COLUMN_COUNT][]M31,
    linear_columns: *[linear_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var plan = try planFromKey(allocator, key);
    defer plan.deinit();
    const multiply_log = try checkedLog(key, 30, multiply_columns);
    const inverse_log = try checkedLog(key, 31, inverse_columns);
    const linear_log = try checkedLog(key, 32, linear_columns);

    var multiply_definition = try multiply_air.build(allocator, .generated);
    defer multiply_definition.deinit();
    const multiply_binding = try multiply_witness.Binding.canonical(&multiply_definition);
    const multiply_executor = try multiply_witness.Executor.init(&multiply_definition, &multiply_binding);
    try multiply_executor.generatePreprocessedInto(multiply_columns, plan.multiply_rows, multiply_log);

    var inverse_definition = try inverse_air.build(allocator, .generated);
    defer inverse_definition.deinit();
    const inverse_binding = try inverse_witness.Binding.canonical(&inverse_definition);
    const inverse_executor = try inverse_witness.Executor.init(&inverse_definition, &inverse_binding);
    try inverse_executor.generatePreprocessedInto(inverse_columns, plan.inverse_rows, inverse_log);

    var linear_definition = try linear_air.build(allocator, .generated);
    defer linear_definition.deinit();
    const linear_binding = try linear_witness.Binding.canonical(&linear_definition);
    const linear_executor = try linear_witness.Executor.init(&linear_definition, &linear_binding);
    try linear_executor.generatePreprocessedInto(linear_columns, plan.linear_rows, linear_log);
}

fn checkedLog(key: *const KeyV1, row: usize, columns: anytype) !u32 {
    const placement = key.manifest.placements[row] orelse return error.InvalidFixedArithmeticGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedArithmeticGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedArithmeticGeometry;
    return placement.geometry.log_size;
}
