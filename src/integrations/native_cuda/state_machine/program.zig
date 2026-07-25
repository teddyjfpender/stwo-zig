//! Geometry-only proof-program emission for the Native state-machine AIR.

const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const cuda_plan = @import(
    "../../../backends/cuda/runtime/execution_plan.zig",
);
const geometry_mod = @import("geometry.zig");
const identities = @import("identities.zig");
const layout_mod = @import("layout.zig");
const topology = @import("topology.zig");
const ir = @import("stwo_backend_contracts").proof_program;

const node_count = 8;

pub const kernel_pack_identity: ir.Digest = digestKernelPack();
pub const scheduler_version = cuda_plan.schedule_version;

fn digestKernelPack() ir.Digest {
    @setEvalBranchQuota(10_000);
    return ir.identityDigest("stwo-zig/native-cuda/state_machine/aot-pack/v1");
}

pub fn emitGeometry(
    allocator: std.mem.Allocator,
    geometry: geometry_mod.Geometry,
) !ir.ProofProgram {
    const buffer = [_]ir.Buffer{.{
        .id = 0,
        .words = geometry.trace_elements,
        .alignment_words = 1,
        .live_from = .ingress,
        .live_through = .decommit,
        .storage = .request_local,
        .immutable = true,
    }};
    return emitWithBuffers(allocator, geometry, &buffer);
}

pub fn emitPlan(
    allocator: std.mem.Allocator,
    geometry: geometry_mod.Geometry,
    logical: layout_mod.Layout,
    quotient: topology.Quotient,
    fri: topology.Fri,
    requirements: []const arena.Requirement,
) !ir.ProofProgram {
    if (!std.meta.eql(logical.geometry, geometry) or
        quotient.prepared_terms.len !=
            geometry_mod.sampled_mask_points or
        fri.layers.len != geometry.fri_tree_count)
    {
        return error.InvalidKernelDescriptor;
    }
    const buffers = try allocator.alloc(ir.Buffer, requirements.len);
    defer allocator.free(buffers);
    for (requirements, 0..) |requirement, index| {
        buffers[index] = .{
            .id = requirement.id,
            .words = requirement.words,
            .alignment_words = @intCast(requirement.alignment_words),
            .live_from = stage(requirement.live_from),
            .live_through = stage(requirement.live_through),
            .storage = .request_local,
            .immutable = requirement.live_from == .ingress and
                requirement.live_through != .proof_assembly,
        };
    }
    return emitWithBuffers(allocator, geometry, buffers);
}

pub fn targetFor(session: anytype) !cuda_plan.CompileOptions {
    const major = std.math.mul(u32, session.device.sm_major, 10) catch
        return error.InvalidDeviceArchitecture;
    const sm = std.math.add(
        u32,
        major,
        session.device.sm_minor,
    ) catch return error.InvalidDeviceArchitecture;
    return .{
        .sm = sm,
        .device_uuid = session.platform.uuid,
        .driver_version = session.platform.driver_version,
        .runtime_version = session.platform.runtime_version,
        .toolkit_version = session.platform.toolkit_version,
        .runtime_build_identity = session.build_identity,
        .host_toolchain_identity = session.build_identity,
        .kernel_pack_identity = kernel_pack_identity,
        .lane_streams = if (session.context.lane_count > 1)
            @intCast(session.context.lane_count - 1)
        else
            0,
        .enable_graphs = true,
        .schedule_schema_version = scheduler_version,
    };
}

fn emitWithBuffers(
    allocator: std.mem.Allocator,
    geometry: geometry_mod.Geometry,
    buffers: []const ir.Buffer,
) !ir.ProofProgram {
    const columns = traceColumns(geometry);
    const constraints = [_]ir.ConstraintProgram{
        .{
            .id = 0,
            .component = 0,
            .expression = identities.constraint_expression,
            .constraint_count = 1,
            .max_degree_log = 2,
        },
        .{
            .id = 1,
            .component = 1,
            .expression = identities.constraint_expression,
            .constraint_count = 1,
            .max_degree_log = 2,
        },
    };
    const commitments = commitmentTrees(geometry);
    const barriers = try transcriptBarriers(allocator, geometry);
    defer allocator.free(barriers);
    const fri_layers = try friLayers(allocator, geometry);
    defer allocator.free(fri_layers);
    const nodes = try executionNodes(geometry);
    const dependencies = [_]u32{ 0, 1, 2, 3, 4, 5, 6 };

    return ir.ProofProgram.init(allocator, .{
        .identity = .{
            .frontend = .native,
            .air = identities.air,
            .statement = identities.statement(geometry.statement),
            .protocol = identities.protocol(geometry.protocol),
        },
        .native_air_contract = nativeContract(geometry),
        .trace_columns = &columns,
        .constraints = &constraints,
        .commitments = &commitments,
        .transcript = barriers,
        .quotient = .{
            .term_count = geometry_mod.sampled_mask_points,
            .group_count = 1,
            .evaluation_log_rows = geometry.commitment_log_rows,
            .composition_degree_log = 2,
        },
        .fri_layers = fri_layers,
        .buffers = buffers,
        .nodes = &nodes,
        .dependency_ids = &dependencies,
    });
}

fn stage(value: @import(
    "../../../backends/cuda/runtime/telemetry.zig",
).Stage) ir.Stage {
    return @enumFromInt(@intFromEnum(value));
}

fn nativeContract(geometry: geometry_mod.Geometry) ir.NativeAirContract {
    return .{
        .geometry = .{
            .component = 0,
            .component_count = 2,
            .log_rows = geometry.statement.log_n_rows,
            .preprocessed_columns = geometry_mod.preprocessed_columns,
            .main_columns = geometry_mod.main_columns,
            .interaction_columns = geometry_mod.interaction_columns,
            .mixed_height_element_count = geometry.committed_cells,
        },
        .ingress = .{
            .recipe_identity = identities.ingress_recipe,
            .layout_abi_identity = identities.ingress_layout,
            .element_count = geometry.trace_elements,
        },
        .statement = .{
            .transcript_recipe_identity = identities.transcript_recipe,
            .public_input_abi_identity = identities.public_input_abi,
            .public_input_words = 4,
        },
        .sampling = .{
            .recipe_identity = identities.sampling_recipe,
            .mask_layout_identity = identities.mask_layout,
            .mask_point_count = geometry_mod.sampled_mask_points,
        },
        .constraint_parameters = .{
            .identity = identities.constraint_parameter_abi,
            .statement_words = geometry_mod.statement_word_count,
            .challenge_words = 4,
            .parameter_words = geometry_mod.statement_word_count + 4,
        },
    };
}

fn traceColumns(geometry: geometry_mod.Geometry) [
    geometry_mod.preprocessed_columns +
        geometry_mod.main_columns +
        geometry_mod.interaction_columns +
        geometry_mod.composition_columns
]ir.TraceColumn {
    const count = geometry_mod.preprocessed_columns +
        geometry_mod.main_columns +
        geometry_mod.interaction_columns +
        geometry_mod.composition_columns;
    var columns: [count]ir.TraceColumn = undefined;
    for (&columns, 0..) |*column, index| {
        const ordinal: u32 = @intCast(index);
        const main_end = geometry_mod.main_columns;
        const interaction_end =
            main_end + geometry_mod.interaction_columns;
        const role: ir.ColumnRole = if (index < main_end)
            .main
        else if (index < interaction_end)
            .interaction
        else
            .composition;
        const local_index = if (index < main_end)
            index
        else if (index < interaction_end)
            index - main_end
        else
            index - interaction_end;
        const component: u32 = switch (role) {
            .main => @intFromBool(local_index >= 2),
            .interaction => @intFromBool(local_index >= 4),
            .composition => 0,
            else => unreachable,
        };
        column.* = .{
            .id = ordinal,
            .component = component,
            .ordinal = ordinal,
            .log_rows = geometry.statement.log_n_rows -
                @intFromBool(component == 1),
            .role = role,
        };
    }
    return columns;
}

fn commitmentTrees(
    geometry: geometry_mod.Geometry,
) [4]ir.CommitmentTree {
    const preprocessed_end = geometry_mod.preprocessed_columns;
    const main_end = preprocessed_end + geometry_mod.main_columns;
    const interaction_end = main_end + geometry_mod.interaction_columns;
    return .{
        tree(0, .preprocessed, 0, geometry_mod.preprocessed_columns, geometry, false),
        tree(1, .main, preprocessed_end, geometry_mod.main_columns, geometry, true),
        tree(
            2,
            .interaction,
            main_end,
            geometry_mod.interaction_columns,
            geometry,
            true,
        ),
        tree(
            3,
            .composition,
            interaction_end,
            geometry_mod.composition_columns,
            geometry,
            true,
        ),
    };
}

fn tree(
    id: u32,
    role: ir.CommitmentRole,
    first_column: u32,
    column_count: u32,
    geometry: geometry_mod.Geometry,
    retain_openings: bool,
) ir.CommitmentTree {
    return .{
        .id = id,
        .role = role,
        .first_column = first_column,
        .column_count = column_count,
        .evaluation_log_rows = geometry.commitment_log_rows,
        .log_rows_per_leaf = geometry.commitment_log_rows,
        .retain_openings = retain_openings,
    };
}

fn transcriptBarriers(
    allocator: std.mem.Allocator,
    geometry: geometry_mod.Geometry,
) ![]ir.TranscriptBarrier {
    const count = try std.math.add(
        u32,
        12,
        try std.math.mul(u32, geometry.fri_tree_count, 2),
    );
    const barriers = try allocator.alloc(ir.TranscriptBarrier, count);
    errdefer allocator.free(barriers);
    var previous_node: u32 = 0;
    var phase: u32 = 0;
    for (barriers, 0..) |*barrier, index| {
        const operation: u32 = @intCast(index);
        const node = transcriptNode(operation, geometry.fri_tree_count);
        if (index != 0 and node == previous_node) {
            phase += 1;
        } else {
            phase = 0;
        }
        barrier.* = .{
            .ordinal = operation,
            .node = node,
            .phase = phase,
            .kind = transcriptKind(operation, geometry.fri_tree_count),
            .value_count = transcriptValueCount(operation, geometry),
        };
        previous_node = node;
    }
    return barriers;
}

fn transcriptNode(operation: u32, fri_tree_count: u32) u32 {
    if (operation == 0) return 0;
    if (operation <= 3) return 1;
    if (operation <= 5) return 2;
    if (operation <= 8) return 3;
    const after_fri = 9 + 2 * fri_tree_count;
    if (operation < after_fri) return 5;
    return switch (operation - after_fri) {
        0 => 5,
        1 => 6,
        2 => 7,
        else => unreachable,
    };
}

fn transcriptKind(operation: u32, fri_tree_count: u32) ir.TranscriptKind {
    if (operation <= 3 or operation == 5 or operation == 7) return .mix;
    if (operation == 4 or operation == 6 or operation == 8) return .challenge;
    const fri_end = 9 + 2 * fri_tree_count;
    if (operation < fri_end) {
        return if ((operation - 9) % 2 == 0) .mix else .challenge;
    }
    return switch (operation - fri_end) {
        0 => .mix,
        1 => .pow,
        2 => .queries,
        else => unreachable,
    };
}

fn transcriptValueCount(
    operation: u32,
    geometry: geometry_mod.Geometry,
) u32 {
    if (operation == 3) return geometry_mod.statement_word_count;
    if (operation == 7) return geometry_mod.sampled_mask_points;
    if (operation == 11 + 2 * geometry.fri_tree_count)
        return @intCast(geometry.protocol.fri_config.n_queries);
    return 1;
}

fn friLayers(
    allocator: std.mem.Allocator,
    geometry: geometry_mod.Geometry,
) ![]ir.FriLayer {
    const layers = try allocator.alloc(ir.FriLayer, geometry.fri_tree_count);
    errdefer allocator.free(layers);
    for (layers, 0..) |*layer, index| {
        const fold: u32 = @intCast(index);
        layer.* = .{
            .tree_id = fold,
            .evaluation_log_rows = geometry.commitment_log_rows - fold,
            .fold_step = geometry.protocol.fri_config.fold_step,
            .cumulative_fold = fold,
            .log_rows_per_leaf = 0,
        };
    }
    return layers;
}

fn executionNodes(
    geometry: geometry_mod.Geometry,
) ![node_count]ir.Node {
    const trace_bytes = try bytes(geometry.trace_elements);
    const commitment_rows = try pow2(geometry.commitment_log_rows);
    const trace_commit_cells = try mul(
        geometry.traceColumnCount() + geometry_mod.composition_columns,
        commitment_rows,
    );
    const sampled_words = geometry_mod.sampled_mask_points * 4;
    const work = [_]ir.WorkEstimate{
        estimate(0, trace_bytes, geometry.trace_elements, 0, 1),
        estimate(
            try bytes(trace_commit_cells),
            try bytes(trace_commit_cells),
            trace_commit_cells,
            trace_commit_cells,
            1,
        ),
        estimate(
            trace_bytes,
            try bytes(try mul(geometry.trace_rows, 4)),
            geometry.trace_rows,
            0,
            1,
        ),
        estimate(
            try bytes(trace_commit_cells),
            try bytes(sampled_words),
            try mul(geometry_mod.sampled_mask_points, geometry.trace_rows),
            0,
            1,
        ),
        estimate(
            try bytes(trace_commit_cells),
            try bytes(try mul(commitment_rows, 4)),
            try mul(geometry_mod.sampled_mask_points, commitment_rows),
            0,
            1,
        ),
        estimate(
            try bytes(try mul(commitment_rows, 4)),
            try bytes(try mul(commitment_rows, 4)),
            try mul(commitment_rows, 4),
            commitment_rows,
            geometry.fri_tree_count,
        ),
        estimate(
            32,
            8,
            0,
            @as(u64, 1) << @intCast(geometry.protocol.pow_bits),
            1,
        ),
        estimate(
            try bytes(trace_commit_cells),
            0,
            0,
            try mul(
                geometry.fri_tree_count +
                    geometry.decommitted_trace_tree_count,
                geometry.protocol.fri_config.n_queries,
            ),
            1,
        ),
    };
    const kinds = [_]ir.OperationKind{
        .trace_generation,
        .commitment,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        .pow,
        .decommit,
    };
    const stages = [_]ir.Stage{
        .trace_generation,
        .trace_commit,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        .pow,
        .decommit,
    };
    const parallelism = [_]ir.Parallelism{
        .component,
        .merkle_subtree,
        .component,
        .coordination,
        .quotient_chunk,
        .fri_round,
        .coordination,
        .merkle_subtree,
    };
    var nodes: [node_count]ir.Node = undefined;
    for (&nodes, 0..) |*node, index| {
        node.* = .{
            .id = @intCast(index),
            .kind = kinds[index],
            .stage = stages[index],
            .dependencies = if (index == 0)
                .{ .first = 0, .count = 0 }
            else
                .{ .first = @intCast(index - 1), .count = 1 },
            .parallelism = parallelism[index],
            .graph_candidate = index != 6,
            .work = work[index],
        };
    }
    return nodes;
}

fn estimate(
    bytes_read: u64,
    bytes_written: u64,
    field_operations: u64,
    hash_compressions: u64,
    minimum_launches: u32,
) ir.WorkEstimate {
    return .{
        .bytes_read = bytes_read,
        .bytes_written = bytes_written,
        .field_operations = field_operations,
        .hash_compressions = hash_compressions,
        .minimum_launches = minimum_launches,
    };
}

fn bytes(words: anytype) !u64 {
    return mul(words, @sizeOf(u32));
}

fn mul(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.GeometryOverflow;
    return std.math.mul(u64, lhs, rhs) catch error.GeometryOverflow;
}

fn pow2(log_size: u32) !u64 {
    if (log_size >= 63) return error.GeometryOverflow;
    return @as(u64, 1) << @intCast(log_size);
}

test "state-machine proof program matches the AIR topology" {
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(
        .{
            .log_n_rows = 7,
            .initial_state = .{
                @import("stwo_core").fields.m31.M31.fromU64(9),
                @import("stwo_core").fields.m31.M31.fromU64(3),
            },
        },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    var emitted = try emitGeometry(allocator, geometry);
    defer emitted.deinit(allocator);
    try emitted.validate();
    const contract = emitted.native_air_contract.?;
    try std.testing.expectEqual(
        @as(u32, 1),
        contract.geometry.preprocessed_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 2),
        contract.geometry.main_columns,
    );
    try std.testing.expectEqual(@as(usize, 11), emitted.trace_columns.len);
    try std.testing.expectEqual(@as(usize, 3), emitted.commitments.len);
    try std.testing.expectEqual(@as(u32, 1), emitted.commitments[0].column_count);
    try std.testing.expectEqual(@as(u32, 2), emitted.commitments[1].column_count);
    try std.testing.expectEqual(@as(u32, 8), emitted.commitments[2].column_count);
    try std.testing.expectEqual(@as(u32, 11), emitted.quotient.term_count);
    try std.testing.expectEqual(@as(u32, 14), emitted.transcript[3].value_count);
}

test "state-machine program sample topology matches a CPU proof" {
    const allocator = std.testing.allocator;
    const cpu_state_machine = @import("../../../examples/state_machine.zig");
    const pcs = @import("stwo_core").pcs;
    const M31 = @import("stwo_core").fields.m31.M31;
    const protocol = pcs.PcsConfig.default();
    const request = cpu_state_machine.Request{
        .log_n_rows = 5,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    };
    const geometry = try geometry_mod.admit(request, protocol);
    var emitted = try emitGeometry(allocator, geometry);
    defer emitted.deinit(allocator);
    var output = try cpu_state_machine.prove(
        allocator,
        protocol,
        request.log_n_rows,
        request.initial_state,
    );
    defer output.proof.deinit(allocator);

    const proof = output.proof.commitment_scheme_proof;
    const widths = [_]usize{ 1, 2, 8 };
    var samples: usize = 0;
    for (proof.sampled_values.items, widths) |sampled_tree, width| {
        try std.testing.expectEqual(width, sampled_tree.len);
        for (sampled_tree) |column| {
            try std.testing.expectEqual(@as(usize, 1), column.len);
            samples += column.len;
        }
    }
    try std.testing.expectEqual(emitted.quotient.term_count, samples);
}

test "state-machine request changes semantic identity without topology drift" {
    const allocator = std.testing.allocator;
    const pcs = @import("stwo_core").pcs.PcsConfig.default();
    const M31 = @import("stwo_core").fields.m31.M31;
    const first_geometry = try geometry_mod.admit(.{
        .log_n_rows = 7,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    }, pcs);
    const second_geometry = try geometry_mod.admit(.{
        .log_n_rows = 7,
        .initial_state = .{ M31.fromU64(10), M31.fromU64(3) },
    }, pcs);
    var first = try emitGeometry(allocator, first_geometry);
    defer first.deinit(allocator);
    var second = try emitGeometry(allocator, second_geometry);
    defer second.deinit(allocator);
    try std.testing.expectEqual(
        first.trace_columns.len,
        second.trace_columns.len,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &first.semantic_digest,
        &second.semantic_digest,
    ));
}
