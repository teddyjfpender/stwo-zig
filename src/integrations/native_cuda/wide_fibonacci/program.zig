//! Backend-neutral proof-program emission for Native wide Fibonacci.

const std = @import("std");
const backend = @import("stwo_backend_contracts");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const cuda_plan = @import(
    "../../../backends/cuda/runtime/execution_plan.zig",
);
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const layout_mod = @import("layout.zig");
const request = @import("request.zig");
const topology = @import("topology.zig");
const transcript = @import("transcript_schedule.zig");

const ir = backend.proof_program;

pub const kernel_pack_identity: ir.Digest = blk: {
    var digest: ir.Digest = undefined;
    _ = std.fmt.hexToBytes(
        &digest,
        "dc9a6c0b4e08f56e567cde94247b7f77661f93f3bb9af6b9e3570fb261071538",
    ) catch unreachable;
    break :blk digest;
};
pub const scheduler_version = cuda_plan.schedule_version;

pub fn emit(
    allocator: std.mem.Allocator,
    geometry: request.Geometry,
    logical: layout_mod.Layout,
    quotient: topology.Quotient,
    fri: topology.Fri,
    requirements: []const arena.Requirement,
) !ir.ProofProgram {
    const trace_columns = try allocator.alloc(
        ir.TraceColumn,
        geometry.sampled_value_count,
    );
    defer allocator.free(trace_columns);
    for (trace_columns, 0..) |*column, index| {
        const main = index < geometry.main_columns;
        column.* = .{
            .id = @intCast(index),
            .component = 0,
            .ordinal = @intCast(index),
            .log_rows = geometry.statement.log_n_rows,
            .role = if (main) .main else .composition,
        };
    }

    const constraint_programs = [_]ir.ConstraintProgram{.{
        .id = 0,
        .component = 0,
        .expression = ir.identityDigest(
            "wide-fibonacci:next=left^2+right^2:m31:qm31-composition:v1",
        ),
        .constraint_count = @intCast(geometry.main_columns - 2),
        .max_degree_log = 2,
    }};
    const commitment_log = geometry.queryLogSize();
    const commitments = [_]ir.CommitmentTree{
        .{
            .id = 0,
            .role = .preprocessed,
            .first_column = 0,
            .column_count = 0,
            .evaluation_log_rows = commitment_log,
            .log_rows_per_leaf = commitment_log,
            .retain_openings = false,
        },
        .{
            .id = 1,
            .role = .main,
            .first_column = 0,
            .column_count = @intCast(geometry.main_columns),
            .evaluation_log_rows = commitment_log,
            .log_rows_per_leaf = commitment_log,
            .retain_openings = true,
        },
        .{
            .id = 2,
            .role = .composition,
            .first_column = @intCast(geometry.main_columns),
            .column_count = request.composition_column_count,
            .evaluation_log_rows = commitment_log,
            .log_rows_per_leaf = commitment_log,
            .retain_openings = true,
        },
    };

    const barriers = try emitTranscript(allocator, geometry);
    defer allocator.free(barriers);
    const fri_layers = try allocator.alloc(ir.FriLayer, fri.layers.len);
    defer allocator.free(fri_layers);
    for (fri.layers, 0..) |layer, index| {
        fri_layers[index] = .{
            .tree_id = @intCast(index),
            .evaluation_log_rows = layer.evaluation_log_size,
            .fold_step = layer.fold_step,
            .cumulative_fold = layer.cumulative_fold,
            .log_rows_per_leaf = layer.log_rows_per_leaf,
        };
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

    const dependencies = [_]u32{ 0, 1, 2, 3, 4, 5, 6 };
    const nodes = try executionNodes(geometry, quotient, logical);
    return ir.ProofProgram.init(allocator, .{
        .identity = .{
            .frontend = .native,
            .air = ir.identityDigest("stwo-zig/native/wide-fibonacci/air/v1"),
            .statement = statementIdentity(geometry),
            .protocol = protocolIdentity(geometry),
        },
        .trace_columns = trace_columns,
        .constraints = &constraint_programs,
        .commitments = &commitments,
        .transcript = barriers,
        .quotient = .{
            .term_count = @intCast(quotient.prepared_terms.len),
            .group_count = @intCast(quotient.group_log_sizes.len),
            .evaluation_log_rows = geometry.queryLogSize(),
            .composition_degree_log = 2,
        },
        .fri_layers = fri_layers,
        .buffers = buffers,
        .nodes = &nodes,
        .dependency_ids = &dependencies,
    });
}

pub fn targetFor(session: anytype) !cuda_plan.CompileOptions {
    const major = std.math.mul(u32, session.device.sm_major, 10) catch
        return error.InvalidDeviceArchitecture;
    const sm = std.math.add(u32, major, session.device.sm_minor) catch
        return error.InvalidDeviceArchitecture;
    // The native archive identity authenticates the compiler invocation,
    // source closure, AOT pack and target SM. It is intentionally included in
    // both runtime and toolchain fields until the runtime ABI exposes those
    // sub-digests separately.
    return .{
        .sm = sm,
        .runtime_build_identity = session.build_identity,
        .toolchain_identity = session.build_identity,
        .kernel_pack_identity = kernel_pack_identity,
        .lane_streams = if (session.context.lane_count > 1)
            @intCast(session.context.lane_count - 1)
        else
            0,
        .enable_graphs = false,
        .version = scheduler_version,
    };
}

fn emitTranscript(
    allocator: std.mem.Allocator,
    geometry: request.Geometry,
) ![]ir.TranscriptBarrier {
    const schedule = try transcript.Schedule.init(geometry);
    const barriers = try allocator.alloc(
        ir.TranscriptBarrier,
        schedule.operation_count,
    );
    errdefer allocator.free(barriers);
    var previous_node: u32 = 0;
    var phase: u32 = 0;
    for (barriers, 0..) |*barrier, index| {
        const operation = try schedule.operation(@intCast(index));
        const node = transcriptNode(operation);
        if (index != 0 and node == previous_node) {
            phase = try std.math.add(u32, phase, 1);
        } else {
            phase = 0;
        }
        barrier.* = .{
            .ordinal = @intCast(index),
            .node = node,
            .phase = phase,
            .kind = transcriptKind(operation),
            .value_count = transcriptValueCount(operation, geometry),
        };
        previous_node = node;
    }
    return barriers;
}

fn executionNodes(
    geometry: request.Geometry,
    quotient: topology.Quotient,
    logical: layout_mod.Layout,
) ![8]ir.Node {
    const trace_bytes = try bytes(geometry.trace_cells);
    const committed_cells = try mul(
        quotient.source_count,
        geometry.commitment_rows,
    );
    const committed_bytes = try bytes(committed_cells);
    const merkle_hashes = try mul(
        logical.quotient.source_column_count,
        geometry.commitment_rows - 1,
    );
    const quotient_terms = try mul(
        quotient.prepared_terms.len,
        quotient.output_rows,
    );
    const fri_cells = try sumFriCells(logical);
    const estimates = [_]ir.WorkEstimate{
        .{
            .bytes_read = 0,
            .bytes_written = trace_bytes,
            .field_operations = @intCast(geometry.trace_cells),
            .hash_compressions = 0,
            .minimum_launches = 1,
        },
        .{
            .bytes_read = committed_bytes,
            .bytes_written = committed_bytes,
            .field_operations = @intCast(committed_cells),
            .hash_compressions = @intCast(merkle_hashes),
            .minimum_launches = 1,
        },
        .{
            .bytes_read = trace_bytes,
            .bytes_written = try bytes(geometry.composition_rows),
            .field_operations = @intCast(try mul(
                geometry.trace_rows,
                geometry.main_columns - 2,
            )),
            .hash_compressions = @intCast(geometry.commitment_rows - 1),
            .minimum_launches = 1,
        },
        .{
            .bytes_read = committed_bytes,
            .bytes_written = try bytes(geometry.sampled_value_count * 4),
            .field_operations = @intCast(try mul(
                geometry.sampled_value_count,
                geometry.trace_rows,
            )),
            .hash_compressions = 0,
            .minimum_launches = 1,
        },
        .{
            .bytes_read = committed_bytes,
            .bytes_written = try bytes(geometry.composition_rows * 4),
            .field_operations = @intCast(quotient_terms),
            .hash_compressions = 0,
            .minimum_launches = 1,
        },
        .{
            .bytes_read = try bytes(fri_cells * 4),
            .bytes_written = try bytes(fri_cells * 4),
            .field_operations = @intCast(fri_cells),
            .hash_compressions = @intCast(fri_cells),
            .minimum_launches = @intCast(logical.fri_trees.len),
        },
        .{
            .bytes_read = 32,
            .bytes_written = 8,
            .field_operations = 0,
            .hash_compressions = 1 << geometry.protocol.pow_bits,
            .minimum_launches = 1,
        },
        .{
            .bytes_read = committed_bytes,
            .bytes_written = 0,
            .field_operations = 0,
            .hash_compressions = @intCast(
                geometry.decommit_tree_count *
                    geometry.protocol.n_queries,
            ),
            .minimum_launches = 1,
        },
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
    var nodes: [8]ir.Node = undefined;
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
            .work = estimates[index],
        };
    }
    return nodes;
}

fn transcriptNode(operation: transcript.Operation) u32 {
    return switch (operation) {
        .mix_pcs_config => 0,
        .mix_empty_preprocessed_root,
        .mix_main_root,
        .mix_statement,
        .draw_composition_alpha,
        => 1,
        .mix_composition_root, .draw_oods_point => 2,
        .mix_sampled_values, .draw_quotient_alpha => 3,
        .mix_fri_root, .draw_fri_alpha, .mix_last_layer => 5,
        .absorb_pow => 6,
        .draw_queries => 7,
    };
}

fn transcriptKind(operation: transcript.Operation) ir.TranscriptKind {
    return switch (operation) {
        .mix_pcs_config,
        .mix_empty_preprocessed_root,
        .mix_main_root,
        .mix_statement,
        .mix_composition_root,
        .mix_sampled_values,
        .mix_fri_root,
        .mix_last_layer,
        => .mix,
        .draw_composition_alpha,
        .draw_oods_point,
        .draw_quotient_alpha,
        .draw_fri_alpha,
        => .challenge,
        .absorb_pow => .pow,
        .draw_queries => .queries,
    };
}

fn transcriptValueCount(
    operation: transcript.Operation,
    geometry: request.Geometry,
) u32 {
    return switch (operation) {
        .mix_sampled_values => @intCast(geometry.sampled_value_count),
        .draw_queries => @intCast(geometry.protocol.n_queries),
        else => 1,
    };
}

fn stage(value: telemetry.Stage) ir.Stage {
    return switch (value) {
        .ingress => .ingress,
        .trace_generation => .trace_generation,
        .trace_commit => .trace_commit,
        .constraint_evaluation => .constraint_evaluation,
        .oods => .oods,
        .quotient => .quotient,
        .fri_commit => .fri_commit,
        .pow => .pow,
        .decommit => .decommit,
        .proof_assembly => .proof_assembly,
    };
}

fn statementIdentity(geometry: request.Geometry) ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/native/wide-fibonacci/statement/v1");
    hashInt(&hash, u32, geometry.statement.log_n_rows);
    hashInt(&hash, u32, geometry.statement.sequence_len);
    var digest: ir.Digest = undefined;
    hash.final(&digest);
    return digest;
}

fn protocolIdentity(geometry: request.Geometry) ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/raw-stwo-wide/protocol/v1");
    hashInt(&hash, u32, geometry.protocol.pow_bits);
    hashInt(&hash, u32, geometry.protocol.log_blowup_factor);
    hashInt(&hash, u32, geometry.protocol.log_last_layer_degree_bound);
    hashInt(&hash, u64, geometry.protocol.n_queries);
    hashInt(&hash, u32, geometry.protocol.fold_step);
    hashInt(
        &hash,
        u32,
        if (geometry.protocol.lifting_log_size) |value| value + 1 else 0,
    );
    var digest: ir.Digest = undefined;
    hash.final(&digest);
    return digest;
}

fn sumFriCells(logical: layout_mod.Layout) !u64 {
    var cells: u64 = 0;
    for (logical.fri_trees) |tree| {
        if (tree.evaluation_log_size >= 63) return error.GeometryOverflow;
        cells = std.math.add(
            u64,
            cells,
            @as(u64, 1) << @intCast(tree.evaluation_log_size),
        ) catch return error.GeometryOverflow;
    }
    return cells;
}

fn bytes(words: anytype) !u64 {
    return mul(words, @sizeOf(u32));
}

fn mul(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.GeometryOverflow;
    return std.math.mul(u64, lhs, rhs) catch error.GeometryOverflow;
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "wide Fibonacci emits one validated backend-neutral program" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(testRequest());
    var logical = try layout_mod.Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    var quotient = try topology.Quotient.init(allocator, logical);
    defer quotient.deinit(allocator);
    var fri = try topology.Fri.init(allocator, logical);
    defer fri.deinit(allocator);
    const requirements = [_]arena.Requirement{.{
        .id = 7,
        .words = 128,
        .alignment_words = 8,
        .live_from = .ingress,
        .live_through = .proof_assembly,
    }};
    var program = try emit(
        allocator,
        geometry,
        logical,
        quotient,
        fri,
        &requirements,
    );
    defer program.deinit(allocator);
    try program.validate();
    try std.testing.expectEqual(
        geometry.sampled_value_count,
        program.trace_columns.len,
    );
    try std.testing.expectEqual(@as(usize, 8), program.nodes.len);
    try std.testing.expectEqual(
        @as(usize, 3),
        program.commitments.len,
    );
}

fn testRequest() request.Request {
    return .{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
}
