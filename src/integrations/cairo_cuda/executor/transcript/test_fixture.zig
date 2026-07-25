//! Minimal validated Cairo ProofProgram for transcript unit tests.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const compact = @import(
    "../../../../frontends/cairo/compact_verifier_interchange.zig",
);
const cairo_identity = @import("../../identity.zig");

pub fn protocol() !compact.CompactProtocolV1 {
    return compact.sn2ProofLayout().protocol(7);
}

pub fn program(
    allocator: std.mem.Allocator,
    protocol_value: compact.CompactProtocolV1,
) !proof_ir.ProofProgram {
    var trace_columns: [4]proof_ir.TraceColumn = undefined;
    const column_roles = [_]proof_ir.ColumnRole{
        .preprocessed,
        .main,
        .interaction,
        .composition,
    };
    for (&trace_columns, column_roles, 0..) |
        *column,
        role,
        index,
    | {
        column.* = .{
            .id = @intCast(index),
            .component = 0,
            .ordinal = @intCast(index),
            .log_rows = protocol_value.max_log_degree_bound,
            .role = role,
        };
    }
    const constraints = [_]proof_ir.ConstraintProgram{.{
        .id = 0,
        .component = 0,
        .expression = proof_ir.identityDigest(
            "cairo-transcript-test-constraint",
        ),
        .constraint_count = 1,
        .max_degree_log = 1,
    }};
    const commitments = [_]proof_ir.CommitmentTree{
        tree(0, .preprocessed, 0, protocol_value),
        tree(1, .main, 1, protocol_value),
        tree(2, .interaction, 2, protocol_value),
        tree(3, .composition, 3, protocol_value),
    };
    const barriers = try transcriptBarriers(
        allocator,
        protocol_value,
    );
    defer allocator.free(barriers);
    const fri_layers = try friLayers(allocator, protocol_value);
    defer allocator.free(fri_layers);
    const nodes = [_]proof_ir.Node{
        node(0, .commitment, .trace_commit),
        node(1, .pow, .trace_commit),
        node(2, .commitment, .trace_commit),
        node(3, .commitment, .constraint_evaluation),
        node(4, .oods, .oods),
        node(5, .fri_commit, .fri_commit),
        node(6, .pow, .pow),
        node(7, .decommit, .decommit),
    };
    const buffers = [_]proof_ir.Buffer{.{
        .id = 0,
        .words = 1,
        .alignment_words = 1,
        .live_from = .ingress,
        .live_through = .proof_assembly,
        .storage = .request_local,
        .immutable = false,
    }};
    return proof_ir.ProofProgram.init(allocator, .{
        .identity = .{
            .frontend = .cairo,
            .air = proof_ir.identityDigest(
                "cairo-transcript-test-air",
            ),
            .statement = proof_ir.identityDigest(
                "cairo-transcript-test-statement",
            ),
            .protocol = try cairo_identity.protocolDigest(
                protocol_value,
            ),
        },
        .trace_columns = &trace_columns,
        .constraints = &constraints,
        .commitments = &commitments,
        .transcript = barriers,
        .quotient = .{
            .term_count = 1,
            .group_count = 1,
            .evaluation_log_rows = protocol_value.max_log_degree_bound,
            .composition_degree_log = 1,
        },
        .fri_layers = fri_layers,
        .buffers = &buffers,
        .nodes = &nodes,
        .dependency_ids = &.{},
    });
}

fn tree(
    id: u32,
    role: proof_ir.CommitmentRole,
    first_column: u32,
    protocol_value: compact.CompactProtocolV1,
) proof_ir.CommitmentTree {
    return .{
        .id = id,
        .role = role,
        .first_column = first_column,
        .column_count = 1,
        .evaluation_log_rows = protocol_value.max_log_degree_bound,
        .log_rows_per_leaf = protocol_value.max_log_degree_bound,
        .retain_openings = true,
    };
}

fn node(
    id: u32,
    kind: proof_ir.OperationKind,
    stage: proof_ir.Stage,
) proof_ir.Node {
    return .{
        .id = id,
        .kind = kind,
        .stage = stage,
        .dependencies = .{ .first = 0, .count = 0 },
        .parallelism = .coordination,
        .graph_candidate = false,
        .work = .{
            .bytes_read = 1,
            .bytes_written = 1,
            .field_operations = 1,
            .hash_compressions = 0,
            .minimum_launches = 1,
        },
    };
}

fn transcriptBarriers(
    allocator: std.mem.Allocator,
    protocol_value: compact.CompactProtocolV1,
) ![]proof_ir.TranscriptBarrier {
    const count: usize = 16 + protocol_value.fri_tree_count * 2;
    const barriers = try allocator.alloc(
        proof_ir.TranscriptBarrier,
        count,
    );
    var cursor: usize = 0;
    const prefix_kinds = [_]proof_ir.TranscriptKind{
        .mix,
        .mix,
        .mix,
        .mix,
        .pow,
        .challenge,
        .mix,
        .mix,
        .challenge,
        .mix,
        .challenge,
        .mix,
        .challenge,
    };
    const prefix_counts = [_]u32{
        1,
        1,
        123,
        1,
        1,
        2,
        protocol_value.interaction_sum_count,
        1,
        1,
        1,
        1,
        protocol_value.sampled_value_words / 4,
        1,
    };
    for (prefix_kinds, prefix_counts) |kind, value_count| {
        barriers[cursor] = barrierAt(
            cursor,
            prefixNode(cursor),
            kind,
            value_count,
            barriers[0..cursor],
        );
        cursor += 1;
    }
    for (0..protocol_value.fri_tree_count) |_| {
        barriers[cursor] = barrierAt(
            cursor,
            5,
            .mix,
            1,
            barriers[0..cursor],
        );
        cursor += 1;
        barriers[cursor] = barrierAt(
            cursor,
            5,
            .challenge,
            1,
            barriers[0..cursor],
        );
        cursor += 1;
    }
    const suffix_kinds = [_]proof_ir.TranscriptKind{
        .mix,
        .pow,
        .queries,
    };
    const suffix_counts = [_]u32{
        protocol_value.final_line_coefficient_count,
        1,
        protocol_value.query_count,
    };
    const suffix_nodes = [_]u32{ 5, 6, 6 };
    for (suffix_kinds, suffix_counts, suffix_nodes) |
        kind,
        value_count,
        node_id,
    | {
        barriers[cursor] = barrierAt(
            cursor,
            node_id,
            kind,
            value_count,
            barriers[0..cursor],
        );
        cursor += 1;
    }
    std.debug.assert(cursor == barriers.len);
    return barriers;
}

fn prefixNode(index: usize) u32 {
    return switch (index) {
        0...3 => 0,
        4...5 => 1,
        6...8 => 2,
        9...10 => 3,
        11...12 => 4,
        else => unreachable,
    };
}

fn barrierAt(
    ordinal: usize,
    node_id: u32,
    kind: proof_ir.TranscriptKind,
    value_count: u32,
    previous: []const proof_ir.TranscriptBarrier,
) proof_ir.TranscriptBarrier {
    var phase: u32 = 0;
    if (previous.len != 0 and previous[previous.len - 1].node == node_id)
        phase = previous[previous.len - 1].phase + 1;
    return .{
        .ordinal = @intCast(ordinal),
        .node = node_id,
        .phase = phase,
        .kind = kind,
        .value_count = value_count,
    };
}

fn friLayers(
    allocator: std.mem.Allocator,
    protocol_value: compact.CompactProtocolV1,
) ![]proof_ir.FriLayer {
    const layers = try allocator.alloc(
        proof_ir.FriLayer,
        protocol_value.fri_tree_count,
    );
    for (layers, 0..) |*layer, index| {
        const cumulative: u32 =
            @intCast(index * protocol_value.fri_fold_step);
        layer.* = .{
            .tree_id = @intCast(index),
            .evaluation_log_rows = protocol_value.max_log_degree_bound - cumulative,
            .fold_step = protocol_value.fri_fold_step,
            .cumulative_fold = cumulative,
            .log_rows_per_leaf = protocol_value.fri_fold_step,
        };
    }
    return layers;
}
