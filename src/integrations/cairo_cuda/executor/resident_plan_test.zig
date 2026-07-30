const std = @import("std");
const core = @import("stwo_core");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const compact_geometry = @import("stwo_cairo_frontend").compact_protocol_geometry;
const semantic_authority = @import("stwo_cairo_frontend").proof_plan.semantic_authority;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const cairo_identity = @import("../identity.zig");
const fixed_table = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const subject = @import("resident_plan.zig");
const test_support = @import("resident_plan_test_support.zig");

test "SN2 resident inventory is identity-bound and fits the modeled H100 arena" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var fixed = try fixed_table.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    const preprocessed_logs = try semantic_authority.preprocessedLogs(
        allocator,
        fixed,
    );
    defer allocator.free(preprocessed_logs);
    const protocol = try sn2Protocol(
        bundle,
        preprocessed_logs.len,
    );
    var program = try sn2Program(
        allocator,
        bundle,
        protocol,
        preprocessed_logs,
    );
    defer program.deinit(allocator);

    const ingress = try test_support.geometry(program, bundle);
    var plan = try subject.Plan.init(
        allocator,
        program,
        protocol,
        bundle,
        ingress,
    );
    defer plan.deinit(allocator);
    const summary = plan.summary;
    try std.testing.expectEqual(
        @as(u64, 3_717_220_288),
        summary.coefficient_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 7_434_440_576),
        summary.evaluation_cells,
    );
    try std.testing.expect(summary.slot_count > 100);
    try std.testing.expect(summary.persistent_words > 0);
    try std.testing.expect(summary.request_arena_words > 0);
    try std.testing.expect(summary.peak_live_words > 0);
    try std.testing.expectEqual(
        @as(u64, 0),
        summary.decommit_terminal_shortfall_words,
    );
    try std.testing.expectEqual(
        @as(u64, 2_102_576 + subject_terminal.container_header_words),
        summary.terminal_words,
    );
    try std.testing.expect(
        compact.sn2_decommitment_capacity_words >=
            summary.decommit_assembly_words,
    );
    try std.testing.expect(summary.fitsBytes(subject.h100_80gb_bytes));
    try std.testing.expect(!std.mem.allEqual(u8, &plan.identity, 0));
    try std.testing.expect(!subject.production_ready);
    try std.testing.expectEqual(
        @as(usize, 6_342),
        plan.quotient_geometry.term_count,
    );
    try std.testing.expectEqual(
        @as(usize, 19),
        plan.quotient_geometry.group_count,
    );
    try std.testing.expectEqual(
        @as(usize, 5_886),
        plan.quotient_geometry.source_count,
    );
    try std.testing.expectEqual(
        @as(usize, 20_971_472),
        plan.quotient_geometry.partial_word_count,
    );
    try std.testing.expectEqual(
        @as(u32, 1) << 23,
        plan.quotient_geometry.maximum_partial_rows,
    );

    const composition_slot = plan.slot(
        .constraint_composition_output,
        3,
    ) orelse return error.MissingCompositionSlot;
    try std.testing.expectEqual(
        proof_ir.StorageClass.request_local,
        composition_slot.storage,
    );
    const fixed_slot = plan.slot(
        .trace_coefficients,
        0,
    ) orelse return error.MissingFixedSlot;
    try std.testing.expectEqual(
        proof_ir.StorageClass.process_cache,
        fixed_slot.storage,
    );
    const source_descriptors = plan.slot(
        .quotient_source_descriptors,
        0,
    ) orelse return error.MissingQuotientSourceDescriptors;
    try std.testing.expectEqual(
        program.trace_columns.len * 4,
        source_descriptors.words,
    );
    const prepared_terms = plan.slot(
        .quotient_prepared_terms,
        0,
    ) orelse return error.MissingQuotientTerms;
    try std.testing.expectEqual(
        plan.quotient_geometry.term_count * 5,
        prepared_terms.words,
    );
    const line_coefficients = plan.slot(
        .quotient_line_coefficients,
        0,
    ) orelse return error.MissingQuotientLines;
    try std.testing.expectEqual(
        plan.quotient_geometry.term_count * 12,
        line_coefficients.words,
    );
    const group_logs = plan.slot(
        .quotient_group_logs,
        0,
    ) orelse return error.MissingQuotientGroups;
    try std.testing.expectEqual(
        plan.quotient_geometry.group_count,
        group_logs.words,
    );
    const partial_offsets = plan.slot(
        .quotient_partial_offsets,
        0,
    ) orelse return error.MissingQuotientPartialOffsets;
    try std.testing.expectEqual(
        (plan.quotient_geometry.group_count + 1) * 2,
        partial_offsets.words,
    );
    const partial_coordinates = plan.slot(
        .quotient_partial_coordinates,
        0,
    ) orelse return error.MissingQuotientPartials;
    try std.testing.expectEqual(
        plan.quotient_geometry.partial_word_count * 4,
        partial_coordinates.words,
    );
    try std.testing.expect(plan.slot(.fri_coordinates, 0) == null);
    const quotient_result = plan.slot(
        .quotient_result_coordinates,
        0,
    ) orelse return error.MissingQuotientResult;
    try std.testing.expectEqual(
        (@as(usize, 1) << @intCast(program.fri_layers[0].evaluation_log_rows)) *
            4,
        quotient_result.words,
    );

    std.debug.print(
        "SN2 CUDA resident plan: slots={} coefficient_cells={} " ++
            "lde_cells={} logical_bytes={} peak_live_bytes={} " ++
            "allocated_bytes={} terminal_words={} decommit_words={} " ++
            "fits_h100_80gb={}\n",
        .{
            summary.slot_count,
            summary.coefficient_cells,
            summary.evaluation_cells,
            summary.logicalBytes(),
            summary.peak_live_words * subject.word_bytes,
            summary.allocatedResidentBytes(),
            summary.terminal_words,
            summary.decommit_assembly_words,
            summary.fitsBytes(subject.h100_80gb_bytes),
        },
    );

    program.commitments[0].evaluation_log_rows += 1;
    try std.testing.expectError(
        subject.Error.UnsupportedGeometry,
        subject.Plan.init(
            allocator,
            program,
            protocol,
            bundle,
            ingress,
        ),
    );
}

const subject_terminal = @import("terminal_bundle.zig");

pub fn sn2Protocol(
    bundle: composition.Bundle,
    preprocessed_columns: usize,
) !compact.CompactProtocolV1 {
    const verifier_log = try bundle.verifierMaxLogDegreeBound();
    var geometry = compact_geometry.RuntimeProtocolGeometryV1.sn2();
    geometry.max_log_degree_bound = verifier_log;
    geometry.fri_tree_count =
        1 + (verifier_log - 1) / geometry.fri_fold_step;
    geometry.decommitment_record_count =
        geometry.commitment_count + geometry.fri_tree_count;
    if (bundle.components.len * 4 != compact.sn2_interaction_claim_words)
        return error.InvalidProtocolGeometry;
    return compact.sn2ProofLayout().protocolRuntime(7, geometry, .{
        @intCast(preprocessed_columns),
        finalSpanEnd(bundle, 1),
        finalSpanEnd(bundle, 2),
        8,
    });
}

pub fn sn2Program(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    protocol: compact.CompactProtocolV1,
    preprocessed_logs: []const u32,
) !proof_ir.ProofProgram {
    const air_identity = proof_ir.identityDigest(
        "sn2-resident-plan-air",
    );
    const columns = try traceColumns(
        allocator,
        bundle,
        protocol,
        preprocessed_logs,
    );
    defer allocator.free(columns);
    const constraints = try allocator.alloc(
        proof_ir.ConstraintProgram,
        bundle.components.len,
    );
    defer allocator.free(constraints);
    for (bundle.components, constraints, 0..) |component, *constraint, index| {
        constraint.* = .{
            .id = @intCast(index),
            .component = @intCast(index),
            .expression = cairo_identity.componentProgramDigest(
                air_identity,
                component,
            ),
            .constraint_count = component.n_constraints,
            .max_degree_log = component.evaluation_log_size - component.trace_log_size,
        };
    }
    const commitments = commitmentTrees(columns, protocol);
    const fri_layers = try friLayers(allocator, protocol);
    defer allocator.free(fri_layers);
    const nodes = [_]proof_ir.Node{
        node(0, .trace_generation, .trace_generation, 0, 0),
        node(1, .commitment, .trace_commit, 0, 1),
        node(2, .constraint_evaluation, .constraint_evaluation, 1, 1),
        node(3, .oods, .oods, 2, 1),
        node(4, .quotient, .quotient, 3, 1),
        node(5, .fri_commit, .fri_commit, 4, 1),
        node(6, .pow, .pow, 5, 1),
        node(7, .decommit, .decommit, 6, 1),
    };
    const dependencies = [_]u32{ 0, 1, 2, 3, 4, 5, 6 };
    const transcript = [_]proof_ir.TranscriptBarrier{
        .{
            .ordinal = 0,
            .node = 1,
            .phase = 0,
            .kind = .mix,
            .value_count = 8,
        },
        .{
            .ordinal = 1,
            .node = 2,
            .phase = 0,
            .kind = .challenge,
            .value_count = 4,
        },
        .{
            .ordinal = 2,
            .node = 5,
            .phase = 0,
            .kind = .mix,
            .value_count = 8,
        },
        .{
            .ordinal = 3,
            .node = 6,
            .phase = 0,
            .kind = .pow,
            .value_count = 2,
        },
        .{
            .ordinal = 4,
            .node = 7,
            .phase = 0,
            .kind = .queries,
            .value_count = protocol.query_count,
        },
    };
    const buffers = [_]proof_ir.Buffer{.{
        .id = 1,
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
            .air = air_identity,
            .statement = proof_ir.identityDigest(
                "sn2-resident-plan-statement",
            ),
            .protocol = try cairo_identity.protocolDigest(protocol),
        },
        .trace_columns = columns,
        .constraints = constraints,
        .commitments = &commitments,
        .transcript = &transcript,
        .quotient = .{
            .term_count = @intCast(bundle.total_constraints),
            .group_count = @intCast(bundle.components.len),
            .evaluation_log_rows = protocol.max_log_degree_bound,
            .composition_degree_log = maxDegree(bundle),
        },
        .fri_layers = fri_layers,
        .buffers = &buffers,
        .nodes = &nodes,
        .dependency_ids = &dependencies,
    });
}

fn traceColumns(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    protocol: compact.CompactProtocolV1,
    preprocessed_logs: []const u32,
) ![]proof_ir.TraceColumn {
    var total: usize = 0;
    for (protocol.trace_columns) |count| total += count;
    const output = try allocator.alloc(proof_ir.TraceColumn, total);
    var cursor: usize = 0;
    for (preprocessed_logs) |log_rows| {
        output[cursor] = column(cursor, std.math.maxInt(u32), log_rows, .preprocessed);
        cursor += 1;
    }
    inline for ([_]u32{ 1, 2 }) |tree| {
        const role: proof_ir.ColumnRole =
            if (tree == 1) .main else .interaction;
        for (bundle.components, 0..) |component, component_index| {
            const span = componentSpan(component, tree);
            for (span.start..span.end) |_| {
                output[cursor] = column(
                    cursor,
                    @intCast(component_index),
                    component.trace_log_size,
                    role,
                );
                cursor += 1;
            }
        }
    }
    for (0..protocol.trace_columns[3]) |_| {
        output[cursor] = column(
            cursor,
            std.math.maxInt(u32) - 1,
            protocol.max_log_degree_bound - 1,
            .composition,
        );
        cursor += 1;
    }
    try std.testing.expectEqual(output.len, cursor);
    return output;
}

fn commitmentTrees(
    columns: []const proof_ir.TraceColumn,
    protocol: compact.CompactProtocolV1,
) [4]proof_ir.CommitmentTree {
    var output: [4]proof_ir.CommitmentTree = undefined;
    var first: u32 = 0;
    inline for (0..4) |index| {
        const count = protocol.trace_columns[index];
        var evaluation_log: u32 = 0;
        for (columns[first .. first + count]) |column_value| {
            evaluation_log = @max(
                evaluation_log,
                column_value.log_rows + protocol.log_blowup_factor,
            );
        }
        output[index] = .{
            .id = index,
            .role = @enumFromInt(index),
            .first_column = first,
            .column_count = count,
            .evaluation_log_rows = evaluation_log,
            .log_rows_per_leaf = evaluation_log,
            .retain_openings = true,
        };
        first += count;
    }
    return output;
}

fn friLayers(
    allocator: std.mem.Allocator,
    protocol: compact.CompactProtocolV1,
) ![]proof_ir.FriLayer {
    const geometry = try core.fri.geometry.FriGeometry.initRuntime(
        protocol.max_log_degree_bound,
        .{
            .round_count = protocol.fri_tree_count,
            .fold_step = protocol.fri_fold_step,
            .final_log = protocol.log_last_layer_degree_bound + 1,
            .packed_log = core.fri.geometry.FriGeometry.packed_log,
        },
    );
    const output = try allocator.alloc(
        proof_ir.FriLayer,
        geometry.roundCount(),
    );
    for (output, 0..) |*layer, index| {
        layer.* = .{
            .tree_id = @intCast(index),
            .evaluation_log_rows = try geometry.evaluationLog(index),
            .fold_step = try geometry.roundFold(index),
            .cumulative_fold = try geometry.cumulativeFold(index),
            .log_rows_per_leaf = try geometry.leafLog(index),
        };
    }
    return output;
}

fn node(
    id: u32,
    kind: proof_ir.OperationKind,
    stage: proof_ir.Stage,
    dependency_first: u32,
    dependency_count: u32,
) proof_ir.Node {
    return .{
        .id = id,
        .kind = kind,
        .stage = stage,
        .dependencies = .{
            .first = dependency_first,
            .count = dependency_count,
        },
        .parallelism = .coordination,
        .graph_candidate = false,
        .work = .{
            .bytes_read = 1,
            .bytes_written = 1,
            .field_operations = 1,
            .hash_compressions = 1,
            .minimum_launches = 1,
        },
    };
}

fn column(
    id: usize,
    component: u32,
    log_rows: u32,
    role: proof_ir.ColumnRole,
) proof_ir.TraceColumn {
    return .{
        .id = @intCast(id),
        .component = component,
        .ordinal = @intCast(id),
        .log_rows = log_rows,
        .role = role,
    };
}

fn componentSpan(
    component: composition.Component,
    tree: u32,
) composition.TraceSpan {
    for (component.trace_spans) |span| {
        if (span.tree == tree) return span;
    }
    unreachable;
}

fn finalSpanEnd(bundle: composition.Bundle, tree: u32) u32 {
    var result: u32 = 0;
    for (bundle.components) |component| {
        result = @max(result, componentSpan(component, tree).end);
    }
    return result;
}

fn maxDegree(bundle: composition.Bundle) u32 {
    var result: u32 = 0;
    for (bundle.components) |component| {
        result = @max(
            result,
            component.evaluation_log_size - component.trace_log_size,
        );
    }
    return result;
}
