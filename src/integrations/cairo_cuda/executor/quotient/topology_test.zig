const std = @import("std");
const core = @import("stwo_core");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const quotients = core.pcs.quotients;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const fixed_table = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const semantic_authority = @import("stwo_cairo_frontend").proof_plan.semantic_authority;
const quotient_geometry = @import("stwo_cairo_frontend").witness.quotient_geometry;
const fixture = @import("../resident_plan_test.zig");
const subject = @import("topology.zig");

test "SN2 quotient topology authenticates 6110 samples into 19 groups" {
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
    const protocol = try fixture.sn2Protocol(
        bundle,
        preprocessed_logs.len,
    );
    var program = try fixture.sn2Program(
        allocator,
        bundle,
        protocol,
        preprocessed_logs,
    );
    defer program.deinit(allocator);

    var topology = try subject.derive(
        allocator,
        bundle,
        program,
        protocol,
    );
    defer topology.deinit();

    try std.testing.expectEqual(@as(u32, 6110), topology.sampled_value_count);
    try std.testing.expectEqual(@as(usize, 6342), topology.termCount());
    try std.testing.expectEqual(@as(usize, 19), topology.groupCount());
    try std.testing.expectEqual(
        @as(usize, 5886),
        topology.sources.len,
    );
    try std.testing.expectEqual(@as(usize, 4), topology.source_trees.len);
    try std.testing.expectEqual(
        @as(u64, 7_434_440_576),
        topology.source_evaluation_word_count,
    );
    try std.testing.expectEqual(
        topology.termCount(),
        topology.group_term_indices.len,
    );
    try std.testing.expectEqual(
        topology.termCount(),
        topology.batch_terms.len,
    );
    try std.testing.expect(topology.termCount() > 6110);
    try std.testing.expectEqual(
        @as(u32, 1) << 23,
        topology.maximum_partial_rows,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &topology.identity, 0));
    try compareCoreGroups(bundle, program, protocol, topology);

    const expected_group_order = [_]u32{
        23, 20, 23, 21, 19, 16, 9,  18, 17, 10,
        4,  8,  15, 13, 12, 6,  11, 7,  14,
    };
    try std.testing.expectEqualSlices(
        u32,
        &expected_group_order,
        topology.group_log_sizes,
    );
    const expected_logs = [_]u32{
        4,  6,  7,  8,  9,  10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 23, 23,
    };
    const sorted_logs = try allocator.dupe(u32, topology.group_log_sizes);
    defer allocator.free(sorted_logs);
    std.mem.sort(u32, sorted_logs, {}, std.sort.asc(u32));
    try std.testing.expectEqualSlices(u32, &expected_logs, sorted_logs);
    try std.testing.expectEqualSlices(
        u32,
        topology.group_log_sizes,
        topology.partial_log_sizes,
    );
    for (
        topology.partial_log_sizes,
        topology.partial_offsets[0..topology.groupCount()],
        topology.partial_offsets[1..],
    ) |log_size, begin, end| {
        try std.testing.expectEqual(
            @as(u64, 1) << @intCast(log_size),
            end - begin,
        );
    }
    try std.testing.expectEqual(
        @as(u64, 20_971_472),
        topology.partial_offsets[topology.partial_offsets.len - 1],
    );
    try std.testing.expectEqualSlices(
        u64,
        &.{
            1_086_201_056,
            3_501_451_808,
            2_712_569_984,
            134_217_728,
        },
        &.{
            topology.source_trees[0].evaluation_words,
            topology.source_trees[1].evaluation_words,
            topology.source_trees[2].evaluation_words,
            topology.source_trees[3].evaluation_words,
        },
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 161, 3449, 2268, 8 },
        &.{
            topology.source_trees[0].source_count,
            topology.source_trees[1].source_count,
            topology.source_trees[2].source_count,
            topology.source_trees[3].source_count,
        },
    );
    for (topology.source_trees) |tree| {
        try std.testing.expectEqual(
            @as(u64, 0),
            topology.sources[tree.first_source].compact.offset_words,
        );
        var expected_offset: u64 = 0;
        for (
            topology.sources[tree.first_source .. tree.first_source + tree.source_count],
        ) |source| {
            try std.testing.expectEqual(
                expected_offset,
                source.compact.offset_words,
            );
            const expected_stride: u32 = @as(u32, 1) << @intCast(
                source.compact.log_size + protocol.log_blowup_factor,
            );
            try std.testing.expectEqual(
                expected_stride,
                source.compact.stride_words,
            );
            expected_offset += expected_stride;
        }
        try std.testing.expectEqual(tree.evaluation_words, expected_offset);
    }
    var expected_identity: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_identity,
        "17ae45e9aa7cc5975f65d6dd67d761501f9284bd6ac6e7de861ce1f2ab272d2b",
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_identity,
        &topology.identity,
    );

    std.debug.print(
        "SN2 quotient topology: samples={} terms={} groups={} " ++
            "sources={} source_evaluation_words={} partial_words={} " ++
            "identity={s}\n",
        .{
            topology.sampled_value_count,
            topology.termCount(),
            topology.groupCount(),
            topology.sources.len,
            topology.source_evaluation_word_count,
            topology.partial_offsets[topology.partial_offsets.len - 1],
            std.fmt.bytesToHex(topology.identity, .lower),
        },
    );

    program.constraints[0].expression[0] ^= 1;
    try std.testing.expectError(
        subject.Error.InvalidProgramGeometry,
        subject.derive(allocator, bundle, program, protocol),
    );
}

const CoreInputs = struct {
    points: quotients.TreeVec([][]circle.CirclePointQM31),
    values: quotients.TreeVec([][]QM31),
    logs: quotients.TreeVec([]u32),
    flat_points: []circle.CirclePointQM31,
};

fn compareCoreGroups(
    bundle: composition.Bundle,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    topology: subject.Topology,
) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const parameter = QM31.fromU32Unchecked(
        846579577,
        1914966500,
        886709583,
        1440664798,
    );
    const oods_point = try quotient_geometry.pointFromParameter(parameter);
    const random_coefficient = QM31.fromU32Unchecked(7, 11, 13, 17);
    const inputs = try coreInputs(
        allocator,
        bundle,
        program,
        protocol,
        oods_point,
    );
    const batches = try quotients.buildColumnSampleBatchesFromParallelInputs(
        allocator,
        inputs.points,
        inputs.values,
        inputs.logs,
        bundle.max_evaluation_log_size,
        random_coefficient,
    );
    try std.testing.expectEqual(topology.groupCount(), batches.len);
    for (batches, 0..) |batch, group_index| {
        const begin = topology.group_offsets[group_index];
        const end = topology.group_offsets[group_index + 1];
        try std.testing.expectEqual(
            batch.cols_vals_randpows.len,
            end - begin,
        );
        const representative = topology.group_term_indices[begin];
        const descriptor = topology.prepared_terms[representative];
        var expected_point = inputs.flat_points[descriptor.sample_index];
        if (descriptor.periodic != 0) {
            expected_point = expected_point.add(
                quotient_geometry.pointM31IntoQM31(.{
                    .x = M31.fromCanonical(descriptor.period_x),
                    .y = M31.fromCanonical(descriptor.period_y),
                }),
            );
        }
        try std.testing.expect(batch.point.eql(expected_point));
        for (
            batch.cols_vals_randpows,
            topology.batch_terms[begin..end],
        ) |member, term| {
            const prepared = topology.prepared_terms[term.term_index];
            try std.testing.expectEqual(
                member.column_index,
                term.source_index,
            );
            try std.testing.expectEqual(
                prepared.sample_index,
                member.sample_value.toM31Array()[0].v,
            );
            try std.testing.expect(
                member.random_coeff.eql(
                    random_coefficient.pow(prepared.exponent),
                ),
            );
        }
    }
}

fn coreInputs(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    oods_point: circle.CirclePointQM31,
) !CoreInputs {
    var masks = try quotient_geometry.deriveMasks(
        allocator,
        bundle,
        protocol.trace_columns[0],
        protocol.trace_columns[1],
        protocol.trace_columns[2],
    );
    defer masks.deinit();
    const point_trees = try allocator.alloc(
        [][]circle.CirclePointQM31,
        4,
    );
    const value_trees = try allocator.alloc([][]QM31, 4);
    const log_trees = try allocator.alloc([]u32, 4);
    var flat = std.ArrayList(circle.CirclePointQM31).empty;
    const trace_step = quotient_geometry.pointM31IntoQM31(
        canonic.CanonicCoset.new(
            bundle.max_evaluation_log_size - 1,
        ).step(),
    );
    for (program.commitments, 0..) |tree, tree_index| {
        const count: usize = tree.column_count;
        point_trees[tree_index] = try allocator.alloc(
            []circle.CirclePointQM31,
            count,
        );
        value_trees[tree_index] = try allocator.alloc([]QM31, count);
        log_trees[tree_index] = try allocator.alloc(u32, count);
        for (
            program.trace_columns[tree.first_column .. tree.first_column + tree.column_count],
            log_trees[tree_index],
        ) |column, *log_size| {
            log_size.* = column.log_rows + 1;
        }
    }
    for (masks.preprocessed_used, 0..) |used, column| {
        try setCoreColumn(
            allocator,
            &point_trees[0][column],
            &value_trees[0][column],
            if (used) &.{0} else &.{},
            oods_point,
            trace_step,
            &flat,
        );
    }
    for (masks.base_offsets, 0..) |offsets, column| {
        try setCoreColumn(
            allocator,
            &point_trees[1][column],
            &value_trees[1][column],
            offsets.items,
            oods_point,
            trace_step,
            &flat,
        );
    }
    for (masks.interaction_offsets, 0..) |offsets, column| {
        try setCoreColumn(
            allocator,
            &point_trees[2][column],
            &value_trees[2][column],
            offsets.items,
            oods_point,
            trace_step,
            &flat,
        );
    }
    for (point_trees[3], value_trees[3]) |*points, *values| {
        try setCoreColumn(
            allocator,
            points,
            values,
            &.{0},
            oods_point,
            trace_step,
            &flat,
        );
    }
    return .{
        .points = .{ .items = point_trees },
        .values = .{ .items = value_trees },
        .logs = .{ .items = log_trees },
        .flat_points = try flat.toOwnedSlice(allocator),
    };
}

fn setCoreColumn(
    allocator: std.mem.Allocator,
    points: *[]circle.CirclePointQM31,
    values: *[]QM31,
    offsets: []const i32,
    oods_point: circle.CirclePointQM31,
    trace_step: circle.CirclePointQM31,
    flat: *std.ArrayList(circle.CirclePointQM31),
) !void {
    points.* = try allocator.alloc(circle.CirclePointQM31, offsets.len);
    values.* = try allocator.alloc(QM31, offsets.len);
    for (offsets, points.*, values.*) |offset, *point, *value| {
        point.* = oods_point.add(trace_step.mulSigned(offset));
        value.* = QM31.fromBase(
            M31.fromCanonical(@intCast(flat.items.len)),
        );
        try flat.append(allocator, point.*);
    }
}

test "quotient topology fails closed on protocol identity drift" {
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
    const logs = try semantic_authority.preprocessedLogs(allocator, fixed);
    defer allocator.free(logs);
    const protocol = try fixture.sn2Protocol(bundle, logs.len);
    var program = try fixture.sn2Program(
        allocator,
        bundle,
        protocol,
        logs,
    );
    defer program.deinit(allocator);
    program.identity.protocol[0] ^= 1;
    try std.testing.expectError(
        subject.Error.InvalidProtocolIdentity,
        subject.derive(allocator, bundle, program, protocol),
    );
}
