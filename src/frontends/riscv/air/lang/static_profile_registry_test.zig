const std = @import("std");
const protocol_report = @import("protocol_report.zig");
const registry = @import("static_profile_registry.zig");

test "AIR static profile registry: all native family definitions have exact authenticated profiles" {
    const report = try registry.collect(std.testing.allocator);
    try report.validate();

    try std.testing.expectEqual(@as(usize, 17), registry.FAMILY_COUNT);
    try std.testing.expectEqual(@as(usize, 17), report.families.len);
    try std.testing.expectEqualStrings(
        "typed_addi",
        registry.DESCRIPTORS[@intFromEnum(registry.Family.base_alu_imm)]
            .native_definition,
    );
    try std.testing.expectEqualDeep(registry.Totals{
        .physical_main_columns = 646,
        .logical_input_nodes = 677,
        .constraint_roots = 545,
        .effects = 243,
        .lookup_events = 243,
        .lookup_batches = 156,
        .interaction_columns = 620,
        .expression_dag_nodes = 3079,
        .expression_dag_edges = 4370,
        .expression_dag_shared_nodes = 649,
        .constraint_effect_reachable_nodes = 3034,
        .nodes_outside_constraint_effect_closure = 45,
        .maximum_logical_constraint_degree = 3,
        .maximum_lookup_numerator_degree = 2,
        .maximum_lookup_denominator_degree = 2,
        .maximum_modeled_interaction_degree = 3,
    }, report.totals);
    try std.testing.expectEqualStrings(
        "0dd67acd8705f77a5c482a8d3706b38929d799091b3971e995b20dcc44f56772",
        &std.fmt.bytesToHex(report.report_digest, .lower),
    );

    const expected_widths = [_]u32{
        35, 35, 60, 51, 44, 37, 30, 37, 18, 29, 41, 20, 48, 39, 47, 67, 6,
    };
    const expected_roots = [_]u32{
        22, 22, 70, 67, 36, 33, 18, 33, 9, 17, 23, 10, 63, 17, 24, 79, 2,
    };
    const expected_lookups = [_]u32{
        18, 16, 20, 16, 14, 11, 9, 11, 7, 12, 18, 8, 16, 16, 22, 25, 3,
    };
    const expected_batch_sizes = [_]u8{
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2,
    };
    for (registry.DESCRIPTORS, 0..) |descriptor, index| {
        try std.testing.expectEqual(expected_widths[index], descriptor.physical_main_columns);
        try std.testing.expectEqual(expected_roots[index], descriptor.authored_constraint_roots);
        try std.testing.expectEqual(expected_lookups[index], descriptor.authored_lookup_events);
        try std.testing.expectEqual(expected_batch_sizes[index], descriptor.audited_lookup_batch_size);
    }
}

test "AIR static profile registry: native facts match the audited production protocol report" {
    const native = try registry.collect(std.testing.allocator);
    const audited = try protocol_report.collect(std.testing.allocator);
    try audited.validate();

    for (native.families, audited.families) |actual, expected| {
        try std.testing.expectEqual(expected.family, actual.family);
        try std.testing.expectEqual(expected.main_columns, actual.profile.physical_main_columns.?);
        try std.testing.expectEqual(expected.direct_constraints, actual.profile.constraint_roots);
        try std.testing.expectEqual(expected.lookups, actual.profile.lookup_events);
        try std.testing.expectEqual(expected.batch_size, actual.profile.lookup_batch_size.?);
        try std.testing.expectEqual(expected.interaction_constraints, actual.profile.lookup_batches.?);
        try std.testing.expectEqual(expected.interaction_columns, actual.profile.interaction_columns.?);
        try std.testing.expectEqual(expected.maximum_direct_degree, actual.profile.maximum_logical_constraint_degree);
        try std.testing.expectEqual(expected.maximum_numerator_degree, actual.profile.maximum_lookup_numerator_degree.?);
        try std.testing.expectEqual(expected.maximum_denominator_degree, actual.profile.maximum_lookup_denominator_degree.?);
        try std.testing.expectEqual(expected.maximum_interaction_degree, actual.profile.maximum_modeled_interaction_degree.?);
        try std.testing.expectEqual(registry.ProductionActivation.not_assessed, actual.production_activation);
    }
}

test "AIR static profile registry: canonical TSV is deterministic and family ordered" {
    const report = try registry.collect(std.testing.allocator);
    var storage: [32 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    try registry.writeTsv(&writer, &report);
    const tsv = writer.buffered();

    var replay_storage: [32 * 1024]u8 = undefined;
    var replay_writer = std.Io.Writer.fixed(&replay_storage);
    try registry.writeTsv(&replay_writer, &report);
    try std.testing.expectEqualStrings(tsv, replay_writer.buffered());
    try std.testing.expectEqual(@as(usize, registry.FAMILY_COUNT + 1), std.mem.count(u8, tsv, "\n"));
    try std.testing.expect(std.mem.indexOf(u8, tsv, "\t0\tbase_alu_reg\ttyped_base_alu_reg\t") != null);
    try std.testing.expect(std.mem.indexOf(u8, tsv, "\t1\tbase_alu_imm\ttyped_addi\t") != null);
    try std.testing.expect(std.mem.indexOf(u8, tsv, "\t16\tfence\ttyped_fence\t") != null);

    var output_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(tsv, &output_digest, .{});
    try std.testing.expectEqualStrings(
        "d4b187cbdf5baee61f4eb2541acf1d69e8e84ddae91007b574ec4a6663a18c6b",
        &std.fmt.bytesToHex(output_digest, .lower),
    );
}

test "AIR static profile registry: report corruption fails closed before output" {
    const report = try registry.collect(std.testing.allocator);

    var corrupted = report;
    corrupted.families[0].family = .div;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.families[0].profile.physical_main_columns.? += 1;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());

    corrupted = report;
    corrupted.report_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidReport, corrupted.validate());
    var storage: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    try std.testing.expectError(
        error.InvalidReport,
        registry.writeTsv(&writer, &corrupted),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);

    var markdown_storage: [1024]u8 = undefined;
    var markdown_writer = std.Io.Writer.fixed(&markdown_storage);
    try std.testing.expectError(
        error.InvalidReport,
        registry.writeMarkdown(&markdown_writer, &corrupted),
    );
    try std.testing.expectEqual(@as(usize, 0), markdown_writer.buffered().len);
}

const Sha256 = std.crypto.hash.sha2.Sha256;
