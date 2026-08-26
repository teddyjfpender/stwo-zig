//! Deterministic M2 report over every imported production opcode family.

const std = @import("std");
const trace = @import("../../runner/trace.zig");
const manifest = @import("manifest.zig");
const protocol_degree = @import("protocol_degree.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");

pub const format_version: u16 = 1;

pub const Family = struct {
    family: trace.OpcodeFamily,
    main_columns: u32,
    source_nodes: u32,
    typed_nodes: u32,
    canonical_merges: u32,
    direct_constraints: u32,
    lookups: u32,
    batch_size: u8,
    interaction_constraints: u32,
    interaction_columns: u32,
    maximum_direct_degree: protocol_degree.Degree,
    maximum_numerator_degree: protocol_degree.Degree,
    maximum_denominator_degree: protocol_degree.Degree,
    maximum_interaction_degree: protocol_degree.Degree,
    direct_expansion_bits: u8,
    interaction_expansion_bits: u8,
    role_counts: [@typeInfo(relation.Role).@"enum".fields.len]u16,
    dependency_counts: [relation.schemas.len]u16,
};

pub const Report = struct {
    families: [trace.N_FAMILIES]Family,

    pub fn validate(self: *const Report) error{InvalidReport}!void {
        for (self.families, 0..) |family, index| {
            const expected_interaction_columns = std.math.mul(
                u32,
                family.interaction_constraints,
                4,
            ) catch return error.InvalidReport;
            if (@intFromEnum(family.family) != index or
                family.main_columns == 0 or
                family.source_nodes == 0 or
                family.typed_nodes == 0 or
                family.typed_nodes > family.source_nodes or
                family.canonical_merges != family.source_nodes - family.typed_nodes or
                family.direct_constraints == 0 or
                family.lookups == 0 or
                (family.batch_size != 1 and family.batch_size != 2) or
                family.interaction_constraints == 0 or
                family.interaction_columns != expected_interaction_columns or
                family.direct_expansion_bits !=
                    protocol_degree.quotientExpansionBits(family.maximum_direct_degree) or
                family.interaction_expansion_bits !=
                    protocol_degree.quotientExpansionBits(family.maximum_interaction_degree))
            {
                return error.InvalidReport;
            }
            const rounded_lookups = std.math.add(
                u32,
                family.lookups,
                family.batch_size - 1,
            ) catch return error.InvalidReport;
            const expected_batches = rounded_lookups / family.batch_size;
            if (family.interaction_constraints != expected_batches)
                return error.InvalidReport;
            var dependency_total: u32 = 0;
            for (family.dependency_counts) |dependency_count|
                dependency_total += dependency_count;
            var role_total: u32 = 0;
            for (family.role_counts) |role_count| role_total += role_count;
            if (dependency_total != family.lookups or role_total != family.lookups)
                return error.InvalidReport;
        }
    }
};

pub fn collect(allocator: std.mem.Allocator) !Report {
    var report: Report = undefined;
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        // A zero trace-log size makes required log bounds equal expansion bits
        // while keeping the calculation on the exact same code path.
        var degrees = try protocol_degree.analyze(allocator, &imported, 0);
        defer degrees.deinit();

        var dependencies = [_]u16{0} ** relation.schemas.len;
        var roles = [_]u16{0} ** @typeInfo(relation.Role).@"enum".fields.len;
        for (imported.lookups) |lookup| {
            const schema_index = @intFromEnum(lookup.schema);
            dependencies[schema_index] = std.math.add(
                u16,
                dependencies[schema_index],
                1,
            ) catch return error.CountOverflow;
            const role_index = @intFromEnum(lookup.role);
            roles[role_index] = std.math.add(
                u16,
                roles[role_index],
                1,
            ) catch return error.CountOverflow;
        }
        const source_nodes = try count(imported.imported.source_to_value.len);
        const typed_nodes = try count(imported.imported.arena.nodeCount());
        const interaction_constraints = try count(imported.batchCount());
        const interaction_columns = std.math.mul(
            u32,
            interaction_constraints,
            4,
        ) catch return error.CountOverflow;
        report.families[family_index] = .{
            .family = family,
            .main_columns = try count(imported.main_column_count),
            .source_nodes = source_nodes,
            .typed_nodes = typed_nodes,
            .canonical_merges = source_nodes - typed_nodes,
            .direct_constraints = try count(imported.direct_constraints.len),
            .lookups = try count(imported.lookups.len),
            .batch_size = imported.batch_size,
            .interaction_constraints = interaction_constraints,
            .interaction_columns = interaction_columns,
            .maximum_direct_degree = degrees.maximum_direct_degree,
            .maximum_numerator_degree = degrees.maximum_lookup_numerator_degree,
            .maximum_denominator_degree = degrees.maximum_lookup_denominator_degree,
            .maximum_interaction_degree = degrees.maximum_interaction_degree,
            .direct_expansion_bits = protocol_degree.quotientExpansionBits(
                degrees.maximum_direct_degree,
            ),
            .interaction_expansion_bits = protocol_degree.quotientExpansionBits(
                degrees.maximum_interaction_degree,
            ),
            .role_counts = roles,
            .dependency_counts = dependencies,
        };
    }
    try report.validate();
    return report;
}

pub fn writeMachine(writer: anytype, report: *const Report) !void {
    try report.validate();
    try writer.print(
        "# stwo-zig typed-air production-shadow-report v{d}\n",
        .{format_version},
    );
    try writer.print(
        "# logical-schema {d}; counts are per independently compiled family\n",
        .{manifest.logical_schema_version},
    );
    try writer.writeAll(
        "family\tmain_columns\tsource_nodes\ttyped_nodes\tcanonical_merges" ++
            "\tdirect_constraints\tlookups\tbatch_size\tinteraction_constraints" ++
            "\tinteraction_columns\tmax_direct_degree\tmax_numerator_degree" ++
            "\tmax_denominator_degree\tmax_interaction_degree" ++
            "\tdirect_expansion_bits\tinteraction_expansion_bits" ++
            "\trole_request\trole_consume\trole_emit",
    );
    for (relation.schemas) |schema|
        try writer.print("\tdep_{s}", .{@tagName(schema.domain)});
    try writer.writeByte('\n');

    for (report.families) |family| {
        try writer.print(
            "{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}" ++
                "\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}",
            .{
                @tagName(family.family),
                family.main_columns,
                family.source_nodes,
                family.typed_nodes,
                family.canonical_merges,
                family.direct_constraints,
                family.lookups,
                family.batch_size,
                family.interaction_constraints,
                family.interaction_columns,
                family.maximum_direct_degree,
                family.maximum_numerator_degree,
                family.maximum_denominator_degree,
                family.maximum_interaction_degree,
                family.direct_expansion_bits,
                family.interaction_expansion_bits,
            },
        );
        for (family.role_counts) |role_count|
            try writer.print("\t{d}", .{role_count});
        for (family.dependency_counts) |dependency_count|
            try writer.print("\t{d}", .{dependency_count});
        try writer.writeByte('\n');
    }
}

pub fn writeMarkdown(writer: anytype, report: *const Report) !void {
    try report.validate();
    try writer.writeAll(
        "# M2 production shadow report\n\n" ++
            "Generated deterministically from the complete production symbolic builder. " ++
            "Counts are per independently compiled opcode family.\n\n" ++
            "| Family | Main cols | DAG source → typed | Merges | Direct | " ++
            "Lookups / batches / interaction cols | Degree D / N / Den / I | " ++
            "Expansion D / I | Relation dependencies |\n" ++
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n",
    );
    var total_main: u64 = 0;
    var total_source: u64 = 0;
    var total_typed: u64 = 0;
    var total_merges: u64 = 0;
    var total_direct: u64 = 0;
    var total_lookups: u64 = 0;
    var total_batches: u64 = 0;
    var total_interaction_columns: u64 = 0;
    var maximum_direct: Degree = 0;
    var maximum_numerator: Degree = 0;
    var maximum_denominator: Degree = 0;
    var maximum_interaction: Degree = 0;
    for (report.families) |family| {
        try writer.print(
            "| `{s}` | {d} | {d} → {d} | {d} | {d} | {d} / {d} / {d} | " ++
                "{d} / {d} / {d} / {d} | {d} / {d} | ",
            .{
                @tagName(family.family),
                family.main_columns,
                family.source_nodes,
                family.typed_nodes,
                family.canonical_merges,
                family.direct_constraints,
                family.lookups,
                family.interaction_constraints,
                family.interaction_columns,
                family.maximum_direct_degree,
                family.maximum_numerator_degree,
                family.maximum_denominator_degree,
                family.maximum_interaction_degree,
                family.direct_expansion_bits,
                family.interaction_expansion_bits,
            },
        );
        try writeDependencies(writer, family.dependency_counts);
        try writer.writeAll(" |\n");
        total_main += family.main_columns;
        total_source += family.source_nodes;
        total_typed += family.typed_nodes;
        total_merges += family.canonical_merges;
        total_direct += family.direct_constraints;
        total_lookups += family.lookups;
        total_batches += family.interaction_constraints;
        total_interaction_columns += family.interaction_columns;
        maximum_direct = @max(maximum_direct, family.maximum_direct_degree);
        maximum_numerator = @max(maximum_numerator, family.maximum_numerator_degree);
        maximum_denominator = @max(maximum_denominator, family.maximum_denominator_degree);
        maximum_interaction = @max(maximum_interaction, family.maximum_interaction_degree);
    }
    try writer.print(
        "| **Independent-family sum / maximum** | **{d}** | **{d} → {d}** | " ++
            "**{d}** | **{d}** | **{d} / {d} / {d}** | **{d} / {d} / {d} / {d}** | " ++
            "**{d} / {d}** | — |\n\n",
        .{
            total_main,
            total_source,
            total_typed,
            total_merges,
            total_direct,
            total_lookups,
            total_batches,
            total_interaction_columns,
            maximum_direct,
            maximum_numerator,
            maximum_denominator,
            maximum_interaction,
            protocol_degree.quotientExpansionBits(maximum_direct),
            protocol_degree.quotientExpansionBits(maximum_interaction),
        },
    );
    try writer.writeAll(
        "Degree columns are: direct constraint, lookup numerator, relation " ++
            "denominator, and final interaction recurrence. Expansion is the " ++
            "additional log-degree capacity required after division by the " ++
            "trace-domain vanishing polynomial. Shifted-row masks remain degree " ++
            "one; `is_first` is the degree-one boundary selector.\n\n" ++
            "This is a compatibility report, not a production activation receipt. " ++
            "The typed logical manifest does not yet identify the external lookup " ++
            "record or physical layout.\n",
    );
}

fn writeDependencies(writer: anytype, counts: [relation.schemas.len]u16) !void {
    var first = true;
    for (relation.schemas, counts) |schema, dependency_count| {
        if (dependency_count == 0) continue;
        if (!first) try writer.writeAll(", ");
        try writer.print("`{s}`×{d}", .{
            @tagName(schema.domain),
            dependency_count,
        });
        first = false;
    }
    if (first) try writer.writeAll("—");
}

fn count(value: usize) error{CountOverflow}!u32 {
    return std.math.cast(u32, value) orelse error.CountOverflow;
}

const Degree = protocol_degree.Degree;
