//! Derives lookup-table counters from the exact opcode columns being committed.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const source_ingest = @import("../air/lookups/tables/source_ingest.zig");
const counter = @import("../air/lookups/tables/counter.zig");
const table_interaction = @import("../air/lookups/tables/interaction.zig");
const table_schema = @import("../air/lookups/tables/schema.zig");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");
const trace = @import("../runner/trace.zig");
const opcode_trace = @import("opcode_trace.zig");

/// Counter-only result for columns generated within the proving transaction.
/// Strict digest-carrying source ingestion remains available in
/// `source_ingest` for caller-owned and formal-audit inputs.
pub const Result = source_ingest.GeneratedCounters;

pub fn ingest(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: *const opcode_trace.Columns,
    options: source_ingest.Options,
) !Result {
    var shard_counts = [_]u32{0} ** trace.N_FAMILIES;
    for (0..statement.n_components) |component_index| {
        const family_index = @intFromEnum(statement.component_descs[component_index].family);
        shard_counts[family_index] += 1;
    }

    var sources: [trace.N_FAMILIES]source_ingest.FamilySource = undefined;
    var shards: [statement_mod.MAX_COMPONENTS]source_ingest.Shard = undefined;
    var column_views: [statement_mod.MAX_COMPONENTS][trace.MAX_FAMILY_COLUMNS][]const M31 = undefined;
    var source_count: usize = 0;
    var shard_offset: usize = 0;
    for (0..trace.N_FAMILIES) |family_index| {
        const count = shard_counts[family_index];
        if (count == 0) continue;
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        const first_shard = shard_offset;
        var ordinal: u32 = 0;
        for (0..statement.n_components) |component_index| {
            const desc = statement.component_descs[component_index];
            if (desc.family != family) continue;
            const component = columns.components[component_index];
            if (component.n_columns != trace.nColumnsForFamily(family) or
                component.n_real_rows != desc.n_rows)
                return error.InvalidShardGeometry;
            for (
                component.columns[0..component.n_columns],
                column_views[shard_offset][0..component.n_columns],
            ) |values, *view| view.* = values;
            shards[shard_offset] = .{
                .ordinal = ordinal,
                .shard_count = count,
                .n_real_rows = component.n_real_rows,
                .committed_columns = column_views[shard_offset][0..component.n_columns],
                .committed_digest = std.mem.zeroes(source_ingest.Digest),
            };
            ordinal += 1;
            shard_offset += 1;
        }
        if (ordinal != count) return error.InvalidShardCount;
        sources[source_count] = .{
            .family = family,
            .shards = shards[first_shard..shard_offset],
        };
        source_count += 1;
    }
    if (shard_offset != statement.n_components) return error.InvalidShardCount;
    return source_ingest.ingestGeneratedCounters(
        allocator,
        sources[0..source_count],
        options,
    );
}

pub fn registerMemoryBoundary(
    counters: *counter.Set,
    rows: []const memory_boundary.Row,
) !void {
    for (rows) |row| try counters.registerList(memory_interaction.entriesFromRow(row));
}

pub fn registerProgram(
    counters: *counter.Set,
    rows: []const program_commitment.Row,
) !void {
    for (rows) |row| try counters.registerList(program_interaction.entriesFromRow(row));
}

test "lookup sources range-check every committed program word address" {
    const allocator = std.testing.allocator;
    const rows = [_]program_commitment.Row{
        .{
            .addr = 0x1000,
            .values = .{ 10, 1, 0, 1 },
            .multiplicity = 3,
            .root = 99,
        },
        .{
            .addr = 0x3fff_fffc,
            .values = .{ 10, 2, 0, 1 },
            .multiplicity = 0,
            .root = 99,
        },
    };
    var counters = try counter.Set.init(allocator);
    defer counters.deinit(allocator);
    try registerProgram(&counters, &rows);
    try std.testing.expect(
        counters.get(.range_check_20).signedTotal().eql(M31.fromU64(2).neg()),
    );
    try std.testing.expect(
        counters.get(.range_check_8_8).signedTotal().eql(M31.fromU64(2).neg()),
    );

    const relations = relations_mod.Relations.dummy();
    inline for (.{ table_schema.Kind.range_check_20, table_schema.Kind.range_check_8_8 }) |kind| {
        var table = try table_interaction.generate(
            allocator,
            counters.get(kind),
            &relations,
        );
        defer table.deinit(allocator);
        const source = try program_interaction.diagnosticSum(
            &rows,
            table_schema.domain(kind),
            &relations,
        );
        try std.testing.expect(source.add(table.claim).isZero());
    }
}

test "lookup sources include both range88 requests from every memory boundary row" {
    const allocator = std.testing.allocator;
    const rows = [_]memory_boundary.Row{.{
        .addr = 0x1000,
        .clock = 7,
        .value = .{ 1, 2, 3, 4 },
        .multiplicity = M31.one().neg(),
        .root = 99,
    }};
    var counters = try counter.Set.init(allocator);
    defer counters.deinit(allocator);
    try registerMemoryBoundary(&counters, &rows);
    try std.testing.expect(
        counters.get(.range_check_8_8).signedTotal().eql(M31.fromU64(2).neg()),
    );

    const relations = relations_mod.Relations.dummy();
    var table = try table_interaction.generate(
        allocator,
        counters.get(.range_check_8_8),
        &relations,
    );
    defer table.deinit(allocator);
    const source = try memory_interaction.diagnosticSum(
        &rows,
        .range_check_8_8,
        &relations,
    );
    try std.testing.expect(source.add(table.claim).isZero());
}
