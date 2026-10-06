//! Physical row36 Statement replacement for the direct V6 diagnostic.
//! The native writer still owns its one main column. This writer checks that
//! main column, writes the four key-owned columns, and generates interaction.

const std = @import("std");
const core = @import("stwo_core");
const air = @import("air/segment_leaf_statement_source_direct_v6.zig");
const roster = @import("air/segment_leaf_wrapper_roster_direct_v6.zig");
const framework = @import("air/framework_interaction.zig");
const universal = @import("air/universal_challenges.zig");
const relation_interaction = @import("air/relation_interaction.zig");
const link = @import("ethereum_leaf_link_program_v3.zig");
const child = @import("ethereum_leaf_child_field_program_v1.zig");
const native = @import("segment_leaf_outer_air_v2.zig").Statement;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const Claim = struct {
    total: QM31,
    audit: relation_interaction.DomainAudit,
};

pub const Writer = struct {
    plan: *const roster.Plan,
    schedule: *const air.Schedule,

    pub fn init(plan: *const roster.Plan, schedule: *const air.Schedule, program: *const link.ProgramV3, local: *const child.ProgramV1, native_rows: []const native.Row) !Writer {
        try plan.validate();
        try schedule.validateAgainst(program, local, native_rows);
        if (schedule.rows.len > traceSize(plan)) return error.InvalidDirectV6StatementWriter;
        return .{ .plan = plan, .schedule = schedule };
    }

    pub fn validateMain(self: *const Writer, columns: []const []const M31) !void {
        if (columns.len != air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidDirectV6StatementMain;
        const size = traceSize(self.plan);
        for (columns) |column| if (column.len != size) return error.InvalidDirectV6StatementMain;
        for (self.schedule.rows, 0..) |row, logical| {
            const committed = framework.committedRow(logical, self.plan.placements[36].?.geometry.log_size);
            if (!std.meta.eql(columns[0][committed], row[0])) return error.InvalidDirectV6StatementMain;
        }
    }

    pub fn writePreprocessed(self: *const Writer, columns: [][]M31) !void {
        try writePreprocessedRows(self.plan, self.schedule.rows, columns);
    }

    pub fn writeInteraction(self: *const Writer, allocator: std.mem.Allocator, relations: *const universal.UniversalRelations, columns: [][]M31) !Claim {
        return writeInteractionRows(allocator, self.plan, self.schedule.rows, relations, columns);
    }
};

pub fn writePreprocessedRows(plan: *const roster.Plan, rows: []const air.Row, columns: [][]M31) !void {
    try plan.validate();
    const size = traceSize(plan);
    if (rows.len > size or columns.len != air.PREPROCESSED_COLUMN_COUNT)
        return error.InvalidDirectV6StatementColumns;
    for (columns) |column| {
        if (column.len != size) return error.InvalidDirectV6StatementColumns;
        for (column) |value| if (!value.isZero()) return error.DirectV6StatementColumnsNotFresh;
    }
    for (rows, 0..) |row, logical| {
        const committed = framework.committedRow(logical, plan.placements[36].?.geometry.log_size);
        for (row[air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |value, column|
            columns[column][committed] = value;
    }
}

pub fn writeInteractionRows(allocator: std.mem.Allocator, plan: *const roster.Plan, rows: []const air.Row, relations: *const universal.UniversalRelations, columns: [][]M31) !Claim {
    try plan.validate();
    try relations.validate();
    const size = traceSize(plan);
    if (rows.len > size or columns.len != air.INTERACTION_COLUMN_COUNT)
        return error.InvalidDirectV6StatementColumns;
    for (columns) |column| {
        if (column.len != size) return error.InvalidDirectV6StatementColumns;
        for (column) |value| if (!value.isZero()) return error.DirectV6StatementColumnsNotFresh;
    }
    var definition = try air.build(allocator);
    defer definition.deinit();
    const authenticated = try air.authenticate(&definition);
    var generated = try authenticated.generateInteraction(
        allocator,
        &definition.arena,
        air.SEMANTIC_DIGEST,
        .{definition.event},
        rows,
        plan.placements[36].?.geometry.log_size,
        relations,
    );
    defer generated.deinit(allocator);
    if (generated.columns.len != columns.len) return error.InvalidDirectV6StatementColumns;
    const claim = generated.claims.total();
    const audit = try authenticated.auditPreparedDomainSums(allocator, rows, relations, claim);
    for (generated.columns, columns) |from, to| {
        if (from.len != size) return error.InvalidDirectV6StatementColumns;
        @memcpy(to, from);
    }
    return .{ .total = claim, .audit = audit };
}

fn traceSize(plan: *const roster.Plan) usize {
    return @as(usize, 1) << @intCast(plan.placements[36].?.geometry.log_size);
}

test "V6 row36 physical writer binds extra-use column and interaction claim" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const v4 = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const manifest = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try link.ProgramV3.init(allocator);
    defer program.deinit();
    var local = try child.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer local.deinit();
    const shape = v4.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    const plan = try roster.Plan.build(allocator, &manifest, &program, shape, &local, &child_fixture.components, &child_fixture.infra);
    const size = traceSize(&plan);
    const rows = [_]air.Row{air.Row{ M31.fromCanonical(19), M31.one(), M31.fromCanonical(2), M31.fromCanonical(7), M31.fromCanonical(8) }};
    const pp = try allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(pp);
    for (pp) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
    }
    defer for (pp) |column| allocator.free(column);
    try writePreprocessedRows(&plan, &rows, pp);
    try std.testing.expectEqual(@as(u32, 2), pp[1][0].toU32());
    try std.testing.expectError(error.DirectV6StatementColumnsNotFresh, writePreprocessedRows(&plan, &rows, pp));
    const interaction = try allocator.alloc([]M31, air.INTERACTION_COLUMN_COUNT);
    defer allocator.free(interaction);
    for (interaction) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
    }
    defer for (interaction) |column| allocator.free(column);
    const relations = universal.UniversalRelations.dummy();
    const claim = try writeInteractionRows(allocator, &plan, &rows, &relations, interaction);
    try std.testing.expectEqualDeep(claim.total, claim.audit.total);
    try std.testing.expect(!claim.total.isZero());
}
