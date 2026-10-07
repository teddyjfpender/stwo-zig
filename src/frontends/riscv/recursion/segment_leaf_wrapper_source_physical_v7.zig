//! Corrected physical row-39 source under the verifier-owned V7 template.
//! The extra verifier-input consumption balances row 5's native claim fan-out.
//! This is a single-row bridge, not a complete wrapper proof.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const roster = @import("air/segment_leaf_wrapper_roster_direct_v7.zig");
const template = @import("air/segment_leaf_wrapper_template_v7.zig");
const link_mod = @import("ethereum_leaf_link_program_v3.zig");
const air = @import("air/ethereum_leaf_link_source_direct_v6.zig");
const framework = @import("air/framework_interaction.zig");
const relations_mod = @import("air/universal_challenges.zig");
const DomainAudit = @import("air/relation_interaction.zig").DomainAudit;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Claim = struct { claim: QM31, audit: DomainAudit };

pub const Writer = struct {
    allocator: std.mem.Allocator,
    plan: *const roster.Plan,
    rows: []const air.Row,

    /// `rows` are the caller's native-witness values. Every fixed coordinate
    /// is checked against the independently compiled link schedule before any
    /// column is written. The template's fixed digest is checked separately.
    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const roster.Plan,
        link: *const link_mod.ProgramV3,
        rows: []const air.Row,
    ) !Writer {
        try plan.validate();
        try link.validate();
        const placement = plan.placements[39];
        if (!std.mem.eql(u8, &link.schedule_id, &plan.template.v6_template.shape.link_schedule_id) or
            !std.mem.eql(u8, &try template.row39FixedColumnsId(link, placement.geometry.log_size), &plan.template.row39_preprocessed_id) or
            !std.mem.eql(u8, &placement.geometry.semantic_digest, &air.SEMANTIC_DIGEST) or
            rows.len != (@as(usize, 1) << @intCast(placement.geometry.log_size)) or
            link.source_rows.len > rows.len)
            return error.V7SourceTemplateMismatch;
        for (rows, 0..) |row, index| {
            const expected = if (index < link.source_rows.len)
                link.source_rows[index].logical(M31.zero())
            else
                [_]M31{M31.zero()} ** air.LOGICAL_INPUT_COUNT;
            for (row[air.PHYSICAL_MAIN_COLUMN_COUNT..], expected[air.PHYSICAL_MAIN_COLUMN_COUNT..]) |actual, fixed|
                if (!actual.eql(fixed)) return error.V7SourceFixedMismatch;
            if (index >= link.source_rows.len and !row[0].isZero()) return error.V7SourcePaddingMismatch;
        }
        return .{ .allocator = allocator, .plan = plan, .rows = rows };
    }

    pub fn fillPreprocessed(self: *const Writer, tree: [][]M31) !void {
        try self.write(tree, .preprocessed);
    }

    pub fn fillMain(self: *const Writer, tree: [][]M31) !void {
        try self.write(tree, .main);
    }

    pub fn fillInteraction(self: *const Writer, relations: *const relations_mod.UniversalRelations, tree: [][]M31) !Claim {
        try relations.validate();
        var definition = try air.build(self.allocator);
        defer definition.deinit();
        const authenticated = try air.authenticate(&definition);
        var generated = try authenticated.generateInteraction(
            self.allocator,
            &definition.arena,
            air.SEMANTIC_DIGEST,
            definition.events,
            self.rows,
            self.plan.placements[39].geometry.log_size,
            relations,
        );
        defer generated.deinit(self.allocator);
        const claim = generated.claims.total();
        const audit = try authenticated.auditPreparedDomainSums(self.allocator, self.rows, relations, claim);
        const placement = self.plan.placements[39];
        if (generated.columns.len != placement.geometry.interaction_columns)
            return error.V7SourceGeometryMismatch;
        const columns = try sliceColumns(tree, placement.interaction_offset, generated.columns.len, self.rows.len);
        for (generated.columns, columns) |from, to| {
            if (from.len != to.len) return error.V7SourceGeometryMismatch;
            for (to) |value| if (!value.isZero()) return error.V7SourceDestinationNotFresh;
        }
        for (generated.columns, columns) |from, to| @memcpy(to, from);
        return .{ .claim = claim, .audit = audit };
    }

    const Tree = enum { preprocessed, main };

    fn write(self: *const Writer, tree: [][]M31, comptime kind: Tree) !void {
        const placement = self.plan.placements[39];
        const count: usize = if (kind == .preprocessed) air.PREPROCESSED_COLUMN_COUNT else air.PHYSICAL_MAIN_COLUMN_COUNT;
        const expected = if (kind == .preprocessed) placement.geometry.preprocessed_columns else placement.geometry.main_columns;
        if (count != expected) return error.V7SourceGeometryMismatch;
        const offset = if (kind == .preprocessed) placement.preprocessed_offset else placement.main_offset;
        const columns = try sliceColumns(tree, offset, count, self.rows.len);
        for (columns) |column| for (column) |value| if (!value.isZero()) return error.V7SourceDestinationNotFresh;
        const begin: usize = if (kind == .preprocessed) air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
        for (self.rows, 0..) |row, index| {
            const committed = framework.committedRow(index, placement.geometry.log_size);
            for (row[begin..][0..count], columns) |word, column| column[committed] = word;
        }
    }
};

fn sliceColumns(tree: [][]M31, offset: u32, count: usize, size: usize) ![][]M31 {
    if (offset > tree.len or count > tree.len - offset) return error.V7SourceGeometryMismatch;
    const columns = tree[offset..][0..count];
    for (columns) |column| if (column.len != size) return error.V7SourceGeometryMismatch;
    return columns;
}

const TestTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    offset: u32,
    count: usize,

    fn init(allocator: std.mem.Allocator, plan: *const roster.Plan, comptime kind: enum { preprocessed, main, interaction }) !TestTree {
        const placement = plan.placements[39];
        const total = switch (kind) {
            .preprocessed => plan.total_preprocessed_columns,
            .main => plan.total_main_columns,
            .interaction => plan.total_interaction_columns,
        };
        const offset = switch (kind) {
            .preprocessed => placement.preprocessed_offset,
            .main => placement.main_offset,
            .interaction => placement.interaction_offset,
        };
        const count = switch (kind) {
            .preprocessed => placement.geometry.preprocessed_columns,
            .main => placement.geometry.main_columns,
            .interaction => placement.geometry.interaction_columns,
        };
        const columns = try allocator.alloc([]M31, total);
        for (columns) |*column| column.* = @constCast(&.{});
        const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
        for (columns[offset..][0..count]) |*column| {
            column.* = try allocator.alloc(M31, size);
            @memset(column.*, M31.zero());
        }
        return .{ .allocator = allocator, .columns = columns, .offset = offset, .count = count };
    }

    fn deinit(self: *TestTree) void {
        for (self.columns[self.offset..][0..self.count]) |column| self.allocator.free(column);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

test "V7 row39 physical source uses corrected AIR and rejects fixed drift" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const child = @import("tests/ethereum_leaf_child_field_test.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const shape_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const prior = @import("air/segment_leaf_wrapper_template_v6.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const instructions = try @import("transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child.components,
        &child.infra,
        false,
    );
    const profile = try prior.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const key = try template.TemplateManifestV7.build(
        allocator,
        &source_catalog,
        shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 },
        &child.components,
        &child.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
    );
    const plan = try roster.Plan.fromTemplate(&key);
    try std.testing.expectEqualDeep(air.SEMANTIC_DIGEST, plan.placements[39].geometry.semantic_digest);
    var link = try link_mod.ProgramV3.init(allocator);
    defer link.deinit();
    const size = @as(usize, 1) << @intCast(plan.placements[39].geometry.log_size);
    const rows = try allocator.alloc(air.Row, size);
    defer allocator.free(rows);
    @memset(rows, [_]M31{M31.zero()} ** air.LOGICAL_INPUT_COUNT);
    for (link.source_rows, 0..) |schedule, index|
        rows[index] = schedule.logical(M31.fromCanonical(@intCast(index + 1)));
    const writer = try Writer.init(allocator, &plan, &link, rows);
    const challenges = relations_mod.UniversalRelations.dummy();
    var pp = try TestTree.init(allocator, &plan, .preprocessed);
    defer pp.deinit();
    var main = try TestTree.init(allocator, &plan, .main);
    defer main.deinit();
    var interaction = try TestTree.init(allocator, &plan, .interaction);
    defer interaction.deinit();
    try writer.fillPreprocessed(pp.columns);
    try writer.fillMain(main.columns);
    try std.testing.expectEqual(rows[0][0], main.columns[main.offset][framework.committedRow(0, plan.placements[39].geometry.log_size)]);
    const claim = try writer.fillInteraction(&challenges, interaction.columns);
    try std.testing.expect(claim.claim.eql(claim.audit.total));
    try std.testing.expect(!claim.audit.values[25].isZero());
    try std.testing.expectError(error.V7SourceDestinationNotFresh, writer.fillInteraction(&challenges, interaction.columns));
    try std.testing.expectError(error.V7SourceDestinationNotFresh, writer.fillMain(main.columns));
    rows[0][air.PHYSICAL_MAIN_COLUMN_COUNT] = M31.zero();
    try std.testing.expectError(error.V7SourceFixedMismatch, Writer.init(allocator, &plan, &link, rows));
    rows[0] = link.source_rows[0].logical(M31.one());
    var forged = key;
    forged.row39_preprocessed_id[0] ^= 1;
    try std.testing.expectError(error.InvalidV7TemplateManifest, forged.validate());
}
