//! Physical V7 row-5/row-42 bridge under a verifier-compiled template key.
//! This writes only the two changed rows. It does not admit a 50-row proof.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const roster = @import("air/segment_leaf_wrapper_roster_direct_v7.zig");
const template_mod = @import("air/segment_leaf_wrapper_template_v7.zig");
const fixed5_mod = @import("segment_leaf_template_payload_fixed_v7.zig");
const halves = @import("segment_leaf_wrapper_row5_halves_v7.zig");
const payload_base = @import("air/transcript_payload_relation.zig");
const payload = @import("air/transcript_payload_direct_v7.zig");
const words_mod = @import("transcript_program_v2_template_words_v6.zig");
const program = @import("air/transcript_program_v2_field_bridge_v6.zig");
const framework = @import("air/framework_interaction.zig");
const relations_mod = @import("air/universal_challenges.zig");
const DomainAudit = @import("air/relation_interaction.zig").DomainAudit;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ChangedClaim = struct { claim: QM31, audit: DomainAudit };
pub const Claims = struct { row5: ChangedClaim, row42: ChangedClaim };

pub const Writer = struct {
    allocator: std.mem.Allocator,
    plan: *const roster.Plan,
    fixed5: *const fixed5_mod.Template,
    row5: halves.Schedule,
    row42_fixed: program.FixedSchedule,
    row42: []program.Row,

    /// The only dynamic inputs are the native transcript rows and canonical
    /// ProgramV2 words. Fixed columns and geometry must match the V7 key.
    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const roster.Plan,
        fixed5: *const fixed5_mod.Template,
        words: *const words_mod.Template,
        selected_native_payload: []const payload_base.Row,
        native_program_words: []const M31,
    ) !Writer {
        try plan.validate();
        try words.checkCanonicalWords(native_program_words);
        if (native_program_words.len != words.words.len or
            fixed5.rows.len != plan.template.row5_active_rows or
            !std.mem.eql(u8, &try template_mod.row5FixedColumnsId(fixed5, plan.placements[5].geometry.log_size), &plan.template.row5_preprocessed_id))
            return error.V7PhysicalTemplateMismatch;
        const row42_fixed = try program.FixedSchedule.initFromTemplate(words.words);
        if (row42_fixed.log_size != plan.placements[42].geometry.log_size or
            !std.mem.eql(u8, &try template_mod.row42FixedColumnsId(row42_fixed), &plan.template.row42_preprocessed_id))
            return error.V7PhysicalTemplateMismatch;
        var row5 = try halves.Schedule.init(allocator, selected_native_payload, native_program_words[10..18]);
        errdefer row5.deinit();
        if (row5.rows.len != fixed5.rows.len or row5.rows.len > capacity(plan, 5))
            return error.V7PhysicalRow5GeometryMismatch;
        for (row5.rows, fixed5.rows) |actual, expected| {
            const begin = payload.PHYSICAL_MAIN_COLUMN_COUNT;
            for (actual[begin..][0..payload.PREPROCESSED_COLUMN_COUNT], expected[begin..][0..payload.PREPROCESSED_COLUMN_COUNT]) |a, b|
                if (!a.eql(b)) return error.V7PhysicalFixedSourceMismatch;
        }
        const row42 = try allocator.alloc(program.Row, row42_fixed.rowCapacity());
        errdefer allocator.free(row42);
        for (row42, 0..) |*row, index| {
            const value = if (index < native_program_words.len) native_program_words[index] else M31.zero();
            row.* = try row42_fixed.logicalRow(index, value);
        }
        return .{
            .allocator = allocator,
            .plan = plan,
            .fixed5 = fixed5,
            .row5 = row5,
            .row42_fixed = row42_fixed,
            .row42 = row42,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.row5.deinit();
        self.allocator.free(self.row42);
        self.* = undefined;
    }

    pub fn fillPreprocessed(self: *const Writer, tree: [][]M31) !void {
        const p5 = self.plan.placements[5];
        const p42 = self.plan.placements[42];
        const columns5 = try sliceColumns(tree, p5.preprocessed_offset, payload.PREPROCESSED_COLUMN_COUNT, capacity(self.plan, 5));
        try self.fixed5.writeInto(p5.geometry.log_size, columns5);
        try writeTyped(program, self.plan, 42, self.row42, tree, .preprocessed);
        if (p42.geometry.preprocessed_columns != program.PREPROCESSED_COLUMN_COUNT)
            return error.V7PhysicalGeometryMismatch;
    }

    pub fn fillMain(self: *const Writer, tree: [][]M31) !void {
        try writeTyped(payload, self.plan, 5, self.row5.rows, tree, .main);
        try writeTyped(program, self.plan, 42, self.row42, tree, .main);
    }

    pub fn fillInteraction(self: *const Writer, relations: *const relations_mod.UniversalRelations, tree: [][]M31) !Claims {
        try relations.validate();
        return .{
            .row5 = try interactTyped(payload, self.allocator, self.plan, 5, self.row5.rows, relations, tree),
            .row42 = try interactTyped(program, self.allocator, self.plan, 42, self.row42, relations, tree),
        };
    }

    /// Audits the actual V7 physical AIR entries for the native half-word
    /// scope. A zero result is necessary but not sufficient for a wrapper
    /// proof: the other relation scopes and detached verifier remain separate.
    pub fn wireHalfResidual(self: *const Writer, relations: *const relations_mod.UniversalRelations) !QM31 {
        try relations.validate();
        const source_claim = try scopedHalfClaim(payload, self.allocator, self.row5.rows, relations);
        const consumer_claim = try scopedHalfClaim(program, self.allocator, self.row42, relations);
        return source_claim.add(consumer_claim);
    }
};

const Tree = enum { preprocessed, main };

fn capacity(plan: *const roster.Plan, row: usize) usize {
    return @as(usize, 1) << @intCast(plan.placements[row].geometry.log_size);
}

fn sliceColumns(tree: [][]M31, offset: u32, count: usize, size: usize) ![][]M31 {
    if (offset > tree.len or count > tree.len - offset) return error.V7PhysicalGeometryMismatch;
    const columns = tree[offset..][0..count];
    for (columns) |column| if (column.len != size) return error.V7PhysicalGeometryMismatch;
    return columns;
}

fn writeTyped(comptime Air: type, plan: *const roster.Plan, row: usize, rows: []const Air.Row, tree: [][]M31, comptime kind: Tree) !void {
    const placement = plan.placements[row];
    const count = if (kind == .preprocessed) Air.PREPROCESSED_COLUMN_COUNT else Air.PHYSICAL_MAIN_COLUMN_COUNT;
    const expected = if (kind == .preprocessed) placement.geometry.preprocessed_columns else placement.geometry.main_columns;
    if (count != expected or rows.len > capacity(plan, row)) return error.V7PhysicalGeometryMismatch;
    const offset = if (kind == .preprocessed) placement.preprocessed_offset else placement.main_offset;
    const columns = try sliceColumns(tree, offset, count, capacity(plan, row));
    for (columns) |column| for (column) |value| if (!value.isZero()) return error.V7PhysicalDestinationNotFresh;
    const begin: usize = if (kind == .preprocessed) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
    for (rows, 0..) |value, logical| {
        const committed = framework.committedRow(logical, placement.geometry.log_size);
        for (value[begin..][0..count], columns) |word, column| column[committed] = word;
    }
}

fn interactTyped(comptime Air: type, allocator: std.mem.Allocator, plan: *const roster.Plan, row: usize, rows: []const Air.Row, relations: *const relations_mod.UniversalRelations, tree: [][]M31) !ChangedClaim {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const authenticated = try Air.authenticate(&definition);
    const events = if (comptime @hasField(Air.Definition, "events")) definition.events else Air.events;
    var generated = try authenticated.generateInteraction(allocator, &definition.arena, Air.SEMANTIC_DIGEST, events, rows, plan.placements[row].geometry.log_size, relations);
    defer generated.deinit(allocator);
    const claim = generated.claims.total();
    const audit = try authenticated.auditPreparedDomainSums(allocator, rows, relations, claim);
    const placement = plan.placements[row];
    if (generated.columns.len != placement.geometry.interaction_columns) return error.V7PhysicalGeometryMismatch;
    const columns = try sliceColumns(tree, placement.interaction_offset, generated.columns.len, capacity(plan, row));
    for (generated.columns, columns) |from, to| {
        if (from.len != to.len) return error.V7PhysicalGeometryMismatch;
        for (to) |value| if (!value.isZero()) return error.V7PhysicalDestinationNotFresh;
    }
    for (generated.columns, columns) |from, to| @memcpy(to, from);
    return .{ .claim = claim, .audit = audit };
}

test "V7 physical row5 and row42 claims close native half tuples under the template key" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const shape_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const prior = @import("air/segment_leaf_wrapper_template_v6.zig");
    const link_mod = @import("ethereum_leaf_link_program_v3.zig");
    const base = @import("air/transcript_payload.zig");
    const relation = @import("../air/lang/relation.zig");
    const ledger_mod = @import("air/relation_interaction.zig");
    const range_v7 = @import("segment_leaf_wrapper_range_provider_v7.zig");
    const range_bridge = @import("air/range_check_8_8_bridge.zig");
    const counter_mod = @import("../air/lookups/tables/counter.zig");
    const arithmetic = @import("air/ethereum_leaf_link_arithmetic_v1.zig");
    const arithmetic_witness = @import("air/ethereum_leaf_link_arithmetic_witness_v1.zig");
    const shared_mod = @import("air/universal_provider_relations.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const instructions = try @import("transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const shape = shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    const profile = try prior.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const key = try template_mod.TemplateManifestV7.build(
        allocator,
        &source_catalog,
        shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
    );
    const plan = try roster.Plan.fromTemplate(&key);
    var link = try link_mod.ProgramV3.init(allocator);
    defer link.deinit();
    var fixed5 = try fixed5_mod.Template.initFromShape(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
        &link,
    );
    defer fixed5.deinit();
    var words = try words_mod.Template.initFromShape(
        allocator,
        &plans.vm,
        @import("segment_v3_production_security_policy.zig").REQUIRED_PCS_CONFIG,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    defer words.deinit();
    const native_rows = try allocator.alloc(payload_base.Row, fixed5.rows.len);
    defer allocator.free(native_rows);
    const mask_at = base.PHYSICAL_MAIN_COLUMN_COUNT + base.PREPROCESSED_COLUMN_COUNT;
    for (native_rows, fixed5.rows) |*out, row| {
        @memcpy(out[0..mask_at], row[0..mask_at]);
        @memcpy(out[mask_at..], row[mask_at + 1 ..]);
    }
    var physical = try Writer.init(allocator, &plan, &fixed5, &words, native_rows, words.words);
    defer physical.deinit();
    var counter = try counter_mod.Counter.init(allocator, range_bridge.TABLE_KIND);
    defer counter.deinit(allocator);
    var native_range = try range_bridge.PreparedBatch.init(allocator, &counter);
    defer native_range.deinit();
    var arithmetic_rows = [_]arithmetic.Row{[_]M31{M31.zero()} ** arithmetic.LOGICAL_INPUT_COUNT} ** 16;
    arithmetic_rows[0] = try arithmetic_witness.logicalRow(.entry_root, 7, false, 0, 0);
    arithmetic_rows[1] = try arithmetic_witness.logicalRow(.exit_root, 9, false, 0, 0);
    arithmetic_rows[2] = try arithmetic_witness.logicalRow(.completion, 0, true, 0, 0);
    arithmetic_rows[3] = try arithmetic_witness.logicalRow(.position, 0, false, 100, 11);
    var prior_range = try @import("segment_leaf_wrapper_range_provider_direct_v4.zig").Provider.init(allocator, &native_range, &arithmetic_rows);
    defer prior_range.deinit();
    var wire_rows: [range_v7.WIRE_ROW_COUNT]program.Row = undefined;
    @memcpy(&wire_rows, physical.row42[10..18]);
    var range = try range_v7.Provider.init(allocator, &native_range, &arithmetic_rows, &wire_rows, words.words[10..18]);
    defer range.deinit();
    var pp = try SparseTree.init(allocator, &plan, .preprocessed);
    defer pp.deinit();
    var main = try SparseTree.init(allocator, &plan, .main);
    defer main.deinit();
    var interaction = try SparseTree.init(allocator, &plan, .interaction);
    defer interaction.deinit();
    try physical.fillPreprocessed(pp.columns);
    try physical.fillMain(main.columns);
    try range.fillMain(&plan, main.columns);
    const challenges = relations_mod.UniversalRelations.dummy();
    const provider_relations = try shared_mod.SharedProviderRelations.init(&challenges);
    const claims = try physical.fillInteraction(&challenges, interaction.columns);
    const row35 = try range.fillInteraction(&plan, &provider_relations, interaction.columns);
    const half_domain = relation.Domain.recursion_vm_public_claim_word;
    // NPH2 shares domain 30 with unrelated ProgramV2 and native claims. Audit
    // the scoped physical subclaim rather than asserting the whole domain zero.
    const scoped5 = try scopedHalfClaim(payload, allocator, physical.row5.rows, &challenges);
    const scoped42 = try scopedHalfClaim(program, allocator, physical.row42, &challenges);
    try std.testing.expect(scoped5.add(scoped42).isZero());
    try std.testing.expect(claims.row5.audit.total.eql(claims.row5.claim));
    try std.testing.expect(claims.row42.audit.total.eql(claims.row42.claim));
    try std.testing.expect(row35.audit.total.eql(row35.claim));
    try std.testing.expectEqual(range_v7.WIRE_REQUEST_COUNT, range.wire_requests);
    var prior_generated = try prior_range.batch.generateNativeInteraction(allocator, &provider_relations.native);
    defer prior_generated.deinit(allocator);
    const range_claim = try scopedDomainClaim(program, allocator, physical.row42[10..18], &challenges, .range_check_8_8);
    try std.testing.expect(row35.claim.sub(prior_generated.claim).add(range_claim).isZero());
    var ledger = ledger_mod.TupleLedger.init(allocator);
    defer ledger.deinit();
    const mask = @as(u64, 1) << @intFromEnum(half_domain);
    var payload_definition = try payload.build(allocator);
    defer payload_definition.deinit();
    const payload_plan = try payload.authenticate(&payload_definition);
    try payload_plan.appendPreparedTupleContributions(&ledger, 5, physical.row5.rows, mask);
    var program_definition = try program.build(allocator);
    defer program_definition.deinit();
    const program_plan = try program.authenticate(&program_definition);
    try program_plan.appendPreparedTupleContributions(&ledger, 42, physical.row42, mask);
    const half_scope = QM31.fromBase(M31.fromCanonical(program.WIRE_HALF_SCOPE));
    var retained: usize = 0;
    for (ledger.contributions.items) |entry| {
        if (entry.domain != half_domain or !entry.tuple_prefix[0].eql(half_scope)) continue;
        ledger.contributions.items[retained] = entry;
        retained += 1;
    }
    ledger.contributions.items = ledger.contributions.items[0..retained];
    const report = ledger.classify();
    try std.testing.expectEqual(@as(usize, 0), report.unmatched_tuple_count);
    try std.testing.expect(report.contribution_count > 0);
    try std.testing.expectError(error.V7PhysicalDestinationNotFresh, physical.fillMain(main.columns));
    var forged_words = try allocator.dupe(M31, words.words);
    defer allocator.free(forged_words);
    forged_words[26] = forged_words[26].add(M31.one());
    try std.testing.expectError(error.ProgramTemplateShapeMismatch, Writer.init(allocator, &plan, &fixed5, &words, native_rows, forged_words));
}

fn scopedHalfClaim(comptime Air: type, allocator: std.mem.Allocator, rows: []const Air.Row, relations: *const relations_mod.UniversalRelations) !QM31 {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const authenticated = try Air.authenticate(&definition);
    const scope = QM31.fromBase(M31.fromCanonical(program.WIRE_HALF_SCOPE));
    var sum = QM31.zero();
    for (rows) |row| for (authenticated.preparedEntries(row)) |entry| {
        if (entry.domain != .recursion_vm_public_claim_word or !entry.values[0].eql(scope)) continue;
        const denominator = try entry.denominator(relations);
        sum = sum.add(entry.numerator.mul(try denominator.inv()));
    };
    return sum;
}

fn scopedDomainClaim(comptime Air: type, allocator: std.mem.Allocator, rows: []const Air.Row, relations: *const relations_mod.UniversalRelations, domain: @import("../air/lang/relation.zig").Domain) !QM31 {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const authenticated = try Air.authenticate(&definition);
    var sum = QM31.zero();
    for (rows) |row| for (authenticated.preparedEntries(row)) |entry| {
        if (entry.domain != domain) continue;
        const denominator = try entry.denominator(relations);
        sum = sum.add(entry.numerator.mul(try denominator.inv()));
    };
    return sum;
}

const SparseTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    allocations: [3][]M31,

    fn init(allocator: std.mem.Allocator, plan: *const roster.Plan, comptime kind: enum { preprocessed, main, interaction }) !SparseTree {
        const count = switch (kind) {
            .preprocessed => plan.total_preprocessed_columns,
            .main => plan.total_main_columns,
            .interaction => plan.total_interaction_columns,
        };
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        @memset(columns, &.{});
        var allocations: [3][]M31 = undefined;
        var written: usize = 0;
        errdefer for (allocations[0..written]) |allocation| allocator.free(allocation);
        inline for (.{ @as(usize, 5), @as(usize, 35), @as(usize, 42) }, 0..) |row, slot| {
            const p = plan.placements[row];
            const offset = switch (kind) {
                .preprocessed => p.preprocessed_offset,
                .main => p.main_offset,
                .interaction => p.interaction_offset,
            };
            const n = switch (kind) {
                .preprocessed => p.geometry.preprocessed_columns,
                .main => p.geometry.main_columns,
                .interaction => p.geometry.interaction_columns,
            };
            const size = capacity(plan, row);
            const backing = try allocator.alloc(M31, n * size);
            @memset(backing, M31.zero());
            allocations[slot] = backing;
            written += 1;
            for (columns[offset..][0..n], 0..) |*column, index| column.* = backing[index * size ..][0..size];
        }
        return .{ .allocator = allocator, .columns = columns, .allocations = allocations };
    }

    fn deinit(self: *SparseTree) void {
        for (self.allocations) |allocation| self.allocator.free(allocation);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};
