//! Physical and interaction assembly for direct wrapper rows 39–46.
//!
//! The caller supplies native-verifier-owned sources. This module writes the
//! eight typed rows into the final PlanV4 trees under one relation bundle and
//! returns independently audited sums. It does not publish a wrapper proof.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");
const projection_air = @import("air/ethereum_leaf_link_projection_v1.zig");
const arithmetic_air = @import("air/ethereum_leaf_link_arithmetic_v1.zig");
const words_air = @import("air/transcript_program_v2_field_source_v1.zig");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_relation = @import("air/vm_public_claim_hash_relation.zig");
const tree0_air = @import("air/segment_v2_tree0_field_link_direct_v4.zig");
const program_mod = @import("ethereum_leaf_link_program_v3.zig");
const source_witness = @import("segment_leaf_wrapper_source_projection_direct_v3.zig");
const native_witness = @import("segment_leaf_wrapper_field_witness_v3.zig");
const hash_witness = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const tree0_witness = @import("segment_v2_tree0_field_witness_v3.zig");
const typed_writer = @import("segment_leaf_wrapper_cohort_typed_rows_v4.zig");
const universal = @import("air/universal_challenges.zig");
const relation_interaction = @import("air/relation_interaction.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const FIRST_ROW: usize = 39;
pub const ROW_COUNT: usize = 8;
pub const DomainAudit = relation_interaction.DomainAudit;

/// Materializes the fixed schedule and pads its two variable-length rows.
/// `arithmetic_rows` are produced by the leaf-local arithmetic authority;
/// their four active rows and twelve zero rows are checked by that owner.
pub const Rows = struct {
    allocator: std.mem.Allocator,
    source: []source_air.Row,
    projection: []projection_air.Row,
    arithmetic: *const [16]arithmetic_air.Row,
    native: *const native_witness.NativeV1,
    metadata_hash: *const hash_witness.HashV1,
    link_hash: *const hash_witness.HashV1,

    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        program: *const program_mod.ProgramV3,
        witness: *const source_witness.WitnessV3,
        arithmetic: *const [16]arithmetic_air.Row,
        native: *const native_witness.NativeV1,
        metadata_hash: *const hash_witness.HashV1,
        link_hash: *const hash_witness.HashV1,
    ) !Rows {
        try plan.validate();
        try program.validate();
        if (!std.meta.eql(plan.program_schedule_id, program.schedule_id) or
            plan.shape.program_words != native.program_words.word_count or
            native.program_words.scope != words_air.PROGRAM_WORD_SCOPE or
            native.program_hash.scope != words_air.PROGRAM_WORD_SCOPE or
            native.program_hash.word_count != native.program_words.word_count or
            witness.source_values.len != program.source_rows.len or
            witness.projection_values.len != program.projection_rows.len or
            metadata_hash.log_size != plan.placements[45].?.geometry.log_size or
            link_hash.log_size != plan.placements[46].?.geometry.log_size)
            return error.InvalidDirectLeafRows;
        const source_size = @as(usize, 1) << @intCast(plan.placements[39].?.geometry.log_size);
        const projection_size = @as(usize, 1) << @intCast(plan.placements[40].?.geometry.log_size);
        if (program.source_rows.len > source_size or program.projection_rows.len > projection_size)
            return error.InvalidDirectLeafRows;
        const source = try allocator.alloc(source_air.Row, source_size);
        errdefer allocator.free(source);
        const projection = try allocator.alloc(projection_air.Row, projection_size);
        errdefer allocator.free(projection);
        @memset(source, [_]M31{M31.zero()} ** source_air.LOGICAL_INPUT_COUNT);
        @memset(projection, [_]M31{M31.zero()} ** projection_air.LOGICAL_INPUT_COUNT);
        for (0..program.source_rows.len) |index| source[index] = try witness.sourceRow(program, index);
        for (0..program.projection_rows.len) |index| projection[index] = try witness.projectionRow(program, index);
        return .{ .allocator = allocator, .source = source, .projection = projection, .arithmetic = arithmetic, .native = native, .metadata_hash = metadata_hash, .link_hash = link_hash };
    }

    pub fn deinit(self: *Rows) void {
        self.allocator.free(self.projection);
        self.allocator.free(self.source);
        self.* = undefined;
    }

    pub fn fillPreprocessed(self: *const Rows, plan: *const plan_mod.Plan, columns: [][]M31) !void {
        try typed_writer.fillPreprocessed(source_air, plan, .link_source, self.source, columns);
        try typed_writer.fillPreprocessed(projection_air, plan, .link_projection, self.projection, columns);
        try typed_writer.fillPreprocessed(arithmetic_air, plan, .link_arithmetic, self.arithmetic, columns);
        try typed_writer.fillPreprocessed(words_air, plan, .program_words, self.native.program_words.rows, columns);
        try typed_writer.fillHashPreprocessed(plan, .program_hash, &self.native.program_hash, columns);
        try typed_writer.fillPreprocessed(tree0_air, plan, .tree0_field, &self.native.tree0_link.rows, columns);
        try typed_writer.fillHashPreprocessed(plan, .metadata_hash, self.metadata_hash, columns);
        try typed_writer.fillHashPreprocessed(plan, .link_hash, self.link_hash, columns);
    }

    pub fn fillMain(self: *const Rows, plan: *const plan_mod.Plan, columns: [][]M31) !void {
        try typed_writer.fillMain(source_air, plan, .link_source, self.source, columns);
        try typed_writer.fillMain(projection_air, plan, .link_projection, self.projection, columns);
        try typed_writer.fillMain(arithmetic_air, plan, .link_arithmetic, self.arithmetic, columns);
        try typed_writer.fillMain(words_air, plan, .program_words, self.native.program_words.rows, columns);
        try typed_writer.fillHashMain(plan, .program_hash, &self.native.program_hash, columns);
        try typed_writer.fillMain(tree0_air, plan, .tree0_field, &self.native.tree0_link.rows, columns);
        try typed_writer.fillHashMain(plan, .metadata_hash, self.metadata_hash, columns);
        try typed_writer.fillHashMain(plan, .link_hash, self.link_hash, columns);
    }

    /// Generates and writes all eight LogUp components under exactly one
    /// caller-provided relation draw. Each claim is cold-audited by domain.
    pub fn fillInteraction(
        self: *const Rows,
        plan: *const plan_mod.Plan,
        relations: *const universal.UniversalRelations,
        columns: [][]M31,
    ) !AuditedClaims {
        try relations.validate();
        var result = AuditedClaims{
            .claims = @splat(QM31.zero()),
            .audits = @splat(emptyAudit()),
        };
        result.set(0, try fillTyped(source_air, self.allocator, plan, .link_source, self.source, source_air.SEMANTIC_DIGEST, relations, columns));
        result.set(1, try fillTyped(projection_air, self.allocator, plan, .link_projection, self.projection, projection_air.SEMANTIC_DIGEST, relations, columns));
        result.set(2, try fillTyped(arithmetic_air, self.allocator, plan, .link_arithmetic, self.arithmetic, arithmetic_air.SEMANTIC_DIGEST, relations, columns));
        result.set(3, try fillTyped(words_air, self.allocator, plan, .program_words, self.native.program_words.rows, words_air.SEMANTIC_DIGEST, relations, columns));
        result.set(4, try fillHash(self.allocator, plan, .program_hash, &self.native.program_hash, relations, columns));
        result.set(5, try fillTyped(tree0_air, self.allocator, plan, .tree0_field, &self.native.tree0_link.rows, tree0_air.SEMANTIC_DIGEST, relations, columns));
        result.set(6, try fillHash(self.allocator, plan, .metadata_hash, self.metadata_hash, relations, columns));
        result.set(7, try fillHash(self.allocator, plan, .link_hash, self.link_hash, relations, columns));
        return result;
    }
};

pub const AuditedClaims = struct {
    claims: [ROW_COUNT]QM31,
    audits: [ROW_COUNT]DomainAudit,

    fn set(self: *AuditedClaims, index: usize, value: ClaimAudit) void {
        self.claims[index] = value.claim;
        self.audits[index] = value.audit;
    }
};

const ClaimAudit = struct { claim: QM31, audit: DomainAudit };

fn fillTyped(
    comptime Air: type,
    allocator: std.mem.Allocator,
    plan: *const plan_mod.Plan,
    key: plan_mod.ComponentKey,
    rows: []const Air.Row,
    digest: [32]u8,
    relations: *const universal.UniversalRelations,
    columns: [][]M31,
) !ClaimAudit {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const authenticated = try Air.authenticate(&definition);
    var generated = try authenticated.generateInteraction(
        allocator,
        &definition.arena,
        digest,
        definition.events,
        rows,
        (try plan.placement(key)).geometry.log_size,
        relations,
    );
    defer generated.deinit(allocator);
    const claim = generated.claims.total();
    const audit = try authenticated.auditPreparedDomainSums(allocator, rows, relations, claim);
    const written = try typed_writer.fillInteraction(plan, key, &generated, columns);
    if (!claim.eql(written)) return error.DirectLeafClaimMismatch;
    return .{ .claim = claim, .audit = audit };
}

fn fillHash(
    allocator: std.mem.Allocator,
    plan: *const plan_mod.Plan,
    key: plan_mod.ComponentKey,
    witness: *const hash_witness.HashV1,
    relations: *const universal.UniversalRelations,
    columns: [][]M31,
) !ClaimAudit {
    var generated = try witness.generateInteraction(allocator, relations);
    defer generated.deinit(allocator);
    const claim = generated.claims.total();
    var definition = try hash_air.build(allocator);
    defer definition.deinit();
    const authenticated = try hash_relation.authenticate(&definition);
    const size = @as(usize, 1) << @intCast(witness.log_size);
    const rows = try allocator.alloc(hash_relation.Row, size);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| row.* = if (index < witness.main.len)
        try witness.logicalRow(index)
    else
        [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT;
    const audit = try authenticated.auditPreparedDomainSums(allocator, rows, relations, claim);
    const written = try typed_writer.fillInteraction(plan, key, &generated, columns);
    if (!claim.eql(written)) return error.DirectLeafClaimMismatch;
    return .{ .claim = claim, .audit = audit };
}

fn emptyAudit() DomainAudit {
    return .{ .values = @splat(QM31.zero()), .total = QM31.zero(), .logical_rows = 0, .event_terms = 0 };
}

test "direct appended ProgramV2 rows write and audit under one relation draw" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const field_program = @import("transcript_program_v2_field_authority_v1.zig");
    const channel = @import("poseidon2_channel.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    const plan = try plan_mod.Plan.build(allocator, &base, &program, .{
        .program_words = 100,
        .base_poseidon_calls = 1193,
    });
    const columns = try allocator.alloc([]M31, plan.total_interaction_columns);
    defer allocator.free(columns);
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const size = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (columns[item.interaction_offset..][0..item.geometry.interaction_columns]) |*column| {
            column.* = try allocator.alloc(M31, size);
            @memset(column.*, M31.zero());
        }
    }
    defer for (columns) |column| allocator.free(column);
    const raw = [_]M31{M31.fromCanonical(17)} ** 100;
    var words = try @import("transcript_program_v2_field_word_witness_v1.zig").WordsV1.init(
        allocator,
        &raw,
        words_air.PROGRAM_WORD_SCOPE,
    );
    defer words.deinit();
    var hash = try hash_witness.HashV1.init(
        allocator,
        &raw,
        field_program.PROGRAM_DOMAIN,
        words_air.PROGRAM_WORD_SCOPE,
        source_air.PROGRAM_AUTHORITY_KIND,
        hash_witness.PROGRAM_STEP_BASE,
        channel.hashCanonicalWords(&raw, field_program.PROGRAM_DOMAIN),
    );
    defer hash.deinit();
    const relations = universal.UniversalRelations.dummy();
    const word_claim = try fillTyped(
        words_air,
        allocator,
        &plan,
        .program_words,
        words.rows,
        words_air.SEMANTIC_DIGEST,
        &relations,
        columns,
    );
    const hash_claim = try fillHash(allocator, &plan, .program_hash, &hash, &relations, columns);
    try std.testing.expect(word_claim.claim.eql(word_claim.audit.total));
    try std.testing.expect(hash_claim.claim.eql(hash_claim.audit.total));
    try std.testing.expectError(
        error.DirectTypedRowDestinationNotFresh,
        fillTyped(words_air, allocator, &plan, .program_words, words.rows, words_air.SEMANTIC_DIGEST, &relations, columns),
    );
    words.rows[0][0] = M31.fromCanonical(18);
    try std.testing.expectError(
        error.InvalidFieldWordWitness,
        words.validateAgainst(&raw, words_air.PROGRAM_WORD_SCOPE),
    );
}

test "direct appended rows materialize all eight physical placements" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const metadata_mod = @import("segment_leaf_local_authority_v3.zig");
    const link_mod = @import("segment_leaf_local_verified_link_v3.zig");
    const channel = @import("poseidon2_channel.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    const plan = try plan_mod.Plan.build(allocator, &base, &program, .{
        .program_words = 100,
        .base_poseidon_calls = 1193,
    });
    const source_values = try allocator.alloc(M31, program.source_rows.len);
    defer allocator.free(source_values);
    const projection_values = try allocator.alloc(M31, program.projection_rows.len);
    defer allocator.free(projection_values);
    @memset(source_values, M31.zero());
    @memset(projection_values, M31.zero());
    var witness = source_witness.WitnessV3{
        .allocator = allocator,
        .source_values = source_values,
        .projection_values = projection_values,
    };
    const word_values = [_]M31{M31.fromCanonical(17)} ** 100;
    var words = try @import("transcript_program_v2_field_word_witness_v1.zig").WordsV1.init(
        allocator,
        &word_values,
        words_air.PROGRAM_WORD_SCOPE,
    );
    defer words.deinit();
    var program_hash = try hash_witness.HashV1.init(
        allocator,
        &word_values,
        @import("transcript_program_v2_field_authority_v1.zig").PROGRAM_DOMAIN,
        words_air.PROGRAM_WORD_SCOPE,
        source_air.PROGRAM_AUTHORITY_KIND,
        hash_witness.PROGRAM_STEP_BASE,
        channel.hashCanonicalWords(&word_values, @import("transcript_program_v2_field_authority_v1.zig").PROGRAM_DOMAIN),
    );
    defer program_hash.deinit();
    const metadata_values = [_]M31{M31.zero()} ** metadata_mod.METADATA_IDENTITY_WORDS;
    const link_values = [_]M31{M31.zero()} ** link_mod.IDENTITY_WORDS;
    var metadata_hash = try hash_witness.HashV1.init(
        allocator,
        &metadata_values,
        metadata_mod.METADATA_ID_DOMAIN,
        source_air.METADATA_SCOPE,
        source_air.METADATA_DIGEST_KIND,
        @import("ethereum_leaf_link_program_v1.zig").METADATA_HASH_STEP_BASE,
        channel.hashCanonicalWords(&metadata_values, metadata_mod.METADATA_ID_DOMAIN),
    );
    defer metadata_hash.deinit();
    var link_hash = try hash_witness.HashV1.init(
        allocator,
        &link_values,
        link_mod.IDENTITY_DOMAIN,
        source_air.LINK_SCOPE,
        source_air.LINK_DIGEST_KIND,
        @import("ethereum_leaf_link_program_v1.zig").LINK_HASH_STEP_BASE,
        channel.hashCanonicalWords(&link_values, link_mod.IDENTITY_DOMAIN),
    );
    defer link_hash.deinit();
    const zero_tree = [_]tree0_air.Row{[_]M31{M31.zero()} ** tree0_air.LOGICAL_INPUT_COUNT} ** tree0_witness.TRACE_SIZE;
    var native = native_witness.NativeV1{
        .program = undefined,
        .program_words = words,
        .program_hash = program_hash,
        .tree0_root = @splat(0),
        .tree0_link = .{
            .native_root = @splat(0),
            .transcript_root = @splat(0),
            .transcript_hash_id = 0,
            .rows = zero_tree,
        },
    };
    const zero_arithmetic = [_]arithmetic_air.Row{[_]M31{M31.zero()} ** arithmetic_air.LOGICAL_INPUT_COUNT} ** 16;
    var rows = try Rows.init(allocator, &plan, &program, &witness, &zero_arithmetic, &native, &metadata_hash, &link_hash);
    defer rows.deinit();
    const pp = try allocateTree(allocator, &plan, .preprocessed);
    defer freeTree(allocator, pp);
    const main = try allocateTree(allocator, &plan, .main);
    defer freeTree(allocator, main);
    const interaction = try allocateTree(allocator, &plan, .interaction);
    defer freeTree(allocator, interaction);
    try rows.fillPreprocessed(&plan, pp);
    try rows.fillMain(&plan, main);
    const relations = universal.UniversalRelations.dummy();
    const sums = try rows.fillInteraction(&plan, &relations, interaction);
    for (sums.claims, sums.audits) |claim, audit| try std.testing.expect(claim.eql(audit.total));
    witness.source_values = witness.source_values[0 .. witness.source_values.len - 1];
    try std.testing.expectError(error.InvalidDirectLeafRows, Rows.init(allocator, &plan, &program, &witness, &zero_arithmetic, &native, &metadata_hash, &link_hash));
}

const Tree = enum { preprocessed, main, interaction };

fn allocateTree(allocator: std.mem.Allocator, plan: *const plan_mod.Plan, tree: Tree) ![][]M31 {
    const count = switch (tree) {
        .preprocessed => plan.total_preprocessed_columns,
        .main => plan.total_main_columns,
        .interaction => plan.total_interaction_columns,
    };
    const columns = try allocator.alloc([]M31, count);
    var written: usize = 0;
    errdefer {
        for (columns[0..written]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const offset = switch (tree) {
            .preprocessed => item.preprocessed_offset,
            .main => item.main_offset,
            .interaction => item.interaction_offset,
        };
        const n = switch (tree) {
            .preprocessed => item.geometry.preprocessed_columns,
            .main => item.geometry.main_columns,
            .interaction => item.geometry.interaction_columns,
        };
        if (written != offset) return error.InvalidDirectLeafRows;
        const size = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (columns[offset..][0..n]) |*column| {
            column.* = try allocator.alloc(M31, size);
            @memset(column.*, M31.zero());
            written += 1;
        }
    }
    return columns;
}

fn freeTree(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
