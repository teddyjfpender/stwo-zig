//! Proof-independent row 41–48 interaction assembly for the V3 leaf wrapper.
//!
//! Rows 39/40 are supplied by their separately owned schedule. This module
//! checks the exact shared word relation before a wrapper transaction may
//! commit these rows. Other domains require the base 39-row provider,
//! statement/transcript sources, range table, and Poseidon caller roster.

const std = @import("std");
const core = @import("stwo_core");
const arithmetic = @import("air/ethereum_leaf_link_arithmetic_v1.zig");
const source = @import("air/ethereum_leaf_link_source_v1.zig");
const projection = @import("air/ethereum_leaf_link_projection_v1.zig");
const words_air = @import("air/transcript_program_v2_field_source_v1.zig");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_relation = @import("air/vm_public_claim_hash_relation.zig");
const tree0_air = @import("air/segment_v2_tree0_field_link_v3.zig");
const words = @import("transcript_program_v2_field_word_witness_v1.zig");
const hash = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const tree0 = @import("segment_v2_tree0_field_witness_v3.zig");
const universal = @import("air/universal_challenges.zig");
const relation = @import("../air/lang/relation.zig");
const interaction = @import("air/relation_interaction.zig");

const M31 = core.fields.m31.M31;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const WORD_DOMAIN = relation.Domain.recursion_vm_public_claim_word;
pub const HASH_STATE_DOMAIN = relation.Domain.recursion_vm_public_claim_hash_state;
pub const CLOSED_DOMAIN_MASK: u64 = (@as(u64, 1) << @intFromEnum(WORD_DOMAIN)) |
    (@as(u64, 1) << @intFromEnum(HASH_STATE_DOMAIN));

/// Every slice is a typed logical row, in canonical 49-row roster order.
/// The caller owns the verifier-derived data and the ProgramV1 schedule.
pub const Rows = struct {
    source_rows: []const source.Row, // 39
    projection_rows: []const projection.Row, // 40
    arithmetic_rows: []const arithmetic.Row, // 41, padded to 16
    program_words: *const words.WordsV1, // 42
    program_hash: *const hash.HashV1, // 43
    provider_words: *const words.WordsV1, // 44
    provider_hash: *const hash.HashV1, // 45
    tree0_rows: *const [tree0.TRACE_SIZE]tree0_air.Row, // 46
    metadata_hash: *const hash.HashV1, // 47
    link_hash: *const hash.HashV1, // 48
};

/// Construct all eight new interaction witnesses with precisely one wrapper
/// challenge bundle. The returned values are not proof acceptance authority.
pub const Interactions = struct {
    arithmetic: arithmetic.Runtime.Interaction,
    program_words: words.Interaction,
    program_hash: hash.Interaction,
    provider_words: words.Interaction,
    provider_hash: hash.Interaction,
    tree0_field: tree0.Interaction,
    metadata_hash: hash.Interaction,
    link_hash: hash.Interaction,

    pub fn deinit(self: *Interactions, allocator: std.mem.Allocator) void {
        self.link_hash.deinit(allocator);
        self.metadata_hash.deinit(allocator);
        self.tree0_field.deinit(allocator);
        self.provider_hash.deinit(allocator);
        self.provider_words.deinit(allocator);
        self.program_hash.deinit(allocator);
        self.program_words.deinit(allocator);
        self.arithmetic.deinit(allocator);
        self.* = undefined;
    }
};

pub fn generateInteractions(
    allocator: std.mem.Allocator,
    rows: Rows,
    relations: *const universal.UniversalRelations,
) !Interactions {
    try validateShape(rows);
    // Exact cold closure is a prerequisite to spending work on LogUp columns.
    _ = try verifyExactLocalClosure(allocator, rows);
    var definition = try arithmetic.build(allocator);
    defer definition.deinit();
    const plan = try arithmetic.authenticate(&definition);
    var arithmetic_interaction = try plan.generateInteraction(
        allocator,
        &definition.arena,
        arithmetic.SEMANTIC_DIGEST,
        definition.events,
        rows.arithmetic_rows,
        4,
        relations,
    );
    errdefer arithmetic_interaction.deinit(allocator);
    var program_words = try rows.program_words.generateInteraction(allocator, relations);
    errdefer program_words.deinit(allocator);
    var program_hash = try rows.program_hash.generateInteraction(allocator, relations);
    errdefer program_hash.deinit(allocator);
    var provider_words = try rows.provider_words.generateInteraction(allocator, relations);
    errdefer provider_words.deinit(allocator);
    var provider_hash = try rows.provider_hash.generateInteraction(allocator, relations);
    errdefer provider_hash.deinit(allocator);
    var tree0_definition = try tree0_air.build(allocator);
    defer tree0_definition.deinit();
    const tree0_plan = try tree0_air.authenticate(&tree0_definition);
    var tree0_field = try tree0_plan.generateInteraction(
        allocator,
        &tree0_definition.arena,
        try tree0_air.computeSemanticDigest(allocator),
        tree0_definition.events,
        rows.tree0_rows,
        tree0.LOG_SIZE,
        relations,
    );
    errdefer tree0_field.deinit(allocator);
    var metadata_hash = try rows.metadata_hash.generateInteraction(allocator, relations);
    errdefer metadata_hash.deinit(allocator);
    const link_hash = try rows.link_hash.generateInteraction(allocator, relations);
    return .{
        .arithmetic = arithmetic_interaction,
        .program_words = program_words,
        .program_hash = program_hash,
        .provider_words = provider_words,
        .provider_hash = provider_hash,
        .tree0_field = tree0_field,
        .metadata_hash = metadata_hash,
        .link_hash = link_hash,
    };
}

/// Audits rows 39–48 under one exact tuple ledger. Only the word and hash
/// state domains close within this slice. Every other unmatched domain is
/// returned as an explicit obligation for the complete 49-row transaction.
pub fn verifyExactLocalClosure(
    allocator: std.mem.Allocator,
    rows: Rows,
) !interaction.TupleClosureReport {
    try validateShape(rows);
    var ledger = interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try appendAll(allocator, &ledger, rows, interaction.allDomainMask());
    const report = ledger.classify();
    if (report.unmatched_by_domain[@intFromEnum(WORD_DOMAIN)] != 0 or
        report.unmatched_by_domain[@intFromEnum(HASH_STATE_DOMAIN)] != 0)
        return error.V3ExtraRowsLocalLookupNotClosed;
    return report;
}

pub fn appendAll(
    allocator: std.mem.Allocator,
    ledger: *interaction.TupleLedger,
    rows: Rows,
    domain_mask: u64,
) !void {
    try validateShape(rows);
    try appendTyped(source, allocator, ledger, 39, rows.source_rows, domain_mask);
    try appendTyped(projection, allocator, ledger, 40, rows.projection_rows, domain_mask);
    try appendTyped(arithmetic, allocator, ledger, 41, rows.arithmetic_rows, domain_mask);
    try appendTyped(words_air, allocator, ledger, 42, rows.program_words.rows, domain_mask);
    try appendHash(allocator, ledger, 43, rows.program_hash, domain_mask);
    try appendTyped(words_air, allocator, ledger, 44, rows.provider_words.rows, domain_mask);
    try appendHash(allocator, ledger, 45, rows.provider_hash, domain_mask);
    try appendTyped(tree0_air, allocator, ledger, 46, rows.tree0_rows, domain_mask);
    try appendHash(allocator, ledger, 47, rows.metadata_hash, domain_mask);
    try appendHash(allocator, ledger, 48, rows.link_hash, domain_mask);
}

fn appendTyped(comptime Air: type, allocator: std.mem.Allocator, ledger: *interaction.TupleLedger, component: u8, rows: []const Air.Row, domain_mask: u64) !void {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const plan = try Air.authenticate(&definition);
    try plan.appendPreparedTupleContributions(ledger, component, rows, domain_mask);
}

fn appendHash(allocator: std.mem.Allocator, ledger: *interaction.TupleLedger, component: u8, witness: *const hash.HashV1, domain_mask: u64) !void {
    var definition = try hash_air.build(allocator);
    defer definition.deinit();
    const plan = try hash_relation.authenticate(&definition);
    const size = @as(usize, 1) << @intCast(witness.log_size);
    const logical = try allocator.alloc(hash_relation.Row, size);
    defer allocator.free(logical);
    for (logical, 0..) |*row, index| row.* = if (index < witness.main.len)
        try witness.logicalRow(index)
    else
        [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT;
    try plan.appendPreparedTupleContributions(ledger, component, logical, domain_mask);
}

fn validateShape(rows: Rows) !void {
    if (rows.source_rows.len == 0 or rows.projection_rows.len == 0 or
        rows.arithmetic_rows.len != 16 or
        rows.program_words.scope != words_air.PROGRAM_WORD_SCOPE or
        rows.provider_words.scope != words_air.PROVIDER_WORD_SCOPE or
        rows.program_words.scope != rows.program_hash.scope or
        rows.provider_words.scope != rows.provider_hash.scope or
        rows.program_words.word_count != rows.program_hash.word_count or
        rows.provider_words.word_count != rows.provider_hash.word_count)
        return error.InvalidV3ExtraRowsShape;
}

pub fn testLocalClosure() !void {
    const values = [_]M31{ M31.one(), M31.fromCanonical(7), M31.fromCanonical(11) };
    const channel = @import("poseidon2_channel.zig");
    var program_words = try words.WordsV1.init(std.testing.allocator, &values, words_air.PROGRAM_WORD_SCOPE);
    defer program_words.deinit();
    var provider_words = try words.WordsV1.init(std.testing.allocator, &values, words_air.PROVIDER_WORD_SCOPE);
    defer provider_words.deinit();
    var program_hash = try hash.HashV1.init(std.testing.allocator, &values, 101, words_air.PROGRAM_WORD_SCOPE, source.PROGRAM_AUTHORITY_KIND, hash.PROGRAM_STEP_BASE, channel.hashCanonicalWords(&values, 101));
    defer program_hash.deinit();
    var provider_hash = try hash.HashV1.init(std.testing.allocator, &values, 102, words_air.PROVIDER_WORD_SCOPE, hash.PROVIDER_FIELD_DIGEST_KIND, hash.PROVIDER_STEP_BASE, channel.hashCanonicalWords(&values, 102));
    defer provider_hash.deinit();
    var metadata_hash = try hash.HashV1.init(std.testing.allocator, &values, 103, source.METADATA_SCOPE, source.METADATA_DIGEST_KIND, 0, channel.hashCanonicalWords(&values, 103));
    defer metadata_hash.deinit();
    var link_hash = try hash.HashV1.init(std.testing.allocator, &values, 104, source.LINK_SCOPE, source.LINK_DIGEST_KIND, 128, channel.hashCanonicalWords(&values, 104));
    defer link_hash.deinit();
    const arithmetic_rows = [_]arithmetic.Row{[_]M31{M31.zero()} ** arithmetic.LOGICAL_INPUT_COUNT} ** 16;
    const tree0_rows = [_]tree0_air.Row{[_]M31{M31.zero()} ** tree0_air.LOGICAL_INPUT_COUNT} ** tree0.TRACE_SIZE;
    const source_rows = [_]source.Row{
        source.logicalRow(values[0], 1, 1, 0, 0, 0, source.METADATA_SCOPE, 0, 0, 0, 1),
        source.logicalRow(values[1], 1, 1, 0, 0, 0, source.METADATA_SCOPE, 0, 1, 0, 1),
        source.logicalRow(values[2], 1, 1, 0, 0, 0, source.METADATA_SCOPE, 0, 2, 0, 1),
        source.logicalRow(values[0], 1, 1, 0, 0, 0, source.LINK_SCOPE, 0, 0, 0, 1),
        source.logicalRow(values[1], 1, 1, 0, 0, 0, source.LINK_SCOPE, 0, 1, 0, 1),
        source.logicalRow(values[2], 1, 1, 0, 0, 0, source.LINK_SCOPE, 0, 2, 0, 1),
    };
    const projection_rows = [_]projection.Row{[_]M31{M31.zero()} ** projection.LOGICAL_INPUT_COUNT};
    var rows = Rows{
        .source_rows = &source_rows,
        .projection_rows = &projection_rows,
        .arithmetic_rows = &arithmetic_rows,
        .program_words = &program_words,
        .program_hash = &program_hash,
        .provider_words = &provider_words,
        .provider_hash = &provider_hash,
        .tree0_rows = &tree0_rows,
        .metadata_hash = &metadata_hash,
        .link_hash = &link_hash,
    };
    const report = try verifyExactLocalClosure(std.testing.allocator, rows);
    try std.testing.expect(report.unmatched_by_domain[@intFromEnum(relation.Domain.recursion_verifier_input_word)] != 0);
    const relations = universal.UniversalRelations.dummy();
    var assembled = try generateInteractions(std.testing.allocator, rows, &relations);
    assembled.deinit(std.testing.allocator);
    provider_hash.scope ^= 1;
    try std.testing.expectError(error.InvalidV3ExtraRowsShape, verifyExactLocalClosure(std.testing.allocator, rows));
    provider_hash.scope ^= 1;
    rows.source_rows = source_rows[0..5];
    try std.testing.expectError(error.V3ExtraRowsLocalLookupNotClosed, verifyExactLocalClosure(std.testing.allocator, rows));
    rows.source_rows = &source_rows;
    var bad_arithmetic = arithmetic_rows;
    bad_arithmetic[0] = try @import("air/ethereum_leaf_link_arithmetic_witness_v1.zig").logicalRow(.entry_root, 7, false, 0, 0);
    rows.arithmetic_rows = &bad_arithmetic;
    try std.testing.expectError(error.V3ExtraRowsLocalLookupNotClosed, verifyExactLocalClosure(std.testing.allocator, rows));
}
