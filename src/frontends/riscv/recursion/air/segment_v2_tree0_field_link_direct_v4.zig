//! Typed Tree0 and PPR1 bridge for the direct SegmentV2 leaf wrapper.
//!
//! An independently verified native commitment emits one verifier-input word per
//! limb. The transcript root consumes those words and the exact frame-word
//! coordinates emitted by the existing transcript-word AIR. A wrapper must
//! also consumes the same native root under PPR1, forcing the public LAS2
//! identity to match the transcript root when all four relations close.
//! This definition alone is not a proof.

const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation_effect = @import("relation_effect.zig");
const relation_interaction = @import("relation_interaction.zig");

const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.segment_v2.tree0_field_link.direct.v4";
pub const VERIFIER_ID: u32 = 0;
pub const COMMITMENT_INPUT_KIND: u32 = 4;
pub const PUBLIC_ROOT_KIND: u32 = @import("ethereum_leaf_link_source_v1.zig").PREPROCESSED_ROOT_KIND;
pub const TREE0_ITEM: u32 = 0;
pub const TREE0_WORD_COUNT: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize = 6;
pub const DIRECT_CONSTRAINT_COUNT: usize = 6;
pub const RELATION_EVENT_COUNT: usize = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 16;
pub const INTERACTION_BATCH_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX = "c5c3f28da5a1bbb2ef643a2e5f03a8423bbe6f477797364517792f0d9def2d64";
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid direct Tree0 typed AIR digest");
    break :blk result;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Runtime = relation_interaction.Runtime(
    LOGICAL_INPUT_COUNT,
    RELATION_EVENT_COUNT,
    LOOKUP_BATCH_SIZE,
);
pub const Plan = Runtime.Plan;

comptime {
    if (VERIFIER_ID >= core.fields.m31.Modulus or
        COMMITMENT_INPUT_KIND >= core.fields.m31.Modulus or
        PUBLIC_ROOT_KIND >= core.fields.m31.Modulus or
        TREE0_ITEM >= core.fields.m31.Modulus)
        @compileError("Tree0 field-link tags are not canonical M31");
}

pub const Definition = struct {
    arena: lang.ir.Arena,
    roots: [DIRECT_CONSTRAINT_COUNT]Id,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidTree0FieldLink;
        const actual = (try lang.digest.computeIdentity(&self.arena)).bytes;
        var expected: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&expected, SEMANTIC_DIGEST_HEX) catch
            return error.InvalidTree0FieldLink;
        if (!std.mem.eql(u8, &actual, &expected))
            return error.InvalidTree0FieldLink;
        for (self.roots, 0..) |root, index| {
            const constraint = self.arena.constraintsView()[index];
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
                return error.InvalidTree0FieldLink;
        }
        for (self.events, 0..) |event, index|
            if (lang.types.idIndex(event) != index)
                return error.InvalidTree0FieldLink;
    }
};

pub fn logicalRow(
    native: M31,
    transcript: M31,
    active: u32,
    limb: u32,
    hash_id: u32,
    frame_word_index: u32,
) Row {
    if (active == 0) return [_]M31{M31.zero()} ** LOGICAL_INPUT_COUNT;
    return .{
        native,
        transcript,
        M31.fromCanonical(active),
        M31.fromCanonical(limb),
        M31.fromCanonical(hash_id),
        M31.fromCanonical(frame_word_index),
    };
}

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var result = try buildRaw(allocator);
    defer result.deinit();
    return (try lang.digest.computeIdentity(&result.arena)).bytes;
}

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, SEMANTIC_DIGEST_HEX);
    return Runtime.authenticate(&definition.arena, expected, definition.events);
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = Span.generated();
    const native = try arena.input("tree0_field.native_root_word", .felt, span);
    const transcript = try arena.input("tree0_field.transcript_root_word", .felt, span);
    const active = try arena.input("tree0_field.active", .selector, span);
    const limb = try arena.input("tree0_field.limb", .felt, span);
    const hash_id = try arena.input("tree0_field.hash_id", .felt, span);
    const word_index = try arena.input("tree0_field.word_index", .felt, span);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const commitment_kind = try arena.constantField(COMMITMENT_INPUT_KIND, span);
    const public_root_kind = try arena.constantField(PUBLIC_ROOT_KIND, span);
    const inactive = try arena.sub(one, active, span);
    const roots: [DIRECT_CONSTRAINT_COUNT]Id = .{
        try arena.mul(active, try arena.sub(active, one, span), span),
        try arena.mul(inactive, native, span),
        try arena.mul(inactive, transcript, span),
        try arena.mul(inactive, limb, span),
        try arena.mul(inactive, hash_id, span),
        try arena.mul(inactive, word_index, span),
    };
    for (roots, 0..) |root, index| {
        var buffer: [64]u8 = undefined;
        _ = try arena.assertZero(
            try std.fmt.bufPrint(&buffer, "tree0_field.constraint_{d}", .{index}),
            root,
            null,
            .semantic,
            span,
        );
    }
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        .{
            .{
                .domain = .recursion_verifier_input_word,
                .role = .emit,
                .values = &.{ zero, commitment_kind, zero, limb, native },
                .weight = active,
            },
            .{
                .domain = .recursion_verifier_input_word,
                .role = .consume,
                .values = &.{ zero, commitment_kind, zero, limb, transcript },
                .weight = active,
            },
            .{
                .domain = .recursion_transcript_frame_word,
                .role = .consume,
                .values = &.{ zero, hash_id, word_index, transcript },
                .weight = active,
            },
            .{
                .domain = .recursion_verifier_input_word,
                .role = .consume,
                .values = &.{ zero, public_root_kind, zero, limb, native },
                .weight = active,
            },
        },
        span,
    );
    return .{ .arena = arena, .roots = roots, .events = events };
}

test "direct Tree0 bridge pins semantic digest and fourth lookup" {
    const actual = try computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, actual);
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    _ = try authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 4), definition.events.len);
}

test "PPR1 source, public projection, and Tree0 bridge close exact native root" {
    const source_air = @import("ethereum_leaf_link_source_v1.zig");
    const projection_air = @import("ethereum_leaf_link_projection_v1.zig");
    const program_mod = @import("../ethereum_leaf_link_program_v3.zig");
    const relation = @import("../../air/lang/relation.zig");
    const interaction = @import("relation_interaction.zig");
    var program = try program_mod.ProgramV3.init(std.testing.allocator);
    defer program.deinit();
    const word = M31.fromCanonical(17);
    const source_row = program.source_rows[program.source_rows.len - 8].logical(word);
    const projection_row = program.projection_rows[program.projection_rows.len - 8].logical(word);
    const tree_row = logicalRow(word, word, 1, 0, 12, 8);
    var source_definition = try source_air.build(std.testing.allocator);
    defer source_definition.deinit();
    const source_plan = try source_air.authenticate(&source_definition);
    var projection_definition = try projection_air.build(std.testing.allocator);
    defer projection_definition.deinit();
    const projection_plan = try projection_air.authenticate(&projection_definition);
    var tree_definition = try build(std.testing.allocator);
    defer tree_definition.deinit();
    const tree_plan = try authenticate(&tree_definition);
    const mask = @as(u64, 1) << @intFromEnum(relation.Domain.recursion_verifier_input_word);
    var ledger = interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try source_plan.appendPreparedTupleContributions(&ledger, 39, &.{source_row}, mask);
    try projection_plan.appendPreparedTupleContributions(&ledger, 40, &.{projection_row}, mask);
    try tree_plan.appendPreparedTupleContributions(&ledger, 44, &.{tree_row}, mask);
    try std.testing.expect(ledger.classify().isClosed());

    var missing = interaction.TupleLedger.init(std.testing.allocator);
    defer missing.deinit();
    try projection_plan.appendPreparedTupleContributions(&missing, 40, &.{projection_row}, mask);
    try tree_plan.appendPreparedTupleContributions(&missing, 44, &.{tree_row}, mask);
    try std.testing.expect(!missing.classify().isClosed());

    var changed = interaction.TupleLedger.init(std.testing.allocator);
    defer changed.deinit();
    var wrong_projection = projection_row;
    wrong_projection[0] = wrong_projection[0].add(M31.one());
    try source_plan.appendPreparedTupleContributions(&changed, 39, &.{source_row}, mask);
    try projection_plan.appendPreparedTupleContributions(&changed, 40, &.{wrong_projection}, mask);
    try tree_plan.appendPreparedTupleContributions(&changed, 44, &.{tree_row}, mask);
    try std.testing.expect(!changed.classify().isClosed());
}
