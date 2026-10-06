//! Typed Tree0 bridge for the base SegmentV2 V3 leaf wrapper.
//!
//! An independently verified native commitment emits one verifier-input word per
//! limb. The transcript root consumes those words and the exact frame-word
//! coordinates emitted by the existing transcript-word AIR. A wrapper must
//! prove all three relations together; this definition alone is not a proof.

const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation_effect = @import("relation_effect.zig");
const relation_interaction = @import("relation_interaction.zig");

const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.segment_v2.tree0_field_link.v3";
pub const VERIFIER_ID: u32 = 0;
pub const COMMITMENT_INPUT_KIND: u32 = 4;
pub const TREE0_ITEM: u32 = 0;
pub const TREE0_WORD_COUNT: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize = 6;
pub const DIRECT_CONSTRAINT_COUNT: usize = 6;
pub const RELATION_EVENT_COUNT: usize = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX = "0e5b9a93756a1cccf37df7fc39f5977638c87f48ab6512cf0f657e6550eaeae5";
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
        },
        span,
    );
    return .{ .arena = arena, .roots = roots, .events = events };
}
