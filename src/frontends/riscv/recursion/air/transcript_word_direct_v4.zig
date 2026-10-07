//! Direct-wrapper transcript word: the native verifier frame plus the eight
//! Tree0 words consumed by the versioned root bridge. The extra selector is
//! fixed preprocessing, never a proof-supplied main value.

const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation_effect = @import("relation_effect.zig");
const relation_interaction = @import("relation_interaction.zig");

const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.transcript_word.direct.v4";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 16;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize = 20;
pub const DIRECT_CONSTRAINT_COUNT: usize = 5;
pub const RELATION_EVENT_COUNT: usize = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;
pub const SEMANTIC_DIGEST_HEX = "31293c88b37c38c2e36c7f0a8cee137daff36f62c934a80cd3e9b3eecbadde9a";
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk result;
};
pub const Row = [LOGICAL_INPUT_COUNT]core.fields.m31.M31;
pub const Runtime = relation_interaction.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Plan = Runtime.Plan;

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
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            !std.mem.eql(u8, &(try lang.digest.computeIdentity(&self.arena)).bytes, &SEMANTIC_DIGEST))
            return error.InvalidDirectTranscriptWord;
        for (self.roots, 0..) |root, index| {
            const item = self.arena.constraintsView()[index];
            if (item.root != root or item.gate != null or item.category != .semantic)
                return error.InvalidDirectTranscriptWord;
        }
        for (self.events, 0..) |effect, index|
            if (lang.types.idIndex(effect) != index) return error.InvalidDirectTranscriptWord;
    }
};

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
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, definition.events);
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = Span.generated();
    const enabler = try arena.input("recursion.transcript_word.enabler", .selector, span);
    const value = try arena.input("recursion.transcript_word.value", .felt, span);
    const row_mask = try arena.input("recursion_transcript_word_row_mask", .selector, span);
    const segment_mask = try arena.input("recursion_transcript_word_segment_mask", .selector, span);
    const binary_mask = try arena.input("recursion_transcript_word_binary_mask", .selector, span);
    const verifier_id = try arena.input("recursion_transcript_word_verifier_id", .felt, span);
    const sequence = try arena.input("recursion_transcript_word_sequence", .felt, span);
    const tag = try arena.input("recursion_transcript_word_tag", .felt, span);
    var args: [4]Id = undefined;
    for (&args, 0..) |*arg, i| {
        var name: [64]u8 = undefined;
        arg.* = try arena.input(try std.fmt.bufPrint(&name, "recursion_transcript_word_arg_{d}", .{i}), .felt, span);
    }
    const hash_id = try arena.input("recursion_transcript_word_hash_id", .felt, span);
    const word_index = try arena.input("recursion_transcript_word_index", .felt, span);
    const is_payload = try arena.input("recursion_transcript_word_is_payload", .selector, span);
    const payload_index = try arena.input("recursion_transcript_word_payload_index", .felt, span);
    const constant_value = try arena.input("recursion_transcript_word_constant", .felt, span);
    const tree0_bridge = try arena.input("recursion_transcript_word_tree0_bridge", .selector, span);
    const segment_active = try arena.input("recursion.transcript_word.param.segment_active", .selector, span);
    const binary_active = try arena.input("recursion.transcript_word.param.binary_active", .selector, span);
    const one = try arena.constantField(1, span);
    const active = try arena.add(try arena.mul(segment_mask, segment_active, span), try arena.mul(binary_mask, binary_active, span), span);
    const frame_value = try arena.add(value, constant_value, span);
    const payload_weight = try arena.mul(active, is_payload, span);
    const bridge_weight = try arena.mul(active, tree0_bridge, span);
    const roots: [DIRECT_CONSTRAINT_COUNT]Id = .{
        try arena.sub(enabler, row_mask, span),
        try arena.mul(try arena.sub(row_mask, active, span), value, span),
        try arena.mul(try arena.mul(active, try arena.sub(one, is_payload, span), span), value, span),
        try arena.mul(tree0_bridge, try arena.sub(one, row_mask, span), span),
        try arena.mul(tree0_bridge, try arena.sub(one, segment_mask, span), span),
    };
    for (roots, 0..) |root, index| {
        var name: [64]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&name, "direct_transcript_word.constraint_{d}", .{index}), root, null, .semantic, span);
    }
    const frame_tuple = [_]Id{ verifier_id, hash_id, word_index, frame_value };
    const payload_tuple = .{ verifier_id, sequence, tag } ++ args ++ .{ payload_index, value };
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_transcript_frame_word, .role = .emit, .values = &frame_tuple, .weight = active },
        .{ .domain = .recursion_transcript_payload_word, .role = .consume, .values = &payload_tuple, .weight = payload_weight },
        .{ .domain = .recursion_transcript_frame_word, .role = .emit, .values = &frame_tuple, .weight = bridge_weight },
    }, span);
    return .{ .arena = arena, .roots = roots, .events = events };
}

test "direct transcript word semantic identity" {
    const actual = try computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, actual);
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    _ = try authenticate(&definition);
}
