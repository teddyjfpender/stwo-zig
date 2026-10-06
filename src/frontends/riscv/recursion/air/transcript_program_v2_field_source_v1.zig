//! Typed fixed-word source for the canonical SegmentV2 transcript Program.
//!
//! The verifier recompiles the expected preprocessed words and pins tree 0.
//! A recursive wrapper may then consume these raw tuples in a Poseidon hash
//! component. This source alone grants no V3 proof capability.

const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation_effect = @import("relation_effect.zig");
const relation_interaction = @import("relation_interaction.zig");

const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.segment_v2.program_field_source.v1";
pub const PROGRAM_WORD_SCOPE: u32 = 0x5056_3257; // "PV2W"
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize = 5;
pub const DIRECT_CONSTRAINT_COUNT: usize = 6;
pub const RELATION_EVENT_COUNT: usize = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX = "53e56c86d19dac6996819ccb03c75a57b23714b8781710900d5e450db6f4d0c5";
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Runtime = relation_interaction.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Plan = Runtime.Plan;

comptime {
    if (PROGRAM_WORD_SCOPE >= core.fields.m31.Modulus)
        @compileError("SegmentV2 Program field scope is not canonical M31");
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
            return error.InvalidProgramFieldSource;
        const actual = (try lang.digest.computeIdentity(&self.arena)).bytes;
        var expected: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&expected, SEMANTIC_DIGEST_HEX) catch
            return error.InvalidProgramFieldSource;
        if (!std.mem.eql(u8, &actual, &expected))
            return error.InvalidProgramFieldSource;
        for (self.roots, 0..) |root, index| {
            const constraint = self.arena.constraintsView()[index];
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
                return error.InvalidProgramFieldSource;
        }
    }
};

pub fn logicalRow(value: M31, active: u32, expected: M31, index: u32) Row {
    return .{
        value,
        M31.fromCanonical(active),
        expected,
        M31.fromCanonical(PROGRAM_WORD_SCOPE),
        M31.fromCanonical(index),
    };
}

pub fn build(allocator: std.mem.Allocator) !Definition {
    var definition = try buildRaw(allocator);
    errdefer definition.deinit();
    try definition.validate();
    return definition;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try lang.digest.computeIdentity(&definition.arena)).bytes;
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
    const value = try arena.input("segment_v2_program_field.value", .felt, span);
    const active = try arena.input("segment_v2_program_field.active", .selector, span);
    const expected = try arena.input("segment_v2_program_field.expected", .felt, span);
    const scope = try arena.input("segment_v2_program_field.scope", .felt, span);
    const index = try arena.input("segment_v2_program_field.index", .felt, span);
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, active, span);
    const roots: [DIRECT_CONSTRAINT_COUNT]Id = .{
        try arena.mul(active, try arena.sub(active, one, span), span),
        try arena.mul(active, try arena.sub(value, expected, span), span),
        try arena.mul(inactive, value, span),
        try arena.mul(inactive, expected, span),
        try arena.mul(inactive, scope, span),
        try arena.mul(inactive, index, span),
    };
    for (roots, 0..) |root, i| {
        var name: [70]u8 = undefined;
        _ = try arena.assertZero(
            try std.fmt.bufPrint(&name, "segment_v2_program_field.constraint_{d}", .{i}),
            root,
            null,
            .semantic,
            span,
        );
    }
    const events: [RELATION_EVENT_COUNT]lang.types.EffectId = .{
        try relation_effect.append(&arena, .{
            .domain = .recursion_vm_public_claim_word,
            .role = .emit,
            .values = &.{ scope, index, value },
            .weight = active,
        }, span),
    };
    return .{ .arena = arena, .roots = roots, .events = events };
}
