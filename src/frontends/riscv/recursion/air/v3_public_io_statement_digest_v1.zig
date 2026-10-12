//! Separate, dormant verifier-owned V3 statement digest relation consumer.
//! The source is an independently supplied expected statement, never an
//! artifact-chosen digest. A future roster must authenticate all 16 fixed rows.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const edge = @import("v3_public_io_edge_digest_v1.zig");

pub const STABLE_NAME = "recursion.v3_public_io_statement_digest.v1";
pub const PROOF_ACTIVATION = false;
pub const LOGICAL_INPUT_COUNT = 4;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 1;
pub const DIRECT_CONSTRAINT_COUNT = 1;
pub const RELATION_EVENT_COUNT = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT = 1;
pub const INTERACTION_COLUMN_COUNT = 4;
pub const SEMANTIC_DIGEST_HEX = "964c3c0c864d349d33b29efbddfc70e41a6e62a9627a2caa3273d7f0f5d7d178";
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch @compileError("invalid V3 statement digest");
    break :blk result;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;

// 0: committed digest limb; 1/2: verifier-fixed kind/index; 3: expected limb.
pub const Definition = struct {
    arena: lang.ir.Arena,
    constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST)) return error.InvalidV3StatementDigestAir;
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or self.arena.calls.items.len != 0)
            return error.InvalidV3StatementDigestAir;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var x: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&x, 0..) |*id, i| {
        var name: [80]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "{s}.column_{d}", .{ STABLE_NAME, i }), .felt, span);
    }
    const constraints = [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId{
        try arena.assertZero("verifier_expected_digest_limb", try arena.sub(x[0], x[3], span), null, .semantic, span),
    };
    const events = [RELATION_EVENT_COUNT]lang.types.EffectId{
        (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_vm_public_io_digest, .role = .consume, .values = &.{ x[1], x[2], x[0] }, .weight = try arena.constantField(1, span) }}, span))[0],
    };
    var result = Definition{ .arena = arena, .constraints = constraints, .events = events };
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var definition = try build(allocator);
    defer definition.deinit();
    return (try lang.digest.computeIdentity(&definition.arena)).bytes;
}

pub fn fixedRows(statement: edge.ExpectedDigests) [16]Row {
    var rows: [16]Row = undefined;
    for (statement.input, 0..) |word, index| rows[index] = makeRow(edge.INPUT_DIGEST_KIND, @intCast(index), word);
    for (statement.output, 0..) |word, index| rows[8 + index] = makeRow(edge.OUTPUT_DIGEST_KIND, @intCast(index), word);
    return rows;
}

fn makeRow(kind: u32, index: u32, value: u32) Row {
    const limb = M31.fromCanonical(value);
    return .{ limb, M31.fromCanonical(kind), M31.fromCanonical(index), limb };
}
