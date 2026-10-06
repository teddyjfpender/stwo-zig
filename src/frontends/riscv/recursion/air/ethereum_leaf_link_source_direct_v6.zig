//! Direct source authority for native transcript claims. ProgramV3 marks
//! those exact 112 rows with the existing `transcript_mask` selector; the
//! source reads their value from the native verifier relation. Other source
//! routes retain the V1 AIR and schedule. Row5 needs a second emit for each
//! selected tuple before this version can enter a wrapper proof.

const std = @import("std");
const core = @import("stwo_core");
const old = @import("ethereum_leaf_link_source_v1.zig");
const ir = @import("../../air/lang/ir.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const source = @import("../../air/lang/source.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");
const interaction = @import("relation_interaction.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const STABLE_NAME = "recursion.ethereum_leaf_link.source.direct.v6";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const PHYSICAL_MAIN_COLUMN_COUNT = old.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = old.PREPROCESSED_COLUMN_COUNT;
pub const LOGICAL_INPUT_COUNT = old.LOGICAL_INPUT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = old.DIRECT_CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT = old.RELATION_EVENT_COUNT + 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT = RELATION_EVENT_COUNT;
pub const INTERACTION_COLUMN_COUNT = 4 * INTERACTION_BATCH_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX = "60d521255412b11b6d60ede353ff8cd3308695644309794bb833a7c1f161c0be";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch @compileError("invalid V6 source digest");
    break :blk bytes;
};
pub const Row = old.Row;
pub const Runtime = interaction.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Plan = Runtime.Plan;

pub const Definition = struct {
    arena: ir.Arena,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST))
            return error.InvalidDirectSourceV6;
    }
};

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var base = try old.build(allocator);
    errdefer base.deinit();
    const span = source.SourceSpan.generated();
    const two = try base.arena.constantField(2, span);
    const tuple = [_]types.ValueId{
        try base.arena.constantField(old.VERIFIER_ID, span),
        base.preprocessed.kind,
        base.preprocessed.index_0,
        base.preprocessed.index_1,
        base.main.value,
    };
    // V1 emits +1. For transcript rows only, a second event consumes 2,
    // leaving one native read (-1) from the exact same committed main value.
    const correction = try relation_effect.append(&base.arena, .{
        .domain = .recursion_verifier_input_word,
        .role = .consume,
        .values = &tuple,
        .weight = try base.arena.mul(two, base.preprocessed.transcript_mask, span),
    }, span);
    return .{ .arena = base.arena, .events = base.events ++ .{correction} };
}

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
    var result = try buildRaw(allocator);
    defer result.deinit();
    return (try digest.computeIdentity(&result.arena)).bytes;
}

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, definition.events);
}

test "direct V6 source reads transcript claims from native fan-out" {
    const actual = try computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualDeep(SEMANTIC_DIGEST, actual);
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    const plan = try authenticate(&definition);
    const value = M31.fromCanonical(17);
    const selected = old.logicalRow(value, 1, 0, 0, 1, 0, 0, old.TRANSCRIPT_CLAIM_KIND, 2, 3, 1);
    const tuple = [_]QM31{
        .fromBase(M31.fromCanonical(old.VERIFIER_ID)),
        .fromBase(M31.fromCanonical(old.TRANSCRIPT_CLAIM_KIND)),
        .fromBase(M31.fromCanonical(2)),
        .fromBase(M31.fromCanonical(3)),
        .fromBase(value),
    };
    const mask: u64 = @as(u64, 1) << @intFromEnum(@import("../../air/lang/relation.zig").Domain.recursion_verifier_input_word);
    var ledger = interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(&ledger, 39, &.{selected}, mask);
    try ledger.append(.recursion_verifier_input_word, 5, 1, .emit, QM31.fromBase(M31.fromCanonical(2)), &tuple);
    try ledger.append(.recursion_verifier_input_word, 18, 8, .consume, QM31.one().neg(), &tuple);
    try std.testing.expect(ledger.classify().isClosed());

    var wrong = selected;
    wrong[3] = M31.one(); // verifier_mask
    wrong[4] = M31.zero(); // transcript_mask
    var mutated = interaction.TupleLedger.init(std.testing.allocator);
    defer mutated.deinit();
    try plan.appendPreparedTupleContributions(&mutated, 39, &.{wrong}, mask);
    try mutated.append(.recursion_verifier_input_word, 5, 1, .emit, QM31.fromBase(M31.fromCanonical(2)), &tuple);
    try mutated.append(.recursion_verifier_input_word, 18, 8, .consume, QM31.one().neg(), &tuple);
    try std.testing.expectEqual(@as(usize, 1), mutated.classify().unmatched_by_domain[25]);
}
