//! Fixed arithmetic constants and output anchors for the common-fold profile.
//! Values and signed multiplicities come from the authenticated lowering plan.
//! A second lookup supplies protocol-defined zero verifier inputs.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const lowering = @import("verifier_arithmetic_lowering.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.fixed_wire.v3";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 9;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 10;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST = blk: {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, "a897d5fa47cc47281b89f753c1c5b5af50c9f3dc6575b4a8472d2c83e1b27aef") catch @compileError("invalid fixed-wire AIR digest");
    break :blk value;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;

pub const Definition = struct {
    arena: lang.ir.Arena,
    roots: [DIRECT_CONSTRAINT_COUNT]Id,
    constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidFixedWireDefinition;
        if (lang.types.idIndex(self.constraints[0]) != 0 or lang.types.idIndex(self.events[0]) != 0 or lang.types.idIndex(self.events[1]) != 1 or
            (self.arena.constraint(self.constraints[0]) orelse return error.InvalidFixedWireDefinition).root != self.roots[0])
            return error.InvalidFixedWireDefinition;
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
fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    const enabled = try arena.input("fixed_wire.enabled", .selector, span);
    const names = [_][]const u8{ "row_mask", "circuit_id", "node_id", "value_0", "value_1", "value_2", "value_3", "signed_multiplicity", "verifier_multiplicity" };
    var pp: [PREPROCESSED_COLUMN_COUNT]Id = undefined;
    for (&pp, names, 0..) |*id, name, index| id.* = try arena.input(name, if (index == 0) .selector else .felt, span);
    const root = try arena.sub(enabled, pp[0], span);
    const constraint = try arena.assertZero("fixed_wire.enabled_matches_mask", root, null, .semantic, span);
    const events = try effects.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ pp[1], pp[2], pp[3], pp[4], pp[5], pp[6] }, .weight = pp[7] },
        .{ .domain = .recursion_verifier_input_word, .role = .emit, .values = &.{ pp[1], pp[2], pp[3], pp[4], pp[5] }, .weight = pp[8] },
    }, span);
    return .{ .arena = arena, .roots = .{root}, .constraints = .{constraint}, .events = events };
}

pub fn logicalRow(term: lowering.PublicWireTerm) !Row {
    if (term.active_in != .binary or term.role == .request or term.circuit_id >= core.fields.m31.Modulus or
        term.node_id >= core.fields.m31.Modulus or term.multiplicity == 0 or term.multiplicity >= core.fields.m31.Modulus)
        return error.InvalidFixedWireTerm;
    const words = term.value.toM31Array();
    for (words) |word| if (word.toU32() >= core.fields.m31.Modulus) return error.InvalidFixedWireTerm;
    const multiplicity = M31.fromCanonical(term.multiplicity);
    return .{ M31.one(), M31.one(), M31.fromCanonical(term.circuit_id), M31.fromCanonical(term.node_id), words[0], words[1], words[2], words[3], if (term.role == .consume) multiplicity.neg() else multiplicity, M31.zero() };
}

/// Zero is fixed in preprocessing, not supplied by the prover's input value.
pub fn zeroVerifierInputRow(verifier_id: u32, item: u32, word: u32) !Row {
    if (verifier_id < 1 or verifier_id > 2 or item >= core.fields.m31.Modulus or word >= 4)
        return error.InvalidFixedWireTerm;
    const kind = @intFromEnum(@import("transcript_payload.zig").VerifierInputKind.claimed_sum);
    return .{ M31.one(), M31.one(), M31.fromCanonical(verifier_id), M31.fromCanonical(kind), M31.fromCanonical(item), M31.fromCanonical(word), M31.zero(), M31.zero(), M31.zero(), M31.one() };
}
