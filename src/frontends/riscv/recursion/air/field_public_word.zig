//! Common-fold field-word routing: child digests, parent statement and hashes.
//! All routes and multiplicities are fixed by verifier-owned preprocessing.
const std = @import("std");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.field_public_word.v3";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 17;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 19;
pub const DIRECT_CONSTRAINT_COUNT: usize = 2;
pub const RELATION_EVENT_COUNT: usize = 6;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const PUBLIC_SCOPE: u32 = 4;
pub const DIGEST_INPUT_KIND: u32 = 11;
pub const SEMANTIC_DIGEST = blk: {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, "c02179e9ba469114f19ddc0ff8e1670ba61bd4dd5d0a1b14445e6799feef3017") catch @compileError("invalid field-public AIR digest");
    break :blk value;
};
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
            return error.InvalidFieldPublicWordDefinition;
        for (self.constraints, self.roots, 0..) |constraint, root, index| {
            if (lang.types.idIndex(constraint) != index or
                (self.arena.constraint(constraint) orelse return error.InvalidFieldPublicWordDefinition).root != root)
                return error.InvalidFieldPublicWordDefinition;
        }
        for (self.events, 0..) |event, index| if (lang.types.idIndex(event) != index) return error.InvalidFieldPublicWordDefinition;
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
    const enabled = try arena.input("field_public.enabled", .selector, span);
    const value = try arena.input("field_public.value", .felt, span);
    const names = [_][]const u8{ "row_mask", "child_mask", "child_scope", "child_word", "parent_mask", "parent_word", "statement_mask", "statement_word", "hash_0_mask", "hash_0_scope", "hash_0_word", "hash_1_mask", "hash_1_scope", "hash_1_word", "digest_mask", "digest_verifier", "digest_limb" };
    var pp: [PREPROCESSED_COLUMN_COUNT]Id = undefined;
    for (&pp, names, 0..) |*id, name, index| id.* = try arena.input(name, if (index == 0 or index == 1 or index == 4 or index == 6 or index == 8 or index == 11 or index == 14) .selector else .felt, span);
    const one = try arena.constantField(1, span);
    const zero = try arena.constantField(0, span);
    const parent_scope = try arena.constantField(3, span);
    const public_scope = try arena.constantField(PUBLIC_SCOPE, span);
    const digest_kind = try arena.constantField(DIGEST_INPUT_KIND, span);
    const roots = [_]Id{ try arena.sub(enabled, pp[0], span), try arena.mul(try arena.sub(one, pp[0], span), value, span) };
    const constraints = [_]lang.types.ConstraintId{ try arena.assertZero("field_public.enabled_matches_mask", roots[0], null, .semantic, span), try arena.assertZero("field_public.inactive_value_zero", roots[1], null, .semantic, span) };
    const events = try effects.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_statement_word, .role = .consume, .values = &.{ pp[2], pp[3], value }, .weight = pp[1] },
        .{ .domain = .recursion_statement_word, .role = .emit, .values = &.{ parent_scope, pp[7], value }, .weight = pp[6] },
        .{ .domain = .recursion_statement_word, .role = .emit, .values = &.{ public_scope, pp[5], value }, .weight = pp[4] },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &.{ pp[9], pp[10], value }, .weight = pp[8] },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &.{ pp[12], pp[13], value }, .weight = pp[11] },
        .{ .domain = .recursion_verifier_input_word, .role = .emit, .values = &.{ pp[15], digest_kind, zero, pp[16], value }, .weight = pp[14] },
    }, span);
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}
