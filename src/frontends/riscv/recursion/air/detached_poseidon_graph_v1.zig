//! Connect one existing Poseidon provider call to32 base-valued graph inputs.
//! The admitted schedule pins each destination node and its exact fan-out.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.detached_poseidon_graph.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 33;
pub const PREPROCESSED_COLUMN_COUNT: usize = 66;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 99;
pub const DIRECT_CONSTRAINT_COUNT: usize = 33;
pub const RELATION_EVENT_COUNT: usize = 33;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 17;
pub const INTERACTION_COLUMN_COUNT: usize = 68;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, "7ea0b8e40c8b757e94023b2e407a2baf303d10cf133b1cfdc0b1c667ef24f46e") catch @compileError("invalid detached AIR digest");
    break :blk digest;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Definition = struct {
    arena: lang.ir.Arena,
    roots: [DIRECT_CONSTRAINT_COUNT]Id,
    constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidDetachedPoseidonGraph;
        for (self.constraints, self.roots, 0..) |constraint, root, i| if (lang.types.idIndex(constraint) != i or (self.arena.constraint(constraint) orelse return error.InvalidDetachedPoseidonGraph).root != root) return error.InvalidDetachedPoseidonGraph;
        for (self.events, 0..) |event, i| if (lang.types.idIndex(event) != i) return error.InvalidDetachedPoseidonGraph;
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
    var main: [33]Id = undefined;
    var pp: [66]Id = undefined;
    for (&main, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "poseidon_graph.main_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "poseidon_graph.fixed_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    const zero = try arena.constantField(0, span);
    const inactive = try arena.sub(try arena.constantField(1, span), pp[0], span);
    var roots: [33]Id = undefined;
    roots[0] = try arena.sub(main[0], pp[0], span);
    for (main[1..], 1..) |value, i| roots[i] = try arena.mul(inactive, value, span);
    var constraints: [33]lang.types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, i| {
        var buf: [48]u8 = undefined;
        constraint.* = try arena.assertZero(try std.fmt.bufPrint(&buf, "poseidon_graph.constraint_{d}", .{i}), root, null, .semantic, span);
    }
    // appendGroup owns the schema and signed lookup convention.
    const call = try effects.appendGroup(1, &arena, .{.{ .domain = .poseidon2_io, .role = .request, .values = main[1..33], .weight = pp[0] }}, span);
    var events: [33]lang.types.EffectId = undefined;
    events[0] = call[0];
    for (main[1..], 0..) |value, i| {
        const event = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &.{ pp[1], pp[2 + i], value, zero, zero, zero }, .weight = pp[34 + i] }}, span);
        events[i + 1] = event[0];
    }
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}
pub fn logicalRow(circuit: u32, nodes: [32]u32, uses: [32]u32, words: [32]M31) !Row {
    var result: Row = @splat(M31.zero());
    result[0] = M31.one();
    result[1..33].* = words;
    const pp = result[33..];
    pp[0] = M31.one();
    pp[1] = try canonical(circuit);
    for (pp[2..34], nodes) |*field, node| field.* = try canonical(node);
    for (pp[34..66], uses) |*field, count| field.* = try canonical(count);
    return result;
}
fn canonical(word: u32) !M31 {
    if (word >= core.fields.m31.Modulus) return error.InvalidDetachedPoseidonGraph;
    return M31.fromCanonical(word);
}
