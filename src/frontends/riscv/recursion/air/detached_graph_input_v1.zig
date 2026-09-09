//! Admitted source-to-arithmetic routing for the detached parent profile.
//! Coordinates, source selectors and use counts belong to preprocessing.
//! Private hints have no external source; their meaning is constrained by the
//! destination graph. Published words always consume one expected-word tuple.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.detached_graph_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 5;
pub const PREPROCESSED_COLUMN_COUNT: usize = 18;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 23;
pub const DIRECT_CONSTRAINT_COUNT: usize = 12;
pub const RELATION_EVENT_COUNT: usize = 6;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, "c73a0e906b7cc3c4bc01d0211ed1dbafffee16a548276c5e543b327aa61f5d27") catch @compileError("invalid detached AIR digest");
    break :blk digest;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Source = union(enum) {
    private,
    verifier_input: [4]u32,
    challenge: [4]u32,
    randomness: [4]u32,
    wire: struct { circuit: u32, node: u32 },
    statement: struct { scope: u32, word: u32 },
    fixed: QM31,
};
pub const Destination = struct { circuit: u32, node: u32, uses: u32 };
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
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidDetachedGraphInput;
        for (self.constraints, self.roots, 0..) |constraint, root, i| if (lang.types.idIndex(constraint) != i or (self.arena.constraint(constraint) orelse return error.InvalidDetachedGraphInput).root != root) return error.InvalidDetachedGraphInput;
        for (self.events, 0..) |event, i| if (lang.types.idIndex(event) != i) return error.InvalidDetachedGraphInput;
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
    var main: [5]Id = undefined;
    var pp: [18]Id = undefined;
    for (&main, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "graph_input.main_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "graph_input.fixed_{d}", .{i}), if (i == 0 or (i >= 4 and i < 10)) .selector else .felt, span);
    }
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, pp[0], span);
    var roots: [12]Id = undefined;
    roots[0] = try arena.sub(main[0], pp[0], span);
    for (main[1..], 1..) |value, i| roots[i] = try arena.mul(inactive, value, span);
    const scalar = try arena.add(try arena.add(pp[4], pp[5], span), try arena.add(pp[6], pp[8], span), span);
    for (main[2..], 5..) |value, i| roots[i] = try arena.mul(scalar, value, span);
    for (main[1..], pp[14..18], 8..) |value, fixed, i| roots[i] = try arena.mul(pp[9], try arena.sub(value, fixed, span), span);
    var constraints: [12]lang.types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, i| {
        var buf: [48]u8 = undefined;
        constraint.* = try arena.assertZero(try std.fmt.bufPrint(&buf, "graph_input.constraint_{d}", .{i}), root, null, .semantic, span);
    }
    const source = pp[10..14].* ++ .{main[1]};
    const events = try effects.appendGroup(6, &arena, .{
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[2] } ++ main[1..5].*), .weight = pp[3] },
        .{ .domain = .recursion_verifier_input_word, .role = .consume, .values = &source, .weight = pp[4] },
        .{ .domain = .recursion_relation_challenge_word, .role = .consume, .values = &source, .weight = pp[5] },
        .{ .domain = .recursion_verifier_randomness_word, .role = .consume, .values = &source, .weight = pp[6] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[10], pp[11] } ++ main[1..5].*), .weight = pp[7] },
        .{ .domain = .recursion_statement_word, .role = .consume, .values = &.{ pp[10], pp[11], main[1] }, .weight = pp[8] },
    }, span);
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}
pub fn logicalRow(destination: Destination, source: Source, value: QM31) !Row {
    var result: Row = @splat(M31.zero());
    result[0] = M31.one();
    result[1..5].* = value.toM31Array();
    const pp = result[5..];
    pp[0] = M31.one();
    const dest = [_]u32{ destination.circuit, destination.node, destination.uses };
    for (pp[1..4], dest) |*field, word| field.* = try canonical(word);
    var coords: [4]u32 = @splat(0);
    var scalar = false;
    switch (source) {
        .private => {},
        .verifier_input => |v| {
            pp[4] = M31.one();
            coords = v;
            scalar = true;
        },
        .challenge => |v| {
            pp[5] = M31.one();
            coords = v;
            scalar = true;
        },
        .randomness => |v| {
            pp[6] = M31.one();
            coords = v;
            scalar = true;
        },
        .wire => |v| {
            pp[7] = M31.one();
            coords[0] = v.circuit;
            coords[1] = v.node;
        },
        .statement => |v| {
            pp[8] = M31.one();
            coords[0] = v.scope;
            coords[1] = v.word;
            scalar = true;
        },
        .fixed => |v| {
            pp[9] = M31.one();
            pp[14..18].* = v.toM31Array();
            if (!v.eql(value)) return error.InvalidDetachedGraphInput;
        },
    }
    if (scalar) _ = try value.tryIntoM31();
    for (pp[10..14], coords) |*field, word| field.* = try canonical(word);
    return result;
}
fn canonical(word: u32) !M31 {
    if (word >= core.fields.m31.Modulus) return error.InvalidDetachedGraphInput;
    return M31.fromCanonical(word);
}
