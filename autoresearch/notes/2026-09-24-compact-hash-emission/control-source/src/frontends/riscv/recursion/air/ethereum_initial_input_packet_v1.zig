//! Opt-in graph/linear-lane bridge. Fixed preprocessing is derived from an
//! admitted arithmetic circuit; witnesses never choose input nodes or fanout.
//! The graph must constrain all packet inputs using constrainPackets, and
//! consume the returned subtotal in its authenticated public memory sum.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const arithmetic = @import("../arithmetic_circuit.zig");
pub const lane = @import("ethereum_initial_input_lane_v1.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const span = lang.source.SourceSpan.generated();
pub const VERSION: u16 = 1;
pub const STABLE_NAME = "recursion.ethereum_initial_input_packet.v1";
pub const PACKET_COUNT: usize = lane.PROGRAM_FIRST_SLOT + lane.PROGRAM_PACKET_COUNT;
pub const INPUT_COUNT: usize = PACKET_COUNT * 4;
pub const ROW_COUNT: usize = 16;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 4;
pub const PREPROCESSED_COLUMN_COUNT: usize = 13;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 17;
pub const DIRECT_CONSTRAINT_COUNT: usize = 13;
pub const RELATION_EVENT_COUNT: usize = 6;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST_HEX = "6c65d75620f0a61a4f36ba95c5297a927cdb06e172bd1c91481421cec60fefa5";
pub const SEMANTIC_DIGEST: lang.digest.Digest = blk: {
    var value: lang.digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&value, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk value;
};
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Preprocessing = [PREPROCESSED_COLUMN_COUNT]M31;
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.meta.eql(identity.bytes, SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidEthereumInitialInputPacketAir;
        for (self.events, 0..) |event, index| if (lang.types.idIndex(event) != index) return error.InvalidEthereumInitialInputPacketAir;
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn semanticIdentity(allocator: std.mem.Allocator) !lang.digest.Identity {
    var result = try buildRaw(allocator);
    defer result.deinit();
    try lang.validate.validate(&result.arena);
    return lang.digest.computeIdentity(&result.arena);
}
fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    var m: [4]Id = undefined;
    inline for (&m, 0..) |*v, i| v.* = try arena.input(std.fmt.comptimePrint("initial_packet.main.{d}", .{i}), .felt, span);
    var p: [13]Id = undefined;
    inline for (&p, 0..) |*v, i| v.* = try arena.input(std.fmt.comptimePrint("initial_packet.preprocessed.{d}", .{i}), .felt, span);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, p[0], span);
    var roots: [DIRECT_CONSTRAINT_COUNT]Id = undefined;
    inline for (0..4) |i| roots[i] = try arena.mul(m[i], inactive, span);
    roots[4] = try arena.mul(p[0], inactive, span);
    roots[5] = try arena.mul(p[3], try arena.sub(one, p[3], span), span);
    roots[6] = try arena.mul(p[3], inactive, span);
    roots[7] = try arena.mul(p[2], inactive, span);
    roots[8] = try arena.mul(p[2], p[3], span);
    inline for (0..4) |i| roots[9 + i] = try arena.mul(p[9 + i], inactive, span);
    inline for (roots, 0..) |root, i| _ = try arena.assertZero(std.fmt.comptimePrint("initial_packet.constraint.{d}", .{i}), root, null, .semantic, span);
    const scope = try arena.constantField(lane.SOURCE_SCOPE, span);
    const packet = [_]Id{ scope, p[1], m[0], m[1], m[2], m[3] };
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    events[0] = try effects.append(&arena, .{ .domain = .recursion_wire, .role = .emit, .values = &packet, .weight = p[2] }, span);
    events[1] = try effects.append(&arena, .{ .domain = .recursion_wire, .role = .consume, .values = &packet, .weight = p[3] }, span);
    inline for (0..4) |i| events[2 + i] = try effects.append(&arena, .{ .domain = .recursion_wire, .role = .emit, .values = &.{ p[4], p[5 + i], m[i], zero, zero, zero }, .weight = p[9 + i] }, span);
    return .{ .arena = arena, .events = events };
}

/// Derive once from the admitted fixed graph. These rows must be bound by
/// the independently derived Tree0, not accepted from a proof's witness.
/// The ordinary scalar-input emitter must omit exactly these 52 inputs.
pub fn preprocessing(shape: lane.Shape, circuit: *const arithmetic.Circuit, circuit_id: u32, first_input: u32) ![ROW_COUNT]Preprocessing {
    try circuit.validate();
    if (circuit_id >= core.fields.m31.Modulus or first_input > circuit.inputNodes().len or INPUT_COUNT > circuit.inputNodes().len - first_input) return error.InvalidEthereumInitialInputPacketPlan;
    var result = [_]Preprocessing{[_]M31{M31.zero()} ** PREPROCESSED_COLUMN_COUNT} ** ROW_COUNT;
    for (result[0..PACKET_COUNT], 0..) |*p, slot| {
        p[0] = M31.one();
        p[1] = M31.fromCanonical(@intCast(slot));
        p[2] = M31.fromCanonical(if (slot == lane.SUM_SLOT) 0 else try shape.wireSourceUses(@intCast(slot)));
        p[3] = M31.fromCanonical(@intFromBool(slot == lane.SUM_SLOT));
        p[4] = M31.fromCanonical(circuit_id);
        for (0..4) |limb| {
            const input: u32 = @intCast(first_input + 4 * slot + limb);
            const uses = try circuit.inputUseCount(input);
            if (uses == 0) return error.UnusedEthereumInitialInputPacket;
            p[5 + limb] = M31.fromCanonical(circuit.inputNodes()[input]);
            p[9 + limb] = M31.fromCanonical(uses);
        }
    }
    return result;
}
pub fn row(p: Preprocessing, words: [4]M31) Row {
    return words ++ p;
}
