//! Dormant, verifier-scheduled closure of the V3 public-I/O byte bridge.
//!
//! Every bridge byte is consumed exactly once. The same independently owned
//! expectation determines the canonical S2I1/S2O1 digests, which must equal
//! the verifier's expected V3 statement digests before the fixed schedule is
//! admitted. This is a fixed-key equality construction, not an in-AIR hash:
//! the complete schedule and its preprocessing must be authenticated by a
//! future proof gate. Native memory custody is still missing.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const bridge = @import("v3_public_io_word_bridge_v1.zig");
const binding = @import("../segment_public_io_binding_v1.zig");
const ingress = @import("../segment_public_io_ingress_v2.zig");

pub const STABLE_NAME = "recursion.v3_public_io_edge_digest.v1";
pub const PROOF_ACTIVATION = false;
pub const INPUT_DIGEST_KIND: u32 = 2;
pub const OUTPUT_DIGEST_KIND: u32 = 3;
pub const LOGICAL_INPUT_COUNT = 7;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 1;
pub const DIRECT_CONSTRAINT_COUNT = 5;
pub const RELATION_EVENT_COUNT = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 1;
pub const INTERACTION_COLUMN_COUNT = 4;
pub const SEMANTIC_DIGEST_HEX = "d081f52c3f81e96470192a97b686e374641e000c38e6c483b2b1772a0dbf9ea3";
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch @compileError("invalid V3 edge digest");
    break :blk result;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const ExpectedDigests = struct { input: binding.Digest, output: binding.Digest };

// 0: committed value; 1: byte selector; 2: digest selector; 3: kind;
// 4: index; 5: verifier-fixed expected value; 6: active selector.
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
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST)) return error.InvalidV3EdgeDigestAir;
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0) return error.InvalidV3EdgeDigestAir;
    }
};

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try lang.digest.computeIdentity(&definition.arena)).bytes;
}

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var x: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&x, 0..) |*id, i| {
        var name: [80]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "{s}.column_{d}", .{ STABLE_NAME, i }), if (i == 0 or i == 5) .felt else if (i == 1 or i == 2 or i == 6) .selector else .felt, span);
    }
    const one = try arena.constantField(1, span);
    const constraints = [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId{
        try arena.assertZero("byte_selector_boolean", try arena.mul(x[1], try arena.sub(x[1], one, span), span), null, .semantic, span),
        try arena.assertZero("digest_selector_boolean", try arena.mul(x[2], try arena.sub(x[2], one, span), span), null, .semantic, span),
        try arena.assertZero("active_boolean", try arena.mul(x[6], try arena.sub(x[6], one, span), span), null, .semantic, span),
        try arena.assertZero("exactly_one_role", try arena.sub(try arena.add(x[1], x[2], span), x[6], span), null, .semantic, span),
        try arena.assertZero("expected_value", try arena.mul(x[6], try arena.sub(x[0], x[5], span), span), null, .semantic, span),
    };
    const events = [RELATION_EVENT_COUNT]lang.types.EffectId{
        (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_vm_public_io_word, .role = .consume, .values = &.{ x[3], x[4], x[0] }, .weight = x[1] }}, span))[0],
        (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_vm_public_io_digest, .role = .emit, .values = &.{ x[3], x[4], x[0] }, .weight = x[2] }}, span))[0],
    };
    return Definition{ .arena = arena, .constraints = constraints, .events = events };
}

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    rows: []Row,

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }
};

/// `statement` is verifier-owned, never read from candidate proof metadata.
/// The final 16 rows export statement digest limbs to a separate statement
/// consumer; they do not self-close that relation.
pub fn fixedSchedule(allocator: std.mem.Allocator, policy: *const ingress.VerifierExpectedIo, statement: ExpectedDigests) !Schedule {
    const expected = binding.Expected{
        .input_start = policy.input_start,
        .input = policy.input,
        .output_len_addr = policy.output_len_addr,
        .output_data_addr = policy.output_data_addr,
        .output = policy.output,
    };
    try expected.validate();
    if (!std.meta.eql(try binding.inputDigest(expected), statement.input)) return error.InputDigestMismatch;
    if (!std.meta.eql(try binding.outputDigest(expected), statement.output)) return error.OutputDigestMismatch;
    const total = std.math.add(usize, std.math.add(usize, policy.input.len, policy.output.len) catch return error.IoRangeOutOfBounds, 20) catch return error.IoRangeOutOfBounds;
    const rows = try allocator.alloc(Row, total);
    errdefer allocator.free(rows);
    var at: usize = 0;
    for (policy.input, 0..) |byte, index| {
        rows[at] = makeRow(true, bridge.INPUT_BYTE_KIND, @intCast(index), byte);
        at += 1;
    }
    for (policy.output, 0..) |byte, index| {
        rows[at] = makeRow(true, bridge.OUTPUT_BYTE_KIND, @intCast(index), byte);
        at += 1;
    }
    const output_len: u32 = @intCast(policy.output.len);
    for (0..4) |index| {
        rows[at] = makeRow(true, bridge.OUTPUT_LENGTH_BYTE_KIND, @intCast(index), @truncate(output_len >> @as(u5, @intCast(index * 8))));
        at += 1;
    }
    for (statement.input, 0..) |word, index| {
        rows[at] = makeRow(false, INPUT_DIGEST_KIND, @intCast(index), word);
        at += 1;
    }
    for (statement.output, 0..) |word, index| {
        rows[at] = makeRow(false, OUTPUT_DIGEST_KIND, @intCast(index), word);
        at += 1;
    }
    std.debug.assert(at == rows.len);
    return .{ .allocator = allocator, .rows = rows };
}

fn makeRow(byte: bool, kind: u32, index: u32, value: u32) Row {
    var row: Row = @splat(M31.zero());
    row[0] = M31.fromCanonical(value);
    row[1] = M31.fromCanonical(@intFromBool(byte));
    row[2] = M31.fromCanonical(@intFromBool(!byte));
    row[3] = M31.fromCanonical(kind);
    row[4] = M31.fromCanonical(index);
    row[5] = row[0];
    row[6] = M31.one();
    return row;
}
