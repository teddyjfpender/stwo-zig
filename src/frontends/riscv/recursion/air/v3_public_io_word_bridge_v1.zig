//! Dormant V3 public-I/O byte bridge from an independently owned memory word.
//!
//! A source component must emit the six-field recursion_wire tuple from the
//! native VM's authenticated input or output memory boundary. This row consumes
//! it once, constrains every selected byte against verifier-owned expected I/O,
//! and exports canonical bytes in V3-only scopes. Neither a host-copied sparse
//! word nor a self-closed relation can authorize this source. A later edge-hash
//! component must consume the exported bytes and bind its digest to the V3
//! statement; production activation remains closed until that path is proven.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const expected_io = @import("../segment_public_io_binding_v1.zig");
const ingress = @import("../segment_public_io_ingress_v2.zig");

pub const STABLE_NAME = "recursion.v3_public_io_word_bridge.v1";
pub const FORMAT_VERSION: u16 = 1;
pub const PROOF_ACTIVATION = false;
pub const INPUT_BYTE_KIND: u32 = 2;
pub const OUTPUT_BYTE_KIND: u32 = 3;
pub const OUTPUT_LENGTH_BYTE_KIND: u32 = 4;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 4;
pub const PREPROCESSED_COLUMN_COUNT: usize = 17;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 18;
pub const RELATION_EVENT_COUNT: usize = 7;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 4;
pub const INTERACTION_COLUMN_COUNT: usize = 16;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX = "0fc5b2cd7b368120721428d3f9378e9ff9d7ee5b407ae59e8912c4820b4c0ece";
pub const SEMANTIC_DIGEST: [32]u8 = hexDigest(SEMANTIC_DIGEST_HEX);

pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Role = enum { input, output, output_length };

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
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0)
            return error.InvalidV3PublicIoWordBridge;
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
    var ids: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&ids, 0..) |*id, index| {
        var name: [72]u8 = undefined;
        id.* = try arena.input(
            try std.fmt.bufPrint(&name, "{s}.column_{d}", .{ STABLE_NAME, index }),
            if (index < 4 or index >= 17) .byte else if (index == 4 or (index >= 13 and index < 17)) .selector else .felt,
            span,
        );
    }
    const one = try arena.constantField(1, span);
    const four = try arena.constantField(4, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId = undefined;
    var at: usize = 0;
    constraints[at] = try arena.assertZero("v3_io_active_boolean", try arena.mul(ids[4], try arena.sub(ids[4], one, span), span), null, .semantic, span);
    at += 1;
    constraints[at] = try arena.assertZero("v3_io_word_address", try arena.mul(ids[4], try arena.sub(try arena.mul(ids[6], four, span), ids[7], span), span), null, .semantic, span);
    at += 1;
    for (0..4) |i| {
        var name: [64]u8 = undefined;
        const mask = ids[13 + i];
        const actual = ids[i];
        const expected = ids[17 + i];
        constraints[at] = try arena.assertZero(try std.fmt.bufPrint(&name, "v3_io_mask_{d}_boolean", .{i}), try arena.mul(mask, try arena.sub(mask, one, span), span), null, .semantic, span);
        at += 1;
        constraints[at] = try arena.assertZero(try std.fmt.bufPrint(&name, "v3_io_mask_{d}_requires_active", .{i}), try arena.mul(mask, try arena.sub(one, ids[4], span), span), null, .semantic, span);
        at += 1;
        constraints[at] = try arena.assertZero(try std.fmt.bufPrint(&name, "v3_io_byte_{d}_expected", .{i}), try arena.mul(mask, try arena.sub(actual, expected, span), span), null, .semantic, span);
        at += 1;
        constraints[at] = try arena.assertZero(try std.fmt.bufPrint(&name, "v3_io_byte_{d}_inactive_zero", .{i}), try arena.mul(try arena.sub(one, ids[4], span), actual, span), null, .semantic, span);
        at += 1;
    }
    std.debug.assert(at == constraints.len);

    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    events[0] = (try effects.appendGroup(1, &arena, .{.{
        .domain = .recursion_wire,
        .role = .consume,
        .values = &(.{ ids[5], ids[6] } ++ ids[0..4].*),
        .weight = ids[4],
    }}, span))[0];
    for (0..4) |i| events[1 + i] = (try effects.appendGroup(1, &arena, .{.{
        .domain = .recursion_vm_public_io_word,
        .role = .emit,
        .values = &.{ ids[8], ids[9 + i], ids[i] },
        .weight = ids[13 + i],
    }}, span))[0];
    for (0..2) |i| events[5 + i] = (try effects.appendGroup(1, &arena, .{.{
        .domain = .range_check_8_8,
        .role = .request,
        .values = ids[i * 2 ..][0..2],
        .weight = ids[4],
    }}, span))[0];
    return .{ .arena = arena, .constraints = constraints, .events = events };
}

/// Independently reconstruct this fixed row from an external verifier request.
/// One aligned source word is admitted per row, including partial edge words.
pub fn fixedRow(policy: *const ingress.VerifierExpectedIo, role: Role, address: u32, source_circuit: u32) !Row {
    const expected = expected_io.Expected{
        .input_start = policy.input_start,
        .input = policy.input,
        .output_len_addr = policy.output_len_addr,
        .output_data_addr = policy.output_data_addr,
        .output = policy.output,
    };
    try expected.validate();
    const output_end = @as(u64, expected.output_data_addr) + expected.output.len;
    if (expected.output.len > 0 and
        @as(u64, expected.output_data_addr) < @as(u64, expected.output_len_addr) + 4 and
        output_end > expected.output_len_addr)
        return error.OverlappingOutputLengthAndBytes;
    if (address & 3 != 0 or address >= (1 << 30) or source_circuit == 0 or source_circuit >= core.fields.m31.Modulus)
        return error.InvalidPublicIoWordAddress;
    const start: u32 = switch (role) {
        .input => expected.input_start,
        .output => expected.output_data_addr,
        .output_length => expected.output_len_addr,
    };
    const bytes: []const u8 = switch (role) {
        .input => expected.input,
        .output => expected.output,
        .output_length => &.{},
    };
    if (role == .output_length and address != expected.output_len_addr)
        return error.InvalidPublicIoWordAddress;
    if (role != .output_length and
        (bytes.len == 0 or @as(u64, address) + 4 <= start or address >= @as(u64, start) + bytes.len))
        return error.InvalidPublicIoWordAddress;
    var row: Row = @splat(M31.zero());
    row[4] = M31.one();
    row[5] = M31.fromCanonical(source_circuit);
    row[6] = M31.fromCanonical(address >> 2);
    row[7] = M31.fromCanonical(address);
    row[8] = M31.fromCanonical(switch (role) {
        .input => INPUT_BYTE_KIND,
        .output => OUTPUT_BYTE_KIND,
        .output_length => OUTPUT_LENGTH_BYTE_KIND,
    });
    for (0..4) |byte_offset| {
        const current = @as(u64, address) + byte_offset;
        const selected = role == .output_length or
            (current >= start and current < @as(u64, start) + bytes.len);
        if (!selected) continue;
        const byte_index: usize = if (role == .output_length) byte_offset else @intCast(current - start);
        const value: u8 = if (role == .output_length)
            @truncate(@as(u32, @intCast(expected.output.len)) >> @as(u5, @intCast(byte_offset * 8)))
        else
            bytes[byte_index];
        row[9 + byte_offset] = M31.fromCanonical(@intCast(byte_index));
        row[13 + byte_offset] = M31.one();
        row[17 + byte_offset] = M31.fromCanonical(value);
    }
    return row;
}

pub fn logicalRow(
    policy: *const ingress.VerifierExpectedIo,
    role: Role,
    address: u32,
    source_circuit: u32,
    actual_bytes: [4]u8,
) !Row {
    var result = try fixedRow(policy, role, address, source_circuit);
    for (actual_bytes, 0..) |byte, index| result[index] = M31.fromCanonical(byte);
    return result;
}

fn hexDigest(comptime text: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, text) catch @compileError("invalid V3 I/O bridge digest");
    return result;
}
