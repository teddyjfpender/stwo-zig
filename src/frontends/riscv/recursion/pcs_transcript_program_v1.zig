//! Value-independent PCS transcript schedule and shared operation writer.
//! Callers supply admitted geometry; captured values never select constants.
const std = @import("std");
const recording = @import("recording_poseidon_channel_v4.zig");

pub const Context = enum(u32) {
    tree0 = 1,
    tree1,
    manifest,
    authority,
    session,
    interaction_pow,
    relations,
    claims,
    boundary,
    tree2,
    composition,
    tree3,
    oods,
    samples,
    deep,
    fri,
    last_layer,
    pcs_pow,
    queries,
};
pub const Source = enum(u8) {
    none,
    manifest_header,
    manifest_seal,
    registry_seal,
    authority_header,
    statement,
    session_header,
    session_seal,
    claim_count,
    claim_metadata,
    claim_value,
    claim_seal,
    boundary,
    commitment,
    nonce,
    sampled_values,
    fri_commitment,
    last_layer,
    provider_partial,
    canonical_preprocessed_root,
    canonical_boundary_header,
    canonical_wire_boundary,
    session_key,
    common_preprocessed_root,

    pub fn isConstantPayload(self: Source) bool {
        return self != .none and !self.witnessDependent();
    }

    pub fn witnessDependent(self: Source) bool {
        return switch (self) {
            .none, .manifest_header, .manifest_seal, .registry_seal, .authority_header, .session_header, .claim_count, .claim_metadata, .canonical_preprocessed_root, .canonical_boundary_header, .session_key, .common_preprocessed_root => false,
            else => true,
        };
    }
};
pub const Draw = enum(u8) { none, relation, composition, oods, deep, fri_alpha, queries };
pub const Operation = struct {
    context: Context,
    effect: recording.Effect,
    payload_words: u32 = 0,
    source: Source = .none,
    item: u32 = 0,
    draw: Draw = .none,
    draw_word_count: u32 = 0,
    pow_bits: u32 = 0,
    constant_words: [16]u32 = .{0} ** 16,
};
pub const Error = error{ InvalidRecursiveTranscriptProgram, ArithmeticOverflow };

/// The shared PCS suffix begins after the interaction commitment. Its shape
/// comes from an admitted profile; captured values are never program constants.
pub const PcsShape = struct {
    sampled_value_count: usize,
    fri_layer_count: usize,
    last_layer_coefficient_count: usize,
    query_count: usize,
    pow_bits: u32,
};

pub fn initPcsOperations(allocator: std.mem.Allocator, shape: PcsShape) ![]Operation {
    var list: std.ArrayList(Operation) = .empty;
    errdefer list.deinit(allocator);
    try appendPcsTranscript(Writer{ .allocator = allocator, .list = &list }, shape);
    return list.toOwnedSlice(allocator);
}

pub fn appendPcsTranscript(writer: anytype, shape: PcsShape) !void {
    if (shape.sampled_value_count == 0 or shape.fri_layer_count == 0 or
        shape.fri_layer_count > 30 or shape.last_layer_coefficient_count == 0 or
        shape.query_count == 0) return error.InvalidRecursiveTranscriptProgram;
    _ = try checked(shape.query_count);
    try writer.draw(.composition, .composition, 0, 4);
    try writer.mix(.tree3, .commitment, 3, 8);
    try writer.draw(.oods, .oods, 0, 4);
    try writer.mix(.samples, .sampled_values, 0, try words(shape.sampled_value_count));
    try writer.draw(.deep, .deep, 0, 4);
    for (0..shape.fri_layer_count) |i| {
        try writer.mix(.fri, .fri_commitment, i, 8);
        try writer.draw(.fri, .fri_alpha, i, 4);
    }
    try writer.mix(.last_layer, .last_layer, 0, try words(shape.last_layer_coefficient_count));
    try writer.pow(.pcs_pow, 1, shape.pow_bits);
    var query: usize = 0;
    while (query < shape.query_count) : (query += recording.RATE)
        try writer.draw(.queries, .queries, query, @min(recording.RATE, shape.query_count - query));
}

pub const Writer = struct {
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Operation),

    pub fn mix(self: Writer, context: Context, source: Source, item: usize, count: usize) !void {
        if (source.isConstantPayload()) return error.InvalidRecursiveTranscriptProgram;
        try self.list.append(self.allocator, .{
            .context = context,
            .effect = .mix,
            .payload_words = try checked(count),
            .source = source,
            .item = try checked(item),
        });
    }
    pub fn mixWords(self: Writer, context: Context, source: Source, item: usize, values: []const u32) !void {
        if (!source.isConstantPayload() or values.len > 8) return error.InvalidRecursiveTranscriptProgram;
        var operation = Operation{ .context = context, .effect = .mix, .payload_words = try checked(2 * values.len), .source = source, .item = try checked(item) };
        for (values, 0..) |word, index| {
            operation.constant_words[2 * index] = word & 0xffff;
            operation.constant_words[2 * index + 1] = word >> 16;
        }
        try self.list.append(self.allocator, operation);
    }
    pub fn mixCanonicalWords(self: Writer, context: Context, source: Source, item: usize, values: []const u32) !void {
        if (!source.isConstantPayload() or values.len > 16) return error.InvalidRecursiveTranscriptProgram;
        var operation = Operation{ .context = context, .effect = .mix, .payload_words = try checked(values.len), .source = source, .item = try checked(item) };
        for (values) |word| if (word >= @import("stwo_core").fields.m31.Modulus) return error.InvalidRecursiveTranscriptProgram;
        @memcpy(operation.constant_words[0..values.len], values);
        try self.list.append(self.allocator, operation);
    }
    pub fn mixDigest(self: Writer, context: Context, source: Source, digest: [32]u8) !void {
        var values: [8]u32 = undefined;
        for (&values, 0..) |*word, index| word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
        try self.mixWords(context, source, 0, &values);
    }
    pub fn draw(self: Writer, context: Context, kind: Draw, item: usize, count: usize) !void {
        try self.list.append(self.allocator, .{
            .context = context,
            .effect = .draw,
            .draw = kind,
            .item = try checked(item),
            .draw_word_count = try checked(count),
        });
    }
    pub fn pow(self: Writer, context: Context, item: u32, bits: u32) !void {
        try self.list.append(self.allocator, .{
            .context = context,
            .effect = .pow,
            .payload_words = 4,
            .source = .nonce,
            .item = item,
            .pow_bits = bits,
        });
    }
};
fn checked(value: usize) Error!u32 {
    // All program coordinates become canonical base-field preprocessing.
    if (value >= 0x7fff_ffff) return error.ArithmeticOverflow;
    return @intCast(value);
}
fn words(count: usize) Error!u32 {
    return checked(std.math.mul(usize, count, 4) catch return error.ArithmeticOverflow);
}
