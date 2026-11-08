//! Parser and owner for optional transcript-parity fixtures.

const std = @import("std");
const stwo = @import("stwo");
const protocol_recipes = stwo.backends.metal.protocol_recipes;

pub const TranscriptReferenceFixture = struct {
    allocator: std.mem.Allocator,
    input_22: []u32,
    input_23: [8]u32,
    input_25: []u32,
    interaction_nonce: u64,
    expected_output_1: [8]u32,
    expected_output_2: [4]u32,
    expected_output_3: [4]u32,
    expected_output_4: [4]u32,
    fri_inputs: [][8]u32,
    input_30: [4]u32,
    input_31: [2]u32,
    query_nonce: u64,

    pub fn read(allocator: std.mem.Allocator, path: []const u8) !TranscriptReferenceFixture {
        const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
        defer allocator.free(encoded);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidTranscriptReference;
        const inputs = parsed.value.object.get("inputs") orelse return error.InvalidTranscriptReference;
        const outputs = parsed.value.object.get("expected_outputs") orelse return error.InvalidTranscriptReference;
        const fri_inputs_value = parsed.value.object.get("fri_inputs") orelse return error.InvalidTranscriptReference;
        if (inputs != .object or outputs != .object or fri_inputs_value != .array or
            fri_inputs_value.array.items.len == 0 or
            fri_inputs_value.array.items.len > protocol_recipes.FriGeometry.max_round_count)
            return error.InvalidTranscriptReference;
        const nonce_words = try jsonFixedWords(2, inputs.object.get("21") orelse return error.InvalidTranscriptReference);
        const z = try jsonFixedWords(4, parsed.value.object.get("z") orelse return error.InvalidTranscriptReference);
        const alpha = try jsonFixedWords(4, parsed.value.object.get("alpha") orelse return error.InvalidTranscriptReference);
        var expected_output_1: [8]u32 = undefined;
        @memcpy(expected_output_1[0..4], &z);
        @memcpy(expected_output_1[4..8], &alpha);
        const input_25_value = inputs.object.get("25") orelse return error.InvalidTranscriptReference;
        const input_22_value = inputs.object.get("22") orelse return error.InvalidTranscriptReference;
        if (input_22_value != .array or input_22_value.array.items.len == 0)
            return error.InvalidTranscriptReference;
        const input_22 = try allocator.alloc(u32, input_22_value.array.items.len);
        errdefer allocator.free(input_22);
        try jsonWords(input_22_value, input_22);
        if (input_25_value != .array or input_25_value.array.items.len == 0)
            return error.InvalidTranscriptReference;
        const input_25 = try allocator.alloc(u32, input_25_value.array.items.len);
        errdefer allocator.free(input_25);
        try jsonWords(input_25_value, input_25);
        const fri_inputs = try allocator.alloc([8]u32, fri_inputs_value.array.items.len);
        errdefer allocator.free(fri_inputs);
        for (fri_inputs_value.array.items, 0..) |fri_input, index| {
            if (fri_input != .object) return error.InvalidTranscriptReference;
            const ordinal = fri_input.object.get("ordinal") orelse return error.InvalidTranscriptReference;
            if (ordinal != .integer or ordinal.integer != 65536 + @as(i64, @intCast(index)) * 4)
                return error.InvalidTranscriptReference;
            fri_inputs[index] = try jsonFixedWords(
                8,
                fri_input.object.get("words") orelse return error.InvalidTranscriptReference,
            );
        }
        const input_31 = try jsonFixedWords(2, inputs.object.get("31") orelse return error.InvalidTranscriptReference);
        return .{
            .allocator = allocator,
            .input_22 = input_22,
            .input_23 = try jsonFixedWords(8, inputs.object.get("23") orelse return error.InvalidTranscriptReference),
            .input_25 = input_25,
            .interaction_nonce = @as(u64, nonce_words[0]) | (@as(u64, nonce_words[1]) << 32),
            .expected_output_1 = expected_output_1,
            .expected_output_2 = try jsonFixedWords(4, outputs.object.get("2") orelse return error.InvalidTranscriptReference),
            .expected_output_3 = try jsonFixedWords(4, outputs.object.get("3") orelse return error.InvalidTranscriptReference),
            .expected_output_4 = try jsonFixedWords(4, outputs.object.get("4") orelse return error.InvalidTranscriptReference),
            .fri_inputs = fri_inputs,
            .input_30 = try jsonFixedWords(4, inputs.object.get("30") orelse return error.InvalidTranscriptReference),
            .input_31 = input_31,
            .query_nonce = @as(u64, input_31[0]) | (@as(u64, input_31[1]) << 32),
        };
    }

    pub fn deinit(self: *TranscriptReferenceFixture) void {
        self.allocator.free(self.input_22);
        self.allocator.free(self.input_25);
        self.allocator.free(self.fri_inputs);
        self.* = undefined;
    }
};

fn jsonFixedWords(comptime count: usize, value: std.json.Value) ![count]u32 {
    var result: [count]u32 = undefined;
    try jsonWords(value, &result);
    return result;
}

fn jsonWords(value: std.json.Value, destination: []u32) !void {
    if (value != .array or value.array.items.len != destination.len)
        return error.InvalidTranscriptReference;
    for (value.array.items, destination) |source, *word| {
        if (source != .integer or source.integer < 0 or source.integer > std.math.maxInt(u32))
            return error.InvalidTranscriptReference;
        word.* = @intCast(source.integer);
    }
}

test "fixed transcript words reject shape and range drift" {
    var valid = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "[1,2]", .{});
    defer valid.deinit();
    try std.testing.expectEqual([2]u32{ 1, 2 }, try jsonFixedWords(2, valid.value));
    try std.testing.expectError(error.InvalidTranscriptReference, jsonFixedWords(3, valid.value));

    var invalid = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "[1,-1]", .{});
    defer invalid.deinit();
    try std.testing.expectError(error.InvalidTranscriptReference, jsonFixedWords(2, invalid.value));
}
