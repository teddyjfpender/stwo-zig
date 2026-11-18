const std = @import("std");
const Entry = @import("stwo_core").error_codes.Entry;
const DecodeError = @import("circuit_serialize.zig").DecodeError;

const postcard = @import("postcard_error_codes");
const PostcardPreflightError = postcard.Error;

/// Append-only meanings owned by the circuit binary decoder, not error ordinals.
pub const table = [_]Entry{
    .{ .tag = "NotEnoughData", .code = 0x5001, .class = .invalid_input, .since = "0.2.0" },
    .{ .tag = "ValueOutOfRange", .code = 0x5002, .class = .invalid_input, .since = "0.2.0" },
} ++ postcard.table ++ [_]Entry{
    .{ .tag = "InvalidJson", .code = 0x5201, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "MissingField", .code = 0x5202, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidValue", .code = 0x5203, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "OutOfMemory", .code = 0x5204, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyTraceRange", .code = 0x5205, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "UnknownConfig", .code = 0x5301, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "UnsupportedLeaf", .code = 0x5302, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "NoLeafVerifiers", .code = 0x5303, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "NotExactlyOneMultiverifier", .code = 0x5304, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "TooDeep", .code = 0x5401, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "InvalidProofShape", .code = 0x5501, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "OutOfMemory", .code = 0x5503, .class = .resource_exhausted, .since = "1.0.0-rc.4" },
    .{ .tag = "EndOfStream", .code = 0x5601, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "ValueOutOfRange", .code = 0x5602, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "InvalidDiscriminant", .code = 0x5603, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "InvalidLinePoly", .code = 0x5604, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "TrailingData", .code = 0x5605, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "OutOfMemory", .code = 0x5606, .class = .resource_exhausted, .since = "1.0.0-rc.5" },
    .{ .tag = "InvalidFeltJson", .code = 0x5701, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "NonCanonicalFelt", .code = 0x5702, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "ValueOutOfRange", .code = 0x5703, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "OutOfMemory", .code = 0x5704, .class = .resource_exhausted, .since = "1.0.0-rc.5" },
    .{ .tag = "InvalidDecimalFelt", .code = 0x5801, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "OutOfMemory", .code = 0x5802, .class = .resource_exhausted, .since = "1.0.0-rc.5" },
    .{ .tag = "ShapeMismatch", .code = 0x5502, .class = .invalid_input, .since = "1.0.0-rc.5" },
    .{ .tag = "OutOfMemory", .code = 0x5901, .class = .resource_exhausted, .since = "1.0.0-rc.5" },
    .{ .tag = "InvalidLinePoly", .code = 0x5902, .class = .invalid_input, .since = "1.0.0-rc.5" },
};
pub fn fromCircuitDecode(err: DecodeError) Entry {
    return switch (err) {
        error.NotEnoughData => table[0],
        error.ValueOutOfRange => table[1],
    };
}
pub const fromPostcard = postcard.fromPostcard;
pub fn fromJsonRead(err: @import("json_text.zig").ReadError) Entry {
    return switch (err) {
        error.InvalidJson => table[12],
        error.MissingField => table[13],
        error.InvalidValue => table[14],
        error.OutOfMemory => table[15],
    };
}
pub fn fromRegistryDefinition(err: @import("registry_definition.zig").ReadError) Entry {
    return switch (err) {
        error.EmptyTraceRange => table[16],
        error.InvalidJson => fromJsonRead(error.InvalidJson),
        error.MissingField => fromJsonRead(error.MissingField),
        error.InvalidValue => fromJsonRead(error.InvalidValue),
        error.OutOfMemory => fromJsonRead(error.OutOfMemory),
    };
}
pub fn fromRegistryQuery(err: @import("registry.zig").QueryError) Entry {
    return switch (err) {
        error.UnknownConfig => table[17],
        error.UnsupportedLeaf => table[18],
        error.NoLeafVerifiers => table[19],
        error.NotExactlyOneMultiverifier => table[20],
    };
}
pub fn fromPacked(err: @import("packed_node.zig").ReadError) Entry {
    return switch (err) {
        error.TooDeep => table[21],
        error.InvalidJson => fromJsonRead(error.InvalidJson),
        error.MissingField => fromJsonRead(error.MissingField),
        error.InvalidValue => fromJsonRead(error.InvalidValue),
        error.OutOfMemory => fromJsonRead(error.OutOfMemory),
    };
}
pub fn fromCircuitConfig(err: @import("circuit_serialize.zig").ConfigError) Entry {
    return switch (err) {
        error.InvalidProofShape => table[22],
    };
}
pub const CircuitInputError = DecodeError || @import("circuit_serialize.zig").ConfigError || std.mem.Allocator.Error;
pub fn fromCircuitInput(err: CircuitInputError) Entry {
    return switch (err) {
        error.NotEnoughData => fromCircuitDecode(error.NotEnoughData),
        error.ValueOutOfRange => fromCircuitDecode(error.ValueOutOfRange),
        error.InvalidProofShape => fromCircuitConfig(error.InvalidProofShape),
        error.OutOfMemory => table[23],
    };
}
pub fn fromFeltPrimitive(err: @import("interop_felt_json").DecodeError) Entry {
    return switch (err) {
        error.EndOfStream => table[24],
        error.ValueOutOfRange => table[25],
        error.InvalidDiscriminant => table[26],
        error.InvalidLinePoly => table[27],
    };
}
pub fn fromFeltStream(err: @import("circuit_felt_stream.zig").DecodeError) Entry {
    return switch (err) {
        error.TrailingData => table[28],
        error.OutOfMemory => table[29],
        error.EndOfStream => fromFeltPrimitive(error.EndOfStream),
        error.ValueOutOfRange => fromFeltPrimitive(error.ValueOutOfRange),
        error.InvalidDiscriminant => fromFeltPrimitive(error.InvalidDiscriminant),
        error.InvalidLinePoly => fromFeltPrimitive(error.InvalidLinePoly),
    };
}
pub fn fromFeltJson(err: @import("interop_felt_json").FeltJsonError) Entry {
    return switch (err) {
        error.InvalidFeltJson => table[30],
        error.NonCanonicalFelt => table[31],
        error.ValueOutOfRange => table[32],
        error.OutOfMemory => table[33],
    };
}
pub fn fromDecimal(err: @import("blake2_felt252.zig").Error) Entry {
    return switch (err) {
        error.InvalidDecimalFelt => table[34],
        error.OutOfMemory => table[35],
    };
}
pub const CircuitEncodeError = @import("circuit_serialize.zig").ShapeError || @import("circuit_serialize.zig").ConfigError || std.mem.Allocator.Error;
pub fn fromCircuitEncode(err: CircuitEncodeError) Entry {
    return switch (err) {
        error.ShapeMismatch => table[36],
        error.OutOfMemory => table[37],
        error.InvalidProofShape => fromCircuitConfig(error.InvalidProofShape),
    };
}
pub fn fromFeltEncode(err: @import("interop_felt_json").EncodeError) Entry {
    return switch (err) {
        error.InvalidLinePoly => table[38],
    };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}

test "api signature: circuit decode codes require the owned error set" {
    const signature = @typeInfo(@TypeOf(fromCircuitDecode)).@"fn";
    try std.testing.expectEqual(@as(usize, 1), signature.params.len);
    try std.testing.expect(signature.params[0].type.? == @import("circuit_serialize.zig").DecodeError);
    try std.testing.expect(signature.return_type.? == @import("stwo_core").error_codes.Entry);
}

test "circuit decode code table pins meanings classes versions and unknown refusal" {
    try std.testing.expectEqual(@as(usize, 39), table.len);
    const errors = [_]@import("circuit_serialize.zig").DecodeError{ error.NotEnoughData, error.ValueOutOfRange };
    for (errors, [_]u16{ 0x5001, 0x5002 }) |err, code| {
        const entry = fromCircuitDecode(err);
        try std.testing.expectEqual(code, entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqual(@import("stwo_core").error_codes.Class.invalid_input, entry.class);
        try std.testing.expectEqualStrings("0.2.0", entry.since);
        try std.testing.expectEqualStrings(entry.tag, lookup(code).?.tag);
    }
    for ([_]u16{ 0, 0x1001, 0x4001, 0x5000, 0x5003, 65535 }) |code| try std.testing.expect(lookup(code) == null);
}

test "postcard preflight codes pin exact owned error set and append-only meanings" {
    const Error = PostcardPreflightError;
    try std.testing.expect(@typeInfo(@TypeOf(fromPostcard)).@"fn".params[0].type.? == Error);
    const errors = [_]Error{ error.EndOfStream, error.InvalidOptionTag, error.InvalidProofConfig, error.InvalidProofShape, error.InvalidPreflightShape, error.NonCanonicalM31, error.NonCanonicalVarint, error.ProofResourceLimitExceeded, error.TrailingProofBytes, error.VarintOverflow };
    for (errors, 0..) |err, index| {
        const entry = fromPostcard(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x5101 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqual(if (err == error.ProofResourceLimitExceeded) @import("stwo_core").error_codes.Class.resource_exhausted else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0, 0x1101, 0x2001, 0x4001, 0x5100, 0x510b, 65535 }) |id| try std.testing.expect(lookup(id) == null);
}

test "recursion JSON codes pin owned parser signatures and append-only meanings" {
    const Error = @import("json_text.zig").ReadError;
    const DefinitionError = @import("registry_definition.zig").ReadError;
    try std.testing.expect(@typeInfo(@TypeOf(fromJsonRead)).@"fn".params[0].type.? == Error);
    try std.testing.expect(@typeInfo(@TypeOf(fromRegistryDefinition)).@"fn".params[0].type.? == DefinitionError);
    const errors = [_]DefinitionError{ error.InvalidJson, error.MissingField, error.InvalidValue, error.OutOfMemory, error.EmptyTraceRange };
    for (errors, 0..) |err, index| {
        const entry = fromRegistryDefinition(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x5201 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.3", entry.since);
        try std.testing.expectEqual(if (err == error.OutOfMemory) @import("stwo_core").error_codes.Class.resource_exhausted else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, lookup(entry.code).?.tag);
    }
    for ([_]Error{ error.InvalidJson, error.MissingField, error.InvalidValue, error.OutOfMemory }) |err|
        try std.testing.expectEqual(fromRegistryDefinition(err).code, fromJsonRead(err).code);
    for ([_]u16{ 0x5200, 0x5206, 65535 }) |code| try std.testing.expect(lookup(code) == null);
}

test "recursion registry packed and config codes pin exact concrete input origins" {
    const Query = @import("registry.zig").QueryError;
    try std.testing.expect(@typeInfo(@TypeOf(fromRegistryQuery)).@"fn".params[0].type.? == Query);
    const queries = [_]Query{ error.UnknownConfig, error.UnsupportedLeaf, error.NoLeafVerifiers, error.NotExactlyOneMultiverifier };
    for (queries, 0..) |err, index| {
        const entry = fromRegistryQuery(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x5301 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.4", entry.since);
    }
    try std.testing.expectEqual(@as(u16, 0x5401), fromPacked(error.TooDeep).code);
    try std.testing.expectEqual(@as(u16, 0x5204), fromPacked(error.OutOfMemory).code);
    try std.testing.expectEqual(@as(u16, 0x5501), fromCircuitConfig(error.InvalidProofShape).code);
    try std.testing.expectEqual(@as(u16, 0x5503), fromCircuitInput(error.OutOfMemory).code);
    for ([_]u16{ 0x5300, 0x5305, 0x5400, 0x5402, 0x5500, 0x5504 }) |id| try std.testing.expect(lookup(id) == null);
}

test "final framing codes pin public codec errors and append-only meanings" {
    const errors = [_]@import("circuit_felt_stream.zig").DecodeError{ error.EndOfStream, error.ValueOutOfRange, error.InvalidDiscriminant, error.InvalidLinePoly, error.TrailingData, error.OutOfMemory };
    try std.testing.expect(@typeInfo(@TypeOf(fromFeltStream)).@"fn".params[0].type.? == @import("circuit_felt_stream.zig").DecodeError);
    for (errors, 0..) |err, index| {
        const entry = fromFeltStream(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x5601 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.5", entry.since);
        try std.testing.expectEqual(if (err == error.OutOfMemory) @import("stwo_core").error_codes.Class.resource_exhausted else .invalid_input, entry.class);
    }
    try std.testing.expectEqual(@as(u16, 0x5502), fromCircuitEncode(error.ShapeMismatch).code);
    try std.testing.expectEqual(@as(u16, 0x5901), fromCircuitEncode(error.OutOfMemory).code);
    try std.testing.expectEqual(@as(u16, 0x5902), fromFeltEncode(error.InvalidLinePoly).code);
    try std.testing.expectEqual(@as(u16, 0x5801), fromDecimal(error.InvalidDecimalFelt).code);
    try std.testing.expectEqual(@as(u16, 0x5802), fromDecimal(error.OutOfMemory).code);
    for ([_]u16{ 0x5600, 0x5607, 0x5700, 0x5705, 0x5800, 0x5803, 0x5900, 0x5903 }) |code| try std.testing.expect(lookup(code) == null);
}
