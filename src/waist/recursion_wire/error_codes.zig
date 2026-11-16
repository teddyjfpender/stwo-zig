const std = @import("std");
const Entry = @import("stwo_core").error_codes.Entry;
const DecodeError = @import("circuit_serialize.zig").DecodeError;

// Structural ABI contract: the actual postcard consumer asserts exact equality
// with its separately owned parser Error set before mapping any rejection.
const PostcardPreflightError = error{
    EndOfStream,
    InvalidOptionTag,
    InvalidProofConfig,
    InvalidProofShape,
    InvalidPreflightShape,
    NonCanonicalM31,
    NonCanonicalVarint,
    ProofResourceLimitExceeded,
    TrailingProofBytes,
    VarintOverflow,
};

/// Append-only meanings owned by the circuit binary decoder, not error ordinals.
pub const table = [_]Entry{
    .{ .tag = "NotEnoughData", .code = 0x5001, .class = .invalid_input, .since = "0.2.0" },
    .{ .tag = "ValueOutOfRange", .code = 0x5002, .class = .invalid_input, .since = "0.2.0" },
    .{ .tag = "EndOfStream", .code = 0x5101, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidOptionTag", .code = 0x5102, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidProofConfig", .code = 0x5103, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidProofShape", .code = 0x5104, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidPreflightShape", .code = 0x5105, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "NonCanonicalM31", .code = 0x5106, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "NonCanonicalVarint", .code = 0x5107, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "ProofResourceLimitExceeded", .code = 0x5108, .class = .resource_exhausted, .since = "1.0.0-rc.2" },
    .{ .tag = "TrailingProofBytes", .code = 0x5109, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "VarintOverflow", .code = 0x510a, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidJson", .code = 0x5201, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "MissingField", .code = 0x5202, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidValue", .code = 0x5203, .class = .invalid_input, .since = "1.0.0-rc.3" },
    .{ .tag = "OutOfMemory", .code = 0x5204, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyTraceRange", .code = 0x5205, .class = .invalid_input, .since = "1.0.0-rc.3" },
};
pub fn fromCircuitDecode(err: DecodeError) Entry {
    return switch (err) {
        error.NotEnoughData => table[0],
        error.ValueOutOfRange => table[1],
    };
}
/// Only an exact parser-owned catch may call this typed ABI projection.
pub fn fromPostcard(err: PostcardPreflightError) Entry {
    return switch (err) {
        error.EndOfStream => table[2],
        error.InvalidOptionTag => table[3],
        error.InvalidProofConfig => table[4],
        error.InvalidProofShape => table[5],
        error.InvalidPreflightShape => table[6],
        error.NonCanonicalM31 => table[7],
        error.NonCanonicalVarint => table[8],
        error.ProofResourceLimitExceeded => table[9],
        error.TrailingProofBytes => table[10],
        error.VarintOverflow => table[11],
    };
}
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
    try std.testing.expectEqual(@as(usize, 17), table.len);
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
