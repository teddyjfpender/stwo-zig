const std = @import("std");
const Entry = @import("stwo_core").error_codes.Entry;
const DecodeError = @import("circuit_serialize.zig").DecodeError;

/// Append-only meanings owned by the circuit binary decoder, not error ordinals.
pub const table = [_]Entry{
    .{ .tag = "NotEnoughData", .code = 0x5001, .class = .invalid_input, .since = "0.2.0" },
    .{ .tag = "ValueOutOfRange", .code = 0x5002, .class = .invalid_input, .since = "0.2.0" },
};
pub fn fromCircuitDecode(err: DecodeError) Entry {
    return switch (err) {
        error.NotEnoughData => table[0],
        error.ValueOutOfRange => table[1],
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
    try std.testing.expectEqual(@as(usize, 2), table.len);
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
