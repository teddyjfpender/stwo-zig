const std = @import("std");
const statement = @import("opstack_frontend_component").statement;

/// Kona `transition.rs` receiver vector shape: chain 10, schema OD.
const sample = statement.Output{ .digest = [_]u8{0xa5} ** 32, .chain_id = 10, .schema = .derivation };

test "statement: encode and decode round-trip the 43-byte layout" {
    const bytes = sample.encode();
    try std.testing.expectEqual(@as(u8, 1), bytes[32]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 0, 0, 0, 0, 0 }, bytes[33..41]);
    try std.testing.expectEqualSlices(u8, "OD", bytes[41..43]);
    const decoded = try statement.decode(&bytes);
    try std.testing.expectEqual(sample.chain_id, decoded.chain_id);
    try std.testing.expectEqual(sample.schema, decoded.schema);
    try std.testing.expectEqualSlices(u8, &sample.digest, &decoded.digest);
}

test "statement: unknown version and schema are rejected" {
    var bytes = sample.encode();
    bytes[32] = 2;
    try std.testing.expectError(error.InvalidOutputVersion, statement.decode(&bytes));
    bytes = sample.encode();
    bytes[41] = 'X';
    try std.testing.expectError(error.InvalidOutputSchema, statement.decode(&bytes));
}

test "statement: expected output hex is exact and strict" {
    const bytes = (statement.Output{ .digest = [_]u8{0} ** 32, .chain_id = 10, .schema = .execution }).encode();
    var hex = std.fmt.bytesToHex(bytes, .lower);
    try std.testing.expectEqualSlices(u8, &bytes, &(try statement.expectedFromHex(&hex)));
    try std.testing.expectError(error.InvalidOutputHex, statement.expectedFromHex(hex[0..84]));
    hex[0] = 'z';
    try std.testing.expectError(error.InvalidOutputHex, statement.expectedFromHex(&hex));
}

test "statement: binding rejects any single flipped byte" {
    const expected = sample.encode();
    try std.testing.expect(try statement.binds(&expected, &expected));
    for (0..32) |i| {
        var proven = expected;
        proven[i] ^= 1;
        try std.testing.expect(!(try statement.binds(&proven, &expected)));
    }
}
