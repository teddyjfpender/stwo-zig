const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");

// This scoped diagnostic is optional and never changes a primary verdict.
pub fn write(out: *std.Io.Writer, entry: @import("stwo_core").error_codes.Entry) void {
    const known = wire.error_codes.lookup(entry.code) orelse return;
    if (known.class != entry.class or !std.mem.eql(u8, known.tag, entry.tag) or !std.mem.eql(u8, known.since, entry.since)) return;
    std.json.Stringify.value(.{ .schema = "circuit_decode_rejection_v1", .provider = "stwo_circuit_recursion_wire", .origin = "circuit_serialize.deserializeProof", .code = entry.code, .class = entry.class }, .{}, out) catch return;
    out.writeByte('\n') catch return;
    out.flush() catch {};
}

test "decoder rejection JSON is exact and unknown metadata emits no fabricated code" {
    const entry = wire.error_codes.fromCircuitDecode(error.NotEnoughData);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    write(&output.writer, entry);
    try std.testing.expectEqualStrings("{\"schema\":\"circuit_decode_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"circuit_serialize.deserializeProof\",\"code\":20481,\"class\":\"invalid_input\"}\n", output.written());
    for (0..4) |fault| {
        var bad = entry;
        switch (fault) {
            0 => bad.code = 65535,
            1 => bad.class = .internal,
            2 => bad.tag = "ForeignOrigin",
            3 => bad.since = "1.0.0",
            else => unreachable,
        }
        const before = output.written().len;
        write(&output.writer, bad);
        try std.testing.expectEqual(before, output.written().len);
    }
}

test "optional decoder diagnostic write failure cannot replace primary rejection" {
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    write(&failing, wire.error_codes.fromCircuitDecode(error.ValueOutOfRange));
    try std.testing.expectEqual(@as(usize, 0), failing.end);
}
