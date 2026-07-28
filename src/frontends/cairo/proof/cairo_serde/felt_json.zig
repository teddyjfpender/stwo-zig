//! Streaming JSON array of Starknet field elements.

pub const State = struct {
    count: usize = 0,
};

pub fn begin(writer: anytype) !void {
    try writer.writeAll("[");
}

pub fn write(writer: anytype, state: *State, value: u64) !void {
    if (state.count == 0) {
        try writer.writeAll("\n");
    } else {
        try writer.writeAll(",\n");
    }
    try writer.print("  \"0x{x}\"", .{value});
    state.count += 1;
}

pub fn end(writer: anytype, state: State) !void {
    if (state.count != 0) try writer.writeAll("\n");
    try writer.writeAll("]");
}

test "felt JSON uses the upstream pretty-array surface" {
    const std = @import("std");
    var storage: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    var state = State{};
    try begin(&writer);
    try write(&writer, &state, 0);
    try write(&writer, &state, 0xabcdef);
    try end(&writer, state);
    try std.testing.expectEqualStrings(
        "[\n  \"0x0\",\n  \"0xabcdef\"\n]",
        writer.buffered(),
    );
}
