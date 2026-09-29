//! Streaming pretty JSON array of Starknet field elements.
//!
//! This is the `ProofFormat::CairoSerde` file of upstream
//! `crates/cairo-air/src/utils.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230, and stwo-cairo `82f2125`):
//! every felt formatted as `"0x{felt:x}"` and the list written with
//! `serde_json::to_string_pretty`, i.e. two-space indentation, one element per
//! line, and `[]` for an empty list. Writing element by element keeps a
//! multi-megabyte proof stream out of memory. It lives in interop, not in a
//! frontend, so the Cairo proof transport (`proof.cairo_serde`) and the
//! circuit-recursion wire formats share one writer without depending on each
//! other.

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

test "felt JSON writes an empty list as serde_json does" {
    const std = @import("std");
    var storage: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const state = State{};
    try begin(&writer);
    try end(&writer, state);
    try std.testing.expectEqualStrings("[]", writer.buffered());
}
