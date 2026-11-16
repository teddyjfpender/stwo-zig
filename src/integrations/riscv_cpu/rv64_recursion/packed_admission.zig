//! Packed root parsing at the receiver's untrusted-byte boundary.
const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");
pub fn parse(allocator: std.mem.Allocator, text: []const u8) wire.packed_node.ReadError!wire.packed_node.OwnedPackedNode {
    var bytes: [320]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&bytes);
    return parseTo(&stderr.interface, allocator, text);
}
fn parseTo(out: *std.Io.Writer, allocator: std.mem.Allocator, text: []const u8) wire.packed_node.ReadError!wire.packed_node.OwnedPackedNode {
    return wire.packed_node.parsePackedNode(allocator, text) catch |err| {
        const entry = wire.error_codes.fromPacked(err);
        std.json.Stringify.value(.{ .schema = "recursion_packed_rejection_v1", .provider = "stwo_circuit_recursion_wire", .origin = "packed_node.parsePackedNode", .code = entry.code, .class = entry.class }, .{}, out) catch return err;
        out.writeByte('\n') catch return err;
        out.flush() catch {};
        return err;
    };
}

test "packed root admission executes public codec bytes depth refusal and every allocation cleanup" {
    const a = std.testing.allocator;
    var encoded: std.Io.Writer.Allocating = .init(a);
    defer encoded.deinit();
    try wire.packed_node.writePackedNode(&encoded.writer, .{ .composite = .{ .circuit_hash = @splat(3), .subtasks = &.{.{ .plain = &.{"7"} }} } });
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, text: []const u8) !void {
            var none: [0]u8 = .{};
            var sink = std.Io.Writer.fixed(&none);
            var parsed = try parseTo(&sink, allocator, text);
            defer parsed.deinit();
            var storage: [4096]u8 = undefined;
            var bytes = std.Io.Writer.fixed(&storage);
            try wire.packed_node.writePackedNode(&bytes, parsed.node);
            try std.testing.expectEqualStrings(text, bytes.buffered());
        }
    };
    try Runner.run(a, encoded.written());
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{encoded.written()});
    var deep: std.Io.Writer.Allocating = .init(a);
    defer deep.deinit();
    for (0..64) |_| try deep.writer.writeAll("{\"Composite\":{\"circuit_hash\":[0,0,0,0,0,0,0,0],\"subtasks\":[");
    try deep.writer.writeAll("{\"Plain\":{\"output_preimage\":[]}}");
    for (0..64) |_| try deep.writer.writeAll("]}}");
    var output: std.Io.Writer.Allocating = .init(a);
    defer output.deinit();
    try std.testing.expectError(error.TooDeep, parseTo(&output.writer, a, deep.written()));
    try std.testing.expectEqualStrings("{\"schema\":\"recursion_packed_rejection_v1\",\"provider\":\"stwo_circuit_recursion_wire\",\"origin\":\"packed_node.parsePackedNode\",\"code\":21505,\"class\":\"invalid_input\"}\n", output.written());
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    try std.testing.expectError(error.InvalidJson, parseTo(&failing, a, "{"));
}
