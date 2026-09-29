//! Test support: compare builder state with upstream `expect!` snapshots.
//!
//! Upstream snapshots are `format!("{:?}", circuit)` (or `{:#?}` of the
//! constants map) written as indented raw strings; the Zig tests keep them
//! verbatim as multiline literals, so a snapshot diff is a text diff.

const std = @import("std");
const context_mod = @import("context.zig");
const debug_format = @import("debug_format.zig");

/// `expect![...].assert_eq(&format!("{:?}", circuit))`.
pub fn expectCircuit(circuit: *const context_mod.Circuit, expected: []const u8) !void {
    const text = try debug_format.circuitText(std.testing.allocator, circuit);
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings(expected, text);
}

/// `expect![...].assert_debug_eq(&context.constants())`, without the trailing
/// newline `assert_debug_eq` appends.
pub fn expectConstants(comptime V: type, ctx: *const context_mod.Context(V), expected: []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    const keys = try std.testing.allocator.alloc(@import("stwo_core").fields.qm31.QM31, ctx.constants.count());
    defer std.testing.allocator.free(keys);
    for (keys, ctx.constants.keys()) |*value, key| value.* = context_mod.constantFromKey(key);
    try debug_format.writeConstants(&out.writer, keys, ctx.constants.values());
    try std.testing.expectEqualStrings(expected, out.written());
}

/// `expect![...].assert_eq(&format!("{value:?}"))` for a value with a `format` method.
pub fn expectFormat(expected: []const u8, value: anytype) !void {
    var buffer: [512]u8 = undefined;
    try std.testing.expectEqualStrings(expected, try std.fmt.bufPrint(&buffer, "{f}", .{value}));
}

/// `{:?}` of a list of wires: `[[3], [4]]`.
pub fn expectVars(expected: []const u8, vars: []const context_mod.Var) !void {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try out.writer.writeAll("[");
    for (vars, 0..) |v, i| {
        if (i != 0) try out.writer.writeAll(", ");
        try out.writer.print("{f}", .{v});
    }
    try out.writer.writeAll("]");
    try std.testing.expectEqualStrings(expected, out.written());
}
