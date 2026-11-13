const std = @import("std");
const codes = @import("error_codes.zig");
const column = @import("column.zig");

test "prover column diagnostics have typed literal meanings and reject foreign codes" {
    try std.testing.expect(@typeInfo(@TypeOf(codes.fromColumn)).@"fn".params[0].type.? == column.QuotientOpsError);
    const errors = [_]column.QuotientOpsError{ error.ShapeMismatch, error.InvalidColumnLogSize, error.InvalidColumnLength };
    for (errors, 0..) |err, i| {
        const entry = codes.fromColumn(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x3001 + i)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqual(@import("stwo_core").error_codes.Class.invalid_input, entry.class);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqualStrings(entry.tag, codes.lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0, 0x1001, 0x2001, 0x3000, 0x3004, 0x4001, 0x5002, 65535 }) |id| try std.testing.expect(codes.lookup(id) == null);
}

test "prover column diagnostics retain exact primary failure and first cause" {
    var diagnostic: ?codes.ColumnFailure = null;
    const invalid = column.ColumnEvaluation{ .log_size = 2, .values = &.{} };
    invalid.validateRetained() catch |err| {
        try std.testing.expectEqual(error.InvalidColumnLength, codes.recordColumnFailure(&diagnostic, err));
    };
    try std.testing.expectEqual(error.InvalidColumnLength, diagnostic.?.cause);
    try std.testing.expectEqual(@as(u16, 0x3003), diagnostic.?.entry.code);
    try std.testing.expectEqual(error.ShapeMismatch, codes.recordColumnFailure(&diagnostic, error.ShapeMismatch));
    try std.testing.expectEqual(@as(u16, 0x3003), diagnostic.?.entry.code);
    try std.testing.expectEqual(error.ShapeMismatch, codes.recordColumnFailure(null, error.ShapeMismatch));
}

test "same-tag arbitrary transaction errors remain unmapped" {
    const engine = @import("engine.zig");
    var diagnostic: ?engine.ProveDiagnostic = null;
    engine.ProveDiagnostic.recordFirst(&diagnostic, .finalize, error.ShapeMismatch);
    try std.testing.expect(diagnostic.?.code == null);
    engine.ProveDiagnostic.recordFirst(&diagnostic, .fri, error.InvalidColumnLength);
    try std.testing.expectEqual(error.ShapeMismatch, diagnostic.?.cause);
    try std.testing.expect(diagnostic.?.code == null);
}
