//! Origin-specific decoder diagnostics; these never participate in proof bytes.
const std = @import("std");
const wire = @import("mod.zig");
const core = @import("stwo_core");
const Entry = core.error_codes.Entry;

test "proof wire diagnostics pin owned codes and refuse unknown provider bands" {
    const Codes = wire.error_codes;
    const info = @typeInfo(@TypeOf(Codes.fromCodec)).@"fn";
    try std.testing.expect(info.params[0].type.? == wire.CodecError);
    try std.testing.expect(info.return_type.? == Entry);
    const errors = [_]wire.CodecError{ error.NonCanonicalM31, error.ValueOutOfRange, error.InvalidBinaryProof, error.UnsupportedBinaryVersion, error.NonCanonicalPoseidonDigest };
    try std.testing.expectEqual(errors.len, Codes.table.len);
    for (errors, 0..) |err, index| {
        const entry = Codes.fromCodec(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x4001 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqual(if (err == error.UnsupportedBinaryVersion) core.error_codes.Class.unsupported else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, Codes.lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0, 0x1001, 0x3001, 0x4000, 0x4006, 0x5002, 65535 }) |code| try std.testing.expect(Codes.lookup(code) == null);
}

test "proof wire diagnostics retain exact decode errors and leave parser and allocation origins unmapped" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |Secure| {
        const W = wire.ForField(Secure);
        var diagnostic: ?Entry = wire.error_codes.fromCodec(error.ValueOutOfRange);
        try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinaryWithDiagnostic(std.testing.allocator, "", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4003), diagnostic.?.code);
        try std.testing.expectError(error.UnsupportedBinaryVersion, W.decodeProofBytesBinaryWithDiagnostic(std.testing.allocator, "NOTSTWO!", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4004), diagnostic.?.code);
        try std.testing.expectError(error.SyntaxError, W.decodeProofBytesWithDiagnostic(std.testing.allocator, "!", &diagnostic));
        try std.testing.expect(diagnostic == null);
        var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, W.decodeProofBytesWithDiagnostic(fail.allocator(), "{}", &diagnostic));
        try std.testing.expect(diagnostic == null);
        try std.testing.expectEqual(fail.allocated_bytes, fail.freed_bytes);
        try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinaryWithDiagnostic(std.testing.allocator, "", null));
    }
}
