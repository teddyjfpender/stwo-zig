//! Untrusted proof framing consumed by the Native examples.
const std = @import("std");
const wire = @import("stwo_proof_wire");
const core = @import("stwo_core");

test "cdc: Native proof decoders refuse malformed framing before allocation in both fields" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |Secure| {
        const W = wire.ForField(Secure);
        var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        const bytes = [_]u8{ 'N', 'O', 'T', 'S', 'T', 'W', 'O', '!' };
        try std.testing.expectError(error.UnsupportedBinaryVersion, W.decodeProofBytesBinary(fail.allocator(), &bytes));
        try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinary(fail.allocator(), bytes[0..7]));
        try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
        try std.testing.expectEqual(@as(usize, 0), fail.allocations);
        try std.testing.expectEqual(@as(usize, 0), fail.deallocations);
        try std.testing.expectEqual(@as(usize, 0), fail.allocated_bytes);
        try std.testing.expectEqual(@as(usize, 0), fail.freed_bytes);
        try std.testing.expectEqualStrings("NOTSTWO!", &bytes);
    }
}
