const std = @import("std");
pub fn main() !void {
    const packed_g = @import("recursion/air/blake3_g_packed.zig");
    std.debug.print("packed={s}\n", .{std.fmt.bytesToHex(try packed_g.computeSemanticDigest(std.heap.page_allocator), .lower)});
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    if (args.len > 1) {
        const call = @import("recursion/air/blake3_g_call.zig");
        std.debug.print("call={s}\n", .{std.fmt.bytesToHex(try call.computeSemanticDigest(std.heap.page_allocator), .lower)});
    }
}
comptime {
    _ = @import("recursion/air/tests/blake3_parent_append_test.zig");
    _ = @import("recursion/air/blake3_g_partition.zig");
    _ = @import("recursion/air/blake3_parent_row_storage.zig");
    _ = @import("recursion/air/tests/blake3_g_packed_test.zig");
    _ = @import("recursion/air/tests/blake3_committed_test.zig");
}
