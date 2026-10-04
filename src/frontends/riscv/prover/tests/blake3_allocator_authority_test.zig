//! Stateless allocator contexts must never be read during ownership admission.
const std = @import("std");
const rows = @import("../../recursion/air/blake3_native_parent_rows.zig");
const Sources = @import("../../recursion/air/blake3_execution_parent_sources.zig").Sources;
const HashColumns = @import("../../recursion/blake3_native_hash_columns.zig").Owner;
test "BLAKE3 execution commitment stateless allocation authority rejects malformed row transfer" {
    var workspace = @import("../../recursion/blake3_native_parent_workspace.zig").Workspace.init(std.testing.allocator, 0);
    defer workspace.deinit();
    const scratch = try workspace.begin();
    defer workspace.end();
    try std.testing.expect(workspace.outputAliasesScratch(scratch));
    var other = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer other.deinit();
    try std.testing.expect(!workspace.outputAliasesScratch(other.allocator()));
    inline for (.{ std.heap.smp_allocator, std.heap.page_allocator }) |a| {
        try std.testing.expect(!workspace.outputAliasesScratch(a));
        var transcript: @import("../../recursion/air/blake3_native_transcript.zig").Prepared = undefined;
        var paths: @import("../../recursion/air/blake3_stark_paths.zig").Prepared = undefined;
        var source: Sources = undefined;
        source.transcript = &transcript;
        source.paths = &paths;
        var columns = HashColumns{ .allocator = a, .layout = undefined };
        // Incomplete metadata must reject before reading any other source or
        // allocation state. In particular, a.ptr is legitimately undefined.
        transcript.live.hash_metadata = null;
        paths.hash_metadata = .{ .g_rows = &.{}, .xor_rows = &.{} };
        try std.testing.expectError(error.InvalidNativeHashColumns, rows.prepareWithHashColumns(source, &columns));
        transcript.live.hash_metadata = .{ .g_rows = &.{}, .xor_rows = &.{} };
        paths.hash_metadata = null;
        try std.testing.expectError(error.InvalidNativeHashColumns, rows.prepareWithHashColumns(source, &columns));
    }
}
