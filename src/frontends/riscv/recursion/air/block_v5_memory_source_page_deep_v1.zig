//! Complete original PAGE component masks select all nine trace trees; no
//! tree, claim or shifted sample is synthesized from received geometry.
const std = @import("std");
const Shared = @import("blake3_component_deep_v1.zig");
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !Shared.Prepared {
    _ = comptime @import("block_v5_memory_source_page_transcript_v1.zig").kindOf(@TypeOf(capture.*));
    try capture.validate(admitted, expected);
    const recipe = try admitted.reconstruct(a, &capture.original.frame, capture.relations);
    defer recipe.deinit();
    var logs: [9][]const u32 = undefined;
    for (&logs, recipe.owner.composition.?.logs) |*view, actual| view.* = actual;
    const handle = recipe.owner.asVerifierComponent();
    return Shared.prepareForTraceTrees(9, a, .{ .components = &.{handle}, .n_preprocessed_columns = logs[0].len }, &logs, admitted.config, &capture.proof);
}
