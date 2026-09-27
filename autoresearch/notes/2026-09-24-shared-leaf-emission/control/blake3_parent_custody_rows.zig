//! Append admitted public-memory conversions using the existing parent AIRs.
//! Byte sources are public constants: emit them at each hash input directly,
//! avoiding a redundant private-copy AIR and its caller-side producers.
const std = @import("std");
const storage = @import("blake3_parent_row_storage.zig");
const append = @import("blake3_parent_append.zig");
const custody = @import("blake3_memory_custody.zig");
const chain = @import("blake3_memory_update_chain.zig");
const boundary = @import("blake3_boundary.zig");
const M = @import("stwo_core").fields.m31.M31;
pub const NAMESPACE_START: u32 = 1_000_000_000;
pub const NAMESPACE_END: u32 = 1_100_000_000;
pub fn extend(target: *storage.Prepared, conversions: [2]*const custody.Prepared, identities: [2][32]u8) !void {
    var ends: [2]u64 = undefined;
    for (conversions, identities, &ends) |conversion, identity, *end| {
        const plan = &conversion.plan;
        if (!std.mem.eql(u8, &try plan.identity(), &identity) or conversion.rows.updates.len != plan.edits.len) return error.InvalidParentCustody;
        end.* = @as(u64, plan.namespace) + plan.edits.len * chain.STRIDE;
        if (plan.namespace < NAMESPACE_START or end.* > NAMESPACE_END) return error.InvalidParentCustodyNamespace;
    }
    if (conversions[0].plan.edits.len != 0 and conversions[1].plan.edits.len != 0 and
        conversions[0].plan.namespace < ends[1] and conversions[1].plan.namespace < ends[0]) return error.InvalidParentCustodyNamespace;
    try @import("blake3_parent_namespace.zig").rejectRange(target, NAMESPACE_START, NAMESPACE_END);
    var arena = std.heap.ArenaAllocator.init(target.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var chunks = append.init();
    defer append.deinit(a, &chunks);
    for (conversions, identities) |conversion, identity| {
        const plan = &conversion.plan;
        const fixed = try chain.trusted(a, plan, identity, plan.roots[0], plan.roots[plan.roots.len - 1]);
        // Arena owns fixed path storage until the new columns have been written.
        for (conversion.rows.updates, fixed.updates, plan.edits) |live, trusted, edit| {
            inline for (.{ live.before, live.after }, .{ trusted.before, trusted.after }, .{ edit.before, edit.after }) |path, fixed_path, byte| {
                inline for (.{ 0, 1, 2, 7, 9 }, .{ path.g_rows, path.xor_rows, path.boundary_rows, path.route_rows, path.word_rows }, .{ fixed_path.g_rows, fixed_path.xor_rows, fixed_path.boundary_rows, fixed_path.route_rows, fixed_path.word_rows }) |i, rows, fixed_rows| {
                    try chunks[i].append(a, .{ .live = rows, .fixed = fixed_rows });
                }
                const input = fixed_path.input;
                const public_source = try a.create(boundary.Row);
                public_source.* = try boundary.logicalRow(input[7].toU32(), input[8].toU32(), M.fromCanonical(input[9].toU32()), byte);
                try chunks[2].append(a, .{ .live = @as([*]boundary.Row, @ptrCast(public_source))[0..1], .fixed = @as([*]boundary.Row, @ptrCast(public_source))[0..1] });
            }
        }
    }
    try append.append(target, &chunks);
}
