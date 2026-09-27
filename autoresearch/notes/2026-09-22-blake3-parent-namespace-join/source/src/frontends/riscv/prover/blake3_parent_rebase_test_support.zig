//! Namespace relocation is followed by actual parent and parent-of-parent proofs.
const std = @import("std");
const rebase = @import("../recursion/air/blake3_parent_rebase.zig");
const storage = @import("../recursion/air/blake3_parent_row_storage.zig");
pub fn check(a: std.mem.Allocator, rows: *storage.Prepared) !void {
    var plan = try rebase.prepare(a, rows, 1);
    defer plan.deinit();
    const pin = try plan.identity();
    const buffers = rows.main[0].ptr;
    const g_main = rows.main[0][0].values.ptr;
    const g_value = rows.main[0][0].values[0];
    const circuit_column = storage.Airs[0].PHYSICAL_MAIN_COLUMN_COUNT + 1;
    const old = rows.fixed[0][0][circuit_column];
    var wrong_pin = pin;
    wrong_pin[31] ^= 1;
    try std.testing.expectError(error.UntrustedParentRebase, rebase.apply(rows, &plan, wrong_pin));
    const last = plan.old.len - 1;
    const saved = plan.old[last];
    plan.old[last] += 1;
    try std.testing.expectError(error.StaleParentRebase, rebase.apply(rows, &plan, try plan.identity()));
    try std.testing.expectEqual(old, rows.fixed[0][0][circuit_column]);
    plan.old[last] = saved;
    const first = plan.first;
    plan.first = @import("stwo_core").fields.m31.Modulus - 1;
    try std.testing.expectError(error.InvalidParentRebase, plan.identity());
    plan.first = first;
    try rebase.apply(rows, &plan, pin);
    try std.testing.expectEqual(buffers, rows.main[0].ptr);
    try std.testing.expectEqual(g_main, rows.main[0][0].values.ptr);
    try std.testing.expectEqual(g_value, rows.main[0][0].values[0]);
    try std.testing.expectEqual(plan.map(old.toU32()).?, rows.fixed[0][0][circuit_column].toU32());
    try @import("../recursion/air/blake3_parent_namespace.zig").rejectRange(rows, try plan.end(), @import("stwo_core").fields.m31.Modulus);
    std.debug.print("PARENT_NAMESPACE_REBASE circuits={d} first={d} end={d} buffers_reused=true\n", .{ plan.old.len, plan.first, try plan.end() });
}
