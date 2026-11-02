const std = @import("std");
const R = @import("../roster.zig");
const Audit = @import("fixed_source_metadata.zig");
const Wire = @import("../wire.zig");
const a = std.testing.allocator;
test "fixed provenance metadata matches real source keys and exposes unused geometry columns" {
    const declaration = Wire.CpuDeclaration{ .geometry = .{ .cpu_log = 5, .alu_log = 6, .alu_tail_log = 5 }, .bridges = .{ .keccak = 5 } };
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &.{ 0x00100093, 0x00000073 } }, declaration.geometry, declaration.bridges);
    defer setup.deinit();
    var audit = try Audit.cpu(a, setup.materials.program.log_size, declaration);
    defer audit.deinit();
    const actual = try setup.logs(a, 0);
    defer a.free(actual);
    try std.testing.expectEqualSlices(u32, actual, audit.ordered_column_logs);
    var cells: u64 = 0;
    for (setup.key.tree.coefficients.?) |coefficient| cells += coefficient.coeffs.len;
    try std.testing.expectEqual(4 * cells, audit.native_bytes);
    try std.testing.expectEqual(@as(usize, 0), audit.request_value_columns);
    try std.testing.expect(audit.unused_native_bytes > 0);
    for (audit.parts) |p| {
        if (std.mem.eql(u8, p.role, "boundary")) try std.testing.expectEqual(Audit.Dependence.universal_selectors, p.dependence);
        if (std.mem.eql(u8, p.role, "rom")) try std.testing.expectEqual(Audit.Dependence.guest_program, p.dependence);
    }
    var changed = declaration;
    changed.geometry.alu_log = 7;
    var other = try Audit.cpu(a, setup.materials.program.log_size, changed);
    defer other.deinit();
    try std.testing.expect(!std.mem.eql(u8, &audit.ordered_log_signature, &other.ordered_log_signature));
    // ALU's old FIRST/LAST columns are unused by this lane but still alter the
    // physical key. This diagnostic does not authorize deleting those columns.
    for (other.parts) |p| if (std.mem.eql(u8, p.role, "alu")) {
        try std.testing.expectEqual(@as(usize, 0), p.used_columns);
        try std.testing.expectEqual(p.native_bytes, p.unused_native_bytes);
    };
}
test "truth fixed schedules are independent of admitted call count and first id" {
    const one = Wire.TruthDeclaration{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, 0 } };
    var two = one;
    two.calls = 2;
    two.first_id = 17;
    var first = try Audit.truth(a, one);
    defer first.deinit();
    var second = try Audit.truth(a, two);
    defer second.deinit();
    try std.testing.expectEqualSlices(u32, first.ordered_column_logs, second.ordered_column_logs);
    try std.testing.expectEqualDeep(first.ordered_log_signature, second.ordered_log_signature);
    var setup = try @import("../../keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer setup.deinit();
    const logs = try setup.logs(a, 0);
    defer a.free(logs);
    try std.testing.expectEqualSlices(u32, logs, first.ordered_column_logs);
    // The native key constructor takes log alone; calls/IDs are truth wrapper
    // public inputs and MAIN activity, not schedule coefficients.
    try std.testing.expectEqual(@as(usize, 0), first.request_value_columns);
}
