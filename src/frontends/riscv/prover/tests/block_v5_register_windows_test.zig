const std = @import("std");
const Registers = @import("../block_v5_register_windows_v1.zig");

fn windows() [2]Registers.Window {
    var first: [32]u32 = @splat(0);
    first[2] = 0x01000000;
    var middle = first;
    middle[5] = 7;
    var last = middle;
    last[5] = 10;
    var first_clocks: [32]u32 = @splat(0);
    first_clocks[5] = 3;
    var last_clocks: [32]u32 = @splat(0);
    last_clocks[5] = 7;
    return .{
        .{ .index = 0, .first_cycle = 1, .cycle_count = 2, .initial_registers = first, .final_registers = middle, .final_clocks = first_clocks },
        .{ .index = 1, .first_cycle = 3, .cycle_count = 2, .initial_registers = middle, .final_registers = last, .final_clocks = last_clocks },
    };
}
test "register window plan pins order endpoints clocks and x0" {
    var rows = windows();
    const plan = Registers.Plan{ .initial_registers = rows[0].initial_registers, .final_registers = rows[1].final_registers, .windows = &rows };
    const digest = try plan.digest();
    rows[1].final_clocks[5] -= 1;
    try std.testing.expect(!std.meta.eql(digest, try plan.digest()));
    rows = windows();
    rows[1].first_cycle += 1;
    try std.testing.expectError(error.InvalidV5RegisterWindowPlan, plan.digest());
    rows = windows();
    std.mem.swap(Registers.Window, &rows[0], &rows[1]);
    try std.testing.expectError(error.InvalidV5RegisterWindowPlan, plan.digest());
    rows = windows();
    var missing = plan;
    missing.windows = rows[0..1];
    try std.testing.expectError(error.InvalidV5RegisterWindowPlan, missing.digest());
    rows = windows();
    rows[1].initial_registers[5] ^= 1;
    try std.testing.expectError(error.InvalidV5RegisterWindowPlan, plan.digest());
    rows = windows();
    rows[1].final_registers[0] = 1;
    try std.testing.expectError(error.InvalidV5RegisterWindowPlan, plan.digest());
    rows = windows();
    rows[1].final_clocks[5] = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidV5RegisterWindowClock, plan.digest());
    rows = windows();
    rows[0].final_clocks[5] = 0;
    try std.testing.expectError(error.InvalidV5RegisterWindowClock, plan.digest());
}
test "register window native public pin comparison rejects substituted final data" {
    const row = windows()[0];
    var data = .{ .clock = row.cycle_count, .initial_regs = row.initial_registers, .final_regs = row.final_registers, .reg_last_clock = row.final_clocks };
    try row.requirePublic(0, 1, &data);
    data.final_regs[5] ^= 1;
    try std.testing.expectError(error.UntrustedV5RegisterWindow, row.requirePublic(0, 1, &data));
    data.final_regs[5] ^= 1;
    data.reg_last_clock[5] += 1;
    try std.testing.expectError(error.UntrustedV5RegisterWindow, row.requirePublic(0, 1, &data));
    try std.testing.expectError(error.UntrustedV5RegisterWindow, row.requirePublic(1, 1, &data));
}
