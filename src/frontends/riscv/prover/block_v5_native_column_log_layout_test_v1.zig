//! Nonproving geometry/custody fixtures. No guest, proof or capture is run.
const std = @import("std");
const Statement = @import("../air/statement.zig");
const Legacy = @import("block_v5_native_template_protocol_v3.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Layout = @import("block_v5_native_column_log_layout_v1.zig");

fn shape(rows: u32, empty: bool) Statement.Blake3ExecutionStatement {
    var result = std.mem.zeroes(Statement.Blake3ExecutionStatement);
    result.initializeDescriptorStorage();
    if (!empty) {
        result.n_components = 1;
        result.component_descs[0] = .{ .family = .base_alu_imm, .log_size = @max(1, std.math.log2_int_ceil(u32, rows)), .n_rows = rows, .n_columns = @intCast(@import("../runner/trace.zig").nColumnsForFamily(.base_alu_imm)) };
        result.n_infra = 1;
        result.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 2, .n_columns = @import("../infra_trace.zig").CLOCK_UPDATE_COLS };
    }
    result.total_steps = rows;
    result.public_data = .{ .initial_pc = 0, .final_pc = 0, .clock = rows, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(0), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}

fn check(a: std.mem.Allocator, statement: *const Statement.Blake3ExecutionStatement, external: u32) !void {
    const plan = try Capacity.Plan.fromShape(statement, external);
    for ([_]Legacy.ColumnTree{ .fixed, .main, .interaction }) |tree| {
        const original = try Legacy.columnLogs(a, statement, external, tree);
        defer a.free(original);
        try Legacy.requireColumnLogs(statement, external, tree, original);
        const capacity = try Capacity.columnLogs(a, statement, external, tree);
        defer a.free(capacity);
        try Capacity.requireColumnLogs(statement, external, tree, capacity);
        if (tree == .main and plan.len != 0) {
            try std.testing.expectEqual(original.len + 2 * plan.len, capacity.len);
            try std.testing.expectEqualSlices(u32, original, capacity[0..original.len]);
            for (plan.active()) |shard| try std.testing.expectEqualSlices(u32, &.{ shard.log_size, shard.log_size }, capacity[shard.main_index..][0..2]);
        } else try std.testing.expectEqualSlices(u32, original, capacity);
        try std.testing.expectError(error.UntrustedNativeColumnGeometry, Capacity.requireColumnLogs(statement, external, tree, capacity[0 .. capacity.len - 1]));
        for (capacity, 0..) |value, i| {
            capacity[i] = value + 1;
            try std.testing.expectError(error.UntrustedNativeColumnGeometry, Capacity.requireColumnLogs(statement, external, tree, capacity));
            capacity[i] = value;
        }
    }
}

test "native column geometry: original descriptor domains and capacity tails remain exact" {
    var statement = shape(5, false);
    try check(std.testing.allocator, &statement, 0);
    const fixed = try Legacy.columnLogs(std.testing.allocator, &statement, 0, .fixed);
    defer std.testing.allocator.free(fixed);
    try std.testing.expectEqualSlices(u32, &.{ 3, 3, 1, 1 }, fixed);
    const cursor = try Layout.Cursor.init(&statement, 0, .main);
    try std.testing.expectEqual(@as(usize, statement.nMainColumns()), try cursor.count());
}

test "native column geometry: genuine empty frame keeps original geometry and external retirement checks" {
    var statement = shape(3, true);
    try check(std.testing.allocator, &statement, 3);
    try std.testing.expectError(error.InvalidStatement, Layout.Cursor.init(&statement, 2, .main));
}

fn allocation(a: std.mem.Allocator) !void {
    var statement = shape(5, false);
    try check(a, &statement, 0);
}
test "native column geometry: exact one-allocation arrays roll back every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocation, .{});
    var statement = shape(5, false);
    for ([_]Legacy.ColumnTree{ .fixed, .main, .interaction }) |tree| {
        var bounded = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        const logs = try Capacity.columnLogs(bounded.allocator(), &statement, 0, tree);
        defer bounded.allocator().free(logs);
        try std.testing.expectEqual(@as(usize, 1), bounded.alloc_index);
        try Capacity.requireColumnLogs(&statement, 0, tree, logs);
    }
}

test "native column geometry: maximum original shard count remains bounded and exact" {
    var statement = shape(65536, false);
    statement.n_components = Statement.MAX_COMPONENTS;
    statement.n_infra = 0;
    for (statement.component_descs[0..statement.n_components]) |*desc| desc.* = statement.component_descs[0];
    statement.total_steps = 65536 * Statement.MAX_COMPONENTS;
    statement.public_data.clock = statement.total_steps;
    const plan = try Capacity.Plan.fromShape(&statement, 0);
    try std.testing.expectEqual(@as(usize, Statement.MAX_COMPONENTS), plan.len);
    const logs = try Capacity.columnLogs(std.testing.allocator, &statement, 0, .main);
    defer std.testing.allocator.free(logs);
    try Capacity.requireColumnLogs(&statement, 0, .main, logs);
    try std.testing.expectEqual(plan.mainCount(), logs.len);
}

test "native column geometry: malformed independent descriptors fail before allocation" {
    var statement = shape(5, false);
    statement.component_descs[0].n_columns += 1;
    var denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidStatement, Capacity.columnLogs(denied.allocator(), &statement, 0, .main));
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
}
