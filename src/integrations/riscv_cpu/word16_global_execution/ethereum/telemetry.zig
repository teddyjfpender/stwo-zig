//! Native committed cells versus lifted leaf-hashing exposure. Cost counters
//! never participate in proof authority or select verification statements.
const std = @import("std");
const Keys = @import("keys.zig").Owner;
const Capture = @import("capture.zig").Owner;
const Driver = @import("../../word16_execution/driver.zig");
pub const Cost = struct {
    columns: [3]u64 = @splat(0),
    native_cells: [3]u64 = @splat(0),
    lifted_leaf_cells: [3]u64 = @splat(0),
    max_log: [3]u32 = @splat(0),
};
fn measure(logs: []const u32, result: *Cost, tree: usize) !void {
    var max: u32 = 0;
    for (logs) |log| {
        if (log > 30) return error.InvalidCostGeometry;
        result.native_cells[tree] = try std.math.add(u64, result.native_cells[tree], @as(u64, 1) << @intCast(log));
        max = @max(max, log);
    }
    result.columns[tree] = logs.len;
    result.max_log[tree] = max;
    // Tree evaluations use the protocol's extra commitment blowup. Keep this
    // explicitly a base-size exposure, not a measured hashing or FFT duration.
    result.lifted_leaf_cells[tree] = try std.math.mul(u64, logs.len, @as(u64, 1) << @intCast(max));
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, keys: *const Keys, captured: *const Capture) !void {
    const cpu = try a.alloc(Cost, keys.cpus.len);
    defer a.free(cpu);
    const truth = try a.alloc(Cost, keys.truths.len);
    defer a.free(truth);
    for (keys.cpus, cpu) |setup, *cost| {
        cost.* = .{};
        for (0..3) |tree| {
            const logs = try setup.logs(a, tree);
            defer a.free(logs);
            try measure(logs, cost, tree);
        }
    }
    for (keys.truths, truth) |setup, *cost| {
        cost.* = .{};
        for (0..3) |tree| {
            const logs = try setup.logs(a, tree);
            defer a.free(logs);
            try measure(logs, cost, tree);
        }
    }
    const Active = struct { retirements: u32, alu_facts: usize, binary_facts: usize, shift_facts: usize, ram_events: usize, keccak_calls: usize, add_calls: usize, double_calls: usize };
    const active = try a.alloc(Active, captured.native.items.len);
    defer a.free(active);
    for (captured.native.items, active, 0..) |n, *out, i| out.* = .{ .retirements = (n.cpu orelse return error.PreparedExecutionConsumed).public.steps, .alu_facts = n.alu.facts.len, .binary_facts = n.binary.facts.len, .shift_facts = n.shift.len, .ram_events = captured.advice.events[i].len, .keccak_calls = captured.advice.keccak[i].len, .add_calls = captured.advice.secp[i][0].len, .double_calls = captured.advice.secp[i][1].len };
    try Driver.writeJson(a, dir, "cost.json", .{ .scope = "exact physical native column cells; lifted leaf cells exclude commitment blowup; neither is measured stage time", .cpu = cpu, .truth = truth, .active = active, .memory_words = captured.advice.initial.len, .unique_cpu_setups = keys.cpu_owners.items.len, .unique_keccak_setups = keys.keccak_owners.items.len, .unique_secp_setups = keys.secp_owners.items.len });
    const Roles = @import("role_cost.zig");
    const roles = try a.alloc([Roles.COUNT]Roles.Row, keys.cpus.len);
    defer a.free(roles);
    for (keys.cpus, captured.native.items, roles, 0..) |setup, native, *out, i| {
        out.* = try Roles.build(setup, native, @intCast(captured.advice.events[i].len), if (i == 0) captured.advice.initial.len else 0, if (i + 1 == keys.cpus.len) captured.advice.terminal.len else 0, .{ captured.advice.keccak[i].len, captured.advice.secp[i][0].len, captured.advice.secp[i][1].len });
        for (0..3) |tree| {
            var cells: u64 = 0;
            for (out.*) |role| cells = try std.math.add(u64, cells, role.native_cells[tree]);
            if (cells != cpu[i].native_cells[tree]) return error.CostRosterMismatch;
        }
    }
    try Driver.writeJson(a, dir, "roster.json", .{ .schema = 1, .scope = "CPU and service-bridge native component cells; padding includes required inactive guard rows; only known active physical row counts are reported; fixed dictionary occupancy is null; truth proofs remain separately counted in cost.json", .cpu = roles });
}
