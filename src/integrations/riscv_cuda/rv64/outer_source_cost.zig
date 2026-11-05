//! Exact device allocation/lifetime plans for legacy outer_source MAIN/INTER.
//! Cold immutable allocation lists and assignment mode must be frozen by the
//! caller. Host allocation coverage and the production adapter remain open.
const std = @import("std");
const A = @import("global_admission.zig");
const Prefix = @import("prefix_plan.zig");
pub const Format = enum { legacy_blake32_m31, poseidon2_w24_v1 };
pub const Kind = enum { main, values, assignment_status, seeds, prefill_tape, prefill_map, tasks, indices, chain_ends, main_status, fixed, sample_check, parameters, results, gather_fixed, inter, numerators, prefix };
pub const Event = struct { kind: Kind, component: ?u32, bytes: u64, retained: bool };
pub const Plan = struct {
    events: std.ArrayList(Event) = .empty,
    additional_peak: A.Footprint = .{},
    retained_after: A.Footprint = .{},
    live: A.Footprint = .{},
    host_cost_known: bool = false,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        self.events.deinit(a);
        self.* = undefined;
    }
    fn allocate(self: *Plan, a: std.mem.Allocator, kind: Kind, component: ?u32, words: u64, retained: bool) !A.Footprint {
        if (words == 0) return .{};
        const bytes = try std.math.mul(u64, words, 4);
        const footprint = try A.Footprint.allocation(bytes);
        try self.events.append(a, .{ .kind = kind, .component = component, .bytes = bytes, .retained = retained });
        self.live = try self.live.add(footprint);
        if (retained) self.retained_after = try self.retained_after.add(footprint);
        self.additional_peak = self.additional_peak.max(self.live);
        return footprint;
    }
    fn free(self: *Plan, footprint: A.Footprint) void {
        self.live.large -= footprint.large;
        self.live.small -= footprint.small;
    }
};
pub const Assignment = struct {
    seeds: u64,
    tasks: u64,
    indices: u64,
    chain_ends: u64,
    prefill_records: u64 = 0,
    prefill_map_words: u64 = 0,
    /// Reusable schedule misses become immutable cache owners. Known hits
    /// supply false below; one-shot schedules always allocate and retire.
    reusable: bool = false,
    tasks_miss: bool = true,
    indices_miss: bool = true,
    chain_ends_miss: bool = true,
};
pub const Main = struct {
    format: Format = .legacy_blake32_m31,
    main_words: u64,
    value_count: u64,
    assignment: ?Assignment = null,
    /// Actual cold cache misses only, one allocation per raw FIXED column.
    fixed_miss_words: []const u64 = &.{},
    sample_check_records: u64 = 0,
    fused_shadow: bool = false,
};
fn mul(a: u64, b: u64) !u64 {
    return std.math.mul(u64, a, b);
}
pub fn main(a: std.mem.Allocator, input: Main) !Plan {
    if (input.format != .legacy_blake32_m31) return error.AllocationCostFormatUnavailable;
    if (input.fused_shadow) return error.UnmodeledFusedDiagnostic;
    if (input.main_words == 0 or input.value_count == 0) return error.InvalidOuterSourceGeometry;
    var p: Plan = .{};
    errdefer p.deinit(a);
    _ = try p.allocate(a, .main, null, input.main_words, true);
    const values = try p.allocate(a, .values, null, try mul(input.value_count, 4), false);
    if (input.assignment) |assignment| {
        if (assignment.seeds == 0 or assignment.tasks == 0 or (assignment.prefill_records == 0) != (assignment.prefill_map_words == 0)) return error.InvalidOuterSourceGeometry;
        const status = try p.allocate(a, .assignment_status, null, 1, false);
        const seeds = try p.allocate(a, .seeds, null, try mul(assignment.seeds, 5), false);
        const tape = try p.allocate(a, .prefill_tape, null, try mul(assignment.prefill_records, 26), false);
        const map = try p.allocate(a, .prefill_map, null, assignment.prefill_map_words, false);
        p.free(map);
        p.free(tape);
        const tasks = if (!assignment.reusable or assignment.tasks_miss) try p.allocate(a, .tasks, null, try mul(assignment.tasks, 8), assignment.reusable) else A.Footprint{};
        const indices = if (!assignment.reusable or assignment.indices_miss) try p.allocate(a, .indices, null, assignment.indices, assignment.reusable) else A.Footprint{};
        const ends = if (!assignment.reusable or assignment.chain_ends_miss) try p.allocate(a, .chain_ends, null, assignment.chain_ends, assignment.reusable) else A.Footprint{};
        if (!assignment.reusable) {
            p.free(ends);
            p.free(indices);
            p.free(tasks);
        }
        p.free(seeds);
        p.free(status);
    }
    const status = try p.allocate(a, .main_status, null, 1, false);
    for (input.fixed_miss_words) |words| {
        if (words == 0) return error.InvalidOuterSourceGeometry;
        _ = try p.allocate(a, .fixed, null, words, true);
    }
    const sample = try p.allocate(a, .sample_check, null, try mul(input.sample_check_records, 26), false);
    p.free(sample);
    p.free(status);
    p.free(values);
    return p;
}
pub const Component = struct { log: u32, pairs: u64, fixed_columns: u64 };
pub const Interaction = struct { format: Format = .legacy_blake32_m31, components: []const Component };
pub fn interaction(a: std.mem.Allocator, input: Interaction) !Plan {
    if (input.format != .legacy_blake32_m31) return error.AllocationCostFormatUnavailable;
    if (input.components.len != 11) return error.InvalidOuterSourceGeometry;
    var p: Plan = .{};
    errdefer p.deinit(a);
    const parameters = try p.allocate(a, .parameters, null, 56, false);
    const results = try p.allocate(a, .results, null, 89, false);
    for (input.components, 0..) |component, ordinal| {
        const prefix = try Prefix.Plan.init(component.log);
        if (component.pairs == 0) return error.InvalidOuterSourceGeometry;
        const rows = @as(u64, 1) << @intCast(component.log);
        const id: u32 = @intCast(ordinal);
        const fixed = try p.allocate(a, .gather_fixed, id, @max(@as(u64, 1), try mul(component.fixed_columns, rows)), false);
        _ = try p.allocate(a, .inter, id, try mul(try mul(8, try std.math.add(u64, component.pairs, 1)), rows), true);
        const numerators = try p.allocate(a, .numerators, id, try mul(try mul(8, component.pairs), rows), false);
        const scratch = try p.allocate(a, .prefix, id, prefix.scratch_words, false);
        p.free(scratch);
        p.free(numerators);
        p.free(fixed);
    }
    p.free(results);
    p.free(parameters);
    return p;
}

test "MAIN plan charges prefill and tasks in separate live phases" {
    var p = try main(std.testing.allocator, .{ .main_words = 1000, .value_count = 100, .assignment = .{ .seeds = 2, .tasks = 3, .indices = 4, .chain_ends = 0, .prefill_records = 10, .prefill_map_words = 10 }, .fixed_miss_words = &.{ 16, 32 }, .sample_check_records = 10 });
    defer p.deinit(std.testing.allocator);
    const retained = try A.Footprint.allocations(&[_]u64{ 4000, 64, 128 });
    try std.testing.expectEqual(retained, p.retained_after);
    try std.testing.expectEqual(p.retained_after, p.live);
    try std.testing.expect(!p.host_cost_known);
    var tape_index: usize = 0;
    var task_index: usize = 0;
    for (p.events.items, 0..) |event, i| {
        if (event.kind == .prefill_tape) tape_index = i;
        if (event.kind == .tasks) task_index = i;
    }
    try std.testing.expect(tape_index < task_index);
}

test "INTER plan accumulates actual output owners including final cumulative column" {
    const components = [_]Component{.{ .log = 4, .pairs = 1, .fixed_columns = 1 }} ** 11;
    var p = try interaction(std.testing.allocator, .{ .components = &components });
    defer p.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 11 * 1024), p.retained_after.small);
    try std.testing.expectEqual(p.retained_after, p.live);
    try std.testing.expectEqual(@as(usize, 46), p.events.items.len);
    try std.testing.expectError(error.UnmodeledFusedDiagnostic, main(std.testing.allocator, .{ .main_words = 1, .value_count = 1, .fused_shadow = true }));
    try std.testing.expectError(error.AllocationCostFormatUnavailable, interaction(std.testing.allocator, .{ .format = .poseidon2_w24_v1, .components = &components }));
}
