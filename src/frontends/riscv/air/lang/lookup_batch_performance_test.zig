//! Paired ReleaseFast telemetry for the A-014 shadow interaction layout.
//!
//! This is evidence, not a promotion gate: P-004 requires an A/A-calibrated
//! whole-proof budget before a local timing ratio can accept a protocol change.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const batching = @import("lookup_batch_execution.zig");
const opcode_interaction = @import("../lookups/opcode_interaction.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const sample_count: usize = 7;

test "lookup batch execution: report paired affected-family throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const allocator = std.testing.allocator;
    const log_size: u32 = 14;
    const row_count: usize = @as(usize, 1) << @intCast(log_size);
    const relations = relations_mod.Relations.dummy();
    const families = [_]trace.OpcodeFamily{ .mul, .mulh, .div };

    for (families) |family| {
        var plan = try batching.FamilyPlan.initNativeV1(allocator, family);
        defer plan.deinit();
        var columns = try OwnedColumns.init(
            allocator,
            trace.nColumnsForFamily(family),
            row_count,
            @intFromEnum(family) + 1,
        );
        defer columns.deinit();

        const warm_current = try measure(
            allocator,
            family,
            null,
            columns.active(),
            log_size,
            &relations,
        );
        const warm_selected = try measure(
            allocator,
            family,
            &plan,
            columns.active(),
            log_size,
            &relations,
        );
        try std.testing.expect(warm_current.total.eql(warm_selected.total));

        var current_times: [sample_count]u64 = undefined;
        var selected_times: [sample_count]u64 = undefined;
        for (0..sample_count) |sample| {
            const first_selected = (sample & 1) != 0;
            const first = try measure(
                allocator,
                family,
                if (first_selected) &plan else null,
                columns.active(),
                log_size,
                &relations,
            );
            const second = try measure(
                allocator,
                family,
                if (first_selected) null else &plan,
                columns.active(),
                log_size,
                &relations,
            );
            try std.testing.expect(first.total.eql(second.total));
            if (first_selected) {
                selected_times[sample] = first.ns;
                current_times[sample] = second.ns;
            } else {
                current_times[sample] = first.ns;
                selected_times[sample] = second.ns;
            }
        }
        std.mem.sort(u64, &current_times, {}, std.sort.asc(u64));
        std.mem.sort(u64, &selected_times, {}, std.sort.asc(u64));
        const current_median = current_times[sample_count / 2];
        const selected_median = selected_times[sample_count / 2];
        std.debug.print(
            "\n  A-014 {s} log_rows={d}: current_batches={d} " ++
                "selected_batches={d} current={d} ns selected={d} ns " ++
                "speed={d:.4}x\n",
            .{
                @tagName(family),
                log_size,
                opcode_interaction.nColumns(family) / 4,
                plan.batchCount(),
                current_median,
                selected_median,
                @as(f64, @floatFromInt(current_median)) /
                    @as(f64, @floatFromInt(selected_median)),
            },
        );
    }
}

const Measurement = struct {
    ns: u64,
    total: QM31,
};

fn measure(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    selected: ?*const batching.FamilyPlan,
    columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Measurement {
    var timer = try std.time.Timer.start();
    var result = if (selected) |plan|
        try opcode_interaction.generateSelected(
            allocator,
            plan,
            columns,
            log_size,
            relations,
        )
    else
        try opcode_interaction.generate(
            allocator,
            family,
            columns,
            log_size,
            relations,
        );
    const total = result.total();
    result.deinit(allocator);
    const ns = timer.read();
    std.mem.doNotOptimizeAway(&total);
    return .{ .ns = ns, .total = total };
}

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: [trace.MAX_FAMILY_COLUMNS][]M31 = .{&.{}} **
        trace.MAX_FAMILY_COLUMNS,
    views: [trace.MAX_FAMILY_COLUMNS][]const M31 = .{&.{}} **
        trace.MAX_FAMILY_COLUMNS,
    len: usize,

    fn init(
        allocator: std.mem.Allocator,
        len: usize,
        row_count: usize,
        seed: u64,
    ) !OwnedColumns {
        var result = OwnedColumns{
            .allocator = allocator,
            .len = len,
        };
        var initialized: usize = 0;
        errdefer for (result.storage[0..initialized]) |column| {
            allocator.free(column);
        };
        var state = seed;
        for (result.storage[0..len], result.views[0..len]) |*storage, *view| {
            storage.* = try allocator.alloc(M31, row_count);
            initialized += 1;
            for (storage.*) |*value| {
                state = state *% 6_364_136_223_846_793_005 +%
                    1_442_695_040_888_963_407;
                value.* = M31.fromU64(state >> 32);
            }
            view.* = storage.*;
        }
        return result;
    }

    fn active(self: *const OwnedColumns) []const []const M31 {
        return self.views[0..self.len];
    }

    fn deinit(self: *OwnedColumns) void {
        for (self.storage[0..self.len]) |column| self.allocator.free(column);
        self.* = undefined;
    }
};
