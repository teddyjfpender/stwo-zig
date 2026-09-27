//! Pure geometry/resource-policy tests. No readers, witnesses, commitments,
//! prover, guest, device or benchmark are invoked.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Replay = @import("block_v5_ram_lanes_replay_v1.zig");
const Planning = @import("block_v5_ram_lanes_replay_plan_v1.zig");
const Proof = @import("block_v5_ram_lanes_proof_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig").Trace;
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const config: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .n_queries = 2, .log_last_layer_degree_bound = 0, .fold_step = 1 } };
const limits: Planning.Limits = .{ .minimum_row_log = 1, .maximum_row_log = 5, .max_instances = 64 };
fn traceBound(log: u32) !Replay.Resources {
    var resources = Replay.Resources{};
    resources.max_trace_bytes = try Trace.ownedBytesForRowLog(log);
    return resources;
}

test "block-v5 RAM resource selection admits trace fixed and interaction caps before count first geometry" {
    const a = std.testing.allocator;
    const resources = try traceBound(3);
    var selected = try Replay.selectSizes(Cpu, a, 33, limits, config, resources);
    defer selected.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 8, 8, 2 }, selected.capacities);
    var fixed = Replay.Resources{};
    fixed.stage.proof.max_fixed_bytes = 4 * 24 * @sizeOf(core.fields.m31.M31);
    var fixed_plan = try Replay.selectSizes(Cpu, a, 33, limits, config, fixed);
    defer fixed_plan.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 4, 4, 4, 4, 2 }, fixed_plan.capacities);
    var interaction = Replay.Resources{};
    interaction.stage.proof.max_interaction_bytes = 4 * Interaction.COLUMN_COUNT * @sizeOf(core.fields.m31.M31) + Interaction.SCRATCH_BYTES;
    var interaction_plan = try Replay.selectSizes(Cpu, a, 33, limits, config, interaction);
    defer interaction_plan.deinit();
    try std.testing.expectEqualSlices(u32, fixed_plan.capacities, interaction_plan.capacities);
    try std.testing.expectError(error.V5RamLanesResourceLimit, interaction.stage.proof.requireGeometry(3));
    interaction.stage.proof.max_interaction_bytes -= 1;
    var smaller = try Replay.selectSizes(Cpu, a, 9, limits, config, interaction);
    defer smaller.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 2, 2, 2 }, smaller.capacities);
}

test "block-v5 RAM resource selection preserves independent caps and exact nonrounded instance limits" {
    const a = std.testing.allocator;
    var resources = try traceBound(3);
    resources.stage.proof.max_row_log = 2;
    resources.stage.plan.max_instances = 3;
    resources.stage.plan.max_shards = 2;
    const narrowed = try @import("block_v5_sorted_memory_replay_v1.zig").laneResources(resources, 5, 64, 64);
    try std.testing.expectEqual(@as(u32, 2), narrowed.stage.proof.max_row_log);
    try std.testing.expectEqual(@as(u32, 3), narrowed.stage.plan.max_instances);
    try std.testing.expectEqual(@as(u32, 2), narrowed.stage.plan.max_shards);
    var selected = try Replay.selectSizes(Cpu, a, 17, limits, config, narrowed);
    defer selected.deinit();
    try std.testing.expectEqual(@as(usize, 3), selected.capacities.len);
    try std.testing.expectEqualSlices(u32, &.{ 4, 4, 2 }, selected.capacities);
    try std.testing.expectError(error.V5RamLanesResourceLimit, Replay.selectSizes(Cpu, a, 25, limits, config, narrowed));
    var too_many = limits;
    too_many.max_instances = 2;
    try std.testing.expectError(error.V5RamReplayInstanceLimit, Replay.selectSizes(Cpu, a, 17, too_many, config, narrowed));
    var no_range = resources;
    no_range.stage.plan.max_shards = 0;
    try std.testing.expectError(error.V5RamLanesResourceLimit, Replay.selectSizes(Cpu, a, 1, limits, config, no_range));
}

const ResidentPolicy = struct {
    pub const RamLaneResident = struct {
        pub const MIN_ROW_LOG: u32 = 2;
        pub fn requireRowLog(log: u32) !void {
            if (log < 2 or log > 4 or log == 3) return error.InvalidSecureResidentColumnGeometry;
        }
    };
};
test "block-v5 RAM resource selection respects exact FRI backend holes and resident ingress guards" {
    const a = std.testing.allocator;
    var folded = config;
    folded.fri_config.fold_step = 3;
    var short = try Replay.selectSizes(Cpu, a, 1, limits, folded, .{});
    defer short.deinit();
    try std.testing.expectEqualSlices(u32, &.{8}, short.capacities);
    const tight = try traceBound(2);
    try std.testing.expectError(error.NoAdmittedV5RamReplayGeometry, Replay.selectSizes(Cpu, a, 1, limits, folded, tight));
    var resident = try Replay.selectSizes(ResidentPolicy, a, 34, limits, config, .{});
    defer resident.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 16, 4 }, resident.capacities);
    var ingress = Replay.Resources{};
    ingress.max_sorted_ingress_bytes = 16 * 24;
    var split = try Replay.selectSizes(ResidentPolicy, a, 34, limits, config, ingress);
    defer split.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 4, 4, 4, 4, 4 }, split.capacities);
    try ingress.requireResidentIngress(16);
    try std.testing.expectError(error.V5RamLanesResourceLimit, ingress.requireResidentIngress(17));
    ingress.stage.max_resident_bytes = 2 * 16 * 24 + 65536 * 20 - 1;
    try std.testing.expectError(error.V5RamLanesResourceLimit, ingress.requireResidentIngress(16));
}
fn minimumArea(mask: u32, rows: u64, remaining: usize, area: u64, best: *u64) void {
    if (remaining == 0) {
        if (area >= rows) best.* = @min(best.*, area);
        return;
    }
    for (1..4) |log| if (mask & (@as(u32, 1) << @intCast(log)) != 0) minimumArea(mask, rows, remaining - 1, area + (@as(u64, 1) << @intCast(log)), best);
}
test "block-v5 RAM resource selection exhaustive admitted masks minimize count then true row area" {
    const a = std.testing.allocator;
    const geometry: Planning.Limits = .{ .minimum_row_log = 1, .maximum_row_log = 3, .max_instances = 64 };
    for (1..8) |variants| {
        const mask: u32 = @as(u32, @intCast(variants)) << 1;
        for (1..25) |events| {
            var selected = try Planning.sizesAdmitted(a, events, geometry, mask);
            defer selected.deinit();
            const rows = events / 2 + events % 2;
            var largest: u64 = 0;
            for (1..4) |log| if (mask & (@as(u32, 1) << @intCast(log)) != 0) {
                largest = @max(largest, @as(u64, 1) << @intCast(log));
            };
            try std.testing.expectEqual(try std.math.divCeil(u64, rows, largest), selected.capacities.len);
            var best: u64 = std.math.maxInt(u64);
            minimumArea(mask, rows, selected.capacities.len, 0, &best);
            try std.testing.expectEqual(best, selected.committedRows());
            for (selected.capacities) |capacity| try std.testing.expect(mask & (@as(u32, 1) << @intCast(std.math.log2_int(u32, capacity))) != 0);
        }
    }
}
fn allocationSelection(a: std.mem.Allocator, resources: Replay.Resources) !void {
    var selected = try Replay.selectSizes(Cpu, a, 33, limits, config, resources);
    defer selected.deinit();
}
test "block-v5 RAM resource selection zero RAM impossible policy and allocation failures are bounded" {
    const a = std.testing.allocator;
    const resources = try traceBound(3);
    var empty = try Replay.selectSizes(Cpu, a, 0, limits, config, resources);
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.capacities.len);
    var impossible = resources;
    impossible.max_trace_bytes = 1;
    try std.testing.expectError(error.NoAdmittedV5RamReplayGeometry, Replay.selectSizes(Cpu, a, 1, limits, config, impossible));
    try std.testing.checkAllAllocationFailures(a, allocationSelection, .{resources});
    var no_reader: @import("../air/block/memory_transition.zig").Reader = undefined;
    const invalid: @import("../air/block/memory_size_plan.zig").Plan = .{ .allocator = a, .capacities = try a.dupe(u32, &.{0}) };
    try std.testing.expectError(error.InvalidV5RamReplayGeometry, Planning.collectAdmitted(a, &no_reader, 1, invalid));
}
