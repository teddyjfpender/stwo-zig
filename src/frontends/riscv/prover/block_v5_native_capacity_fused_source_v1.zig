//! Capacity-native fused inventory. Typed requests and their access ordinals
//! remain exactly the original native recipe; activity is a committed main
//! cell, never the capacity fixed tree's all-ones placeholder.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v5_native_projection_fused_source_v1.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Opcode = @import("../runner/trace.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Memory = @import("block_execution_sidecar_batch_v2.zig");
const Access = @import("block_execution_access_bridge_v2.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Seal = @import("block_v5_source_seal_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Slot = Original.Slot;
pub const Partition = Original.Partition;
pub const PARTITION_COUNT = Original.PARTITION_COUNT;
pub const fromCommittedMain = Original.fromCommittedMain;
pub const mixSlot = Original.mixSlot;
pub fn slotsFromShapeForMode(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: u32) ![]Slot {
    _ = try Capacity.Plan.fromShape(shape, external);
    if (mode > 1 or (shape.localZeroCustody() and mode != 1)) return error.InvalidV5RegisterCustodyMode;
    return Original.slotsFromShapeForMode(a, shape, external, mode);
}
pub const Binding = struct {
    main_index: usize,
    fixed_active_index: usize,
    native_main_count: usize,
    log_size: u32,
    n_rows: u32,
};
/// Match the exact component origin, not just family/log (multiple shards of
/// one family may share both). Counts remain independently pinned instance data.
pub fn binding(shape: *const Shape, external: u32, offset: usize, log: u32, rows: ?u32) !Binding {
    const plan = try Capacity.Plan.fromShape(shape, external);
    var at: usize = 0;
    var shard: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        if (offset == at) return requireBinding(plan, shard, log, rows);
        at += desc.n_columns;
        shard += 1;
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        if (offset == at) return requireBinding(plan, shard, log, rows);
        at += desc.n_columns;
        shard += 1;
    }
    return error.InvalidCapacityFusedSelectorOrigin;
}
fn requireBinding(plan: Capacity.Plan, ordinal: usize, log: u32, rows: ?u32) !Binding {
    if (ordinal >= plan.len) return error.InvalidCapacityFusedSelectorOrigin;
    const shard = plan.shards[ordinal];
    if (shard.log_size != log or (rows != null and shard.rows != rows.?)) return error.InvalidCapacityFusedSelectorOrigin;
    return .{ .main_index = shard.main_index, .fixed_active_index = shard.active_index, .native_main_count = plan.native_main_count, .log_size = shard.log_size, .n_rows = shard.rows };
}
/// Uses the same declared program source as the original opcode AIR. An
/// opcode's one-hot activity or a clock row's enabler must equal its appended
/// selector. No multiplication changes any signed table or memory tuple.
pub fn activity(slot: Slot, main: []const Q) !Q {
    return @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).activity(slot, main);
}
pub fn opcodeActivity(family: Opcode.OpcodeFamily, main: []const Q) !Q {
    return @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).opcodeActivity(family, main);
}

/// Capacity main includes native envelope columns as well as appended count
/// columns. Memory tuples retain the original base-column recipe and ordinal;
/// offsets advance by the true committed descriptor width.
pub fn memorySlots(a: std.mem.Allocator, shape: *const Shape, external: u32, frame: Frame, mode: u32) ![]Memory.Slot {
    _ = try Capacity.Plan.fromShape(shape, external);
    if (mode > 1 or (shape.localZeroCustody() and mode != 1)) return error.InvalidV5RegisterCustodyMode;
    var out: std.ArrayList(Memory.Slot) = .empty;
    errdefer out.deinit(a);
    var offset: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        const width = Opcode.nColumnsForFamily(desc.family);
        const zero: [Opcode.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
        const pairs = try Access.fromCommittedMain(Q, desc.family, zero[0..width]);
        for (pairs.items[0..pairs.len], 0..) |pair, ordinal| {
            if (mode == 1 and pair.space.eql(Q.zero()) and !Access.hasConditionalSpace(desc.family, ordinal)) continue;
            _ = try Access.rwPairForMode(Q, desc.family, ordinal, pair, mode);
            try out.append(a, .{ .family = desc.family, .slot = ordinal, .log_size = desc.log_size, .main_offset = offset, .frame = frame });
        }
        offset += desc.n_columns;
    }
    return out.toOwnedSlice(a);
}
pub fn requireLogs(shape: *const Shape, external: u32, fixed: []const u32, main: []const u32) !void {
    const plan = try Capacity.Plan.fromShape(shape, external);
    if (fixed.len != plan.fixed_count or main.len != plan.mainCount()) return error.InvalidCapacityFusedColumnRoster;
    if (plan.len == 0) {
        for (fixed) |log| if (log != @import("block_v5_native_frame_v1.zig").LOG_SIZE) return error.InvalidCapacityFusedColumnRoster;
        for (main) |log| if (log != @import("block_v5_native_frame_v1.zig").LOG_SIZE) return error.InvalidCapacityFusedColumnRoster;
        return;
    }
    for (plan.active()) |shard| {
        if (fixed[shard.first_index] != shard.log_size or fixed[shard.active_index] != shard.log_size or
            main[shard.main_index] != shard.log_size or main[shard.main_index + 1] != shard.log_size) return error.InvalidCapacityFusedColumnRoster;
    }
    var offset: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        for (main[offset..][0..desc.n_columns]) |log| if (log != desc.log_size) return error.InvalidCapacityFusedColumnRoster;
        offset += desc.n_columns;
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        for (main[offset..][0..desc.n_columns]) |log| if (log != desc.log_size) return error.InvalidCapacityFusedColumnRoster;
        offset += desc.n_columns;
    }
}
pub fn emptyWitnessRoot(mode: u32) ![32]u8 {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354346, 1, 0x454d5054, Capacity.TAG, Capacity.VERSION, mode });
    channel.mixRoot(@import("block_v5_word_memory_protocol_v1.zig").abiId());
    return channel.digestBytes();
}
/// Typed absence requires authentic zero RW roster and the real capacity
/// execution entry. It produces neither a STARK nor a scalar receipt.
pub fn emptyEntry(a: std.mem.Allocator, shape: *const Shape, external: u32, frame: Frame, execution: Seal.Entry, expected_events: u64, mode: u32) !Seal.Entry {
    if (expected_events != 0 or execution.family != .execution or frame.clock_frame != .leaf_local or frame.global_first_cycle == 0 or frame.cycle_count != shape.public_data.clock)
        return error.InvalidCapacityFusedAbsence;
    const slots = try memorySlots(a, shape, external, frame, mode);
    defer a.free(slots);
    if (slots.len != 0) return error.NonemptyCapacityFusedAbsence;
    const root = try emptyWitnessRoot(mode);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354346, 1, 0x454d5054, execution.index, mode });
    channel.mixRoot(root);
    channel.mixRoot(execution.instance_id);
    for (execution.roots) |native_root| channel.mixRoot(native_root);
    channel.mixU64(frame.global_first_cycle);
    channel.mixU32s(&.{frame.cycle_count});
    return .{ .family = .execution_sidecar, .index = execution.index, .instance_id = channel.digestBytes(), .roots = .{ root, @splat(0) } };
}
