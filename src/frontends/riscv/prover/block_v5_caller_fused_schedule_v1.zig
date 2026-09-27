//! Independent caller composite schedule and union openings. Keccak state
//! current/+27 openings remain owned by the original external access component.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Program = @import("block_v5_program_extension_slots_v1.zig");
const Tables = @import("block_v5_precompile_lookup_source_v1.zig");
const Algebra = @import("block_v5_precompile_lookup_algebra_v1.zig");
const External = @import("block_execution_external_trace_v2.zig");
const Old = @import("block_execution_external_batch_v2.zig");
const Eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const Schedule = struct {
    a: std.mem.Allocator,
    fixed: []u32,
    main: []u32,
    program: []Program.Slot,
    tables: []Tables.Slot,
    memory: []External.Descriptor,
    owner: *Tables.Owner,
    masks: Old.Masks,
    split: u32,
    all_memory_events: u64,
    rw_events: u64,
    pub fn init(a: std.mem.Allocator, statement: *const Profile.admission.Statement, total_steps: u32, frame: Frame, mode: u32) !Schedule {
        try Protocol.validateGeometry(statement, total_steps);
        if (Profile.externalCount(statement) == 0) return error.EmptyV5CallerCompositeRequiresAbsence;
        try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
        if (frame.clock_frame != .leaf_local or frame.cycle_count != total_steps or mode > 1) return error.InvalidV5CallerCompositeFrame;
        const fixed = try Protocol.columnLogs(a, statement, .fixed);
        errdefer a.free(fixed);
        const main = try Protocol.columnLogs(a, statement, .main);
        errdefer a.free(main);
        const program = try Program.fromProfile(a, statement, fixed, main, 0, 0);
        errdefer a.free(program);
        const owner = try Tables.Owner.init(a);
        errdefer owner.destroy(a);
        const tables = try owner.slotsForMode(a, statement, mode);
        errdefer a.free(tables);
        const memory = try External.descriptorsFromStatementForMode(a, statement, fixed, main, frame, mode);
        errdefer a.free(memory);
        if (program.len == 0 or memory.len == 0) return error.EmptyV5CallerCompositeRequiresAbsence;
        var masks = try Old.masks(a, memory, fixed.len, main.len);
        errdefer masks.deinit(a);
        for (program) |slot| {
            if (slot.fixed_selector_offset) |i| masks.fixed[i] = true;
            @memset(masks.main[slot.main_offset..][0..slot.main_columns], true);
        }
        for (tables) |slot| {
            @memset(masks.fixed[slot.fixed_offset..][0..slot.fixed_width], true);
            @memset(masks.main[slot.main_offset..][0..slot.width], true);
        }
        return .{ .a = a, .fixed = fixed, .main = main, .program = program, .tables = tables, .memory = memory, .owner = owner, .masks = masks, .split = @max(2, Algebra.compositionSplit(tables)), .all_memory_events = try owner.memoryPairCensus(statement), .rw_events = try External.expectedEventCountForMode(statement, mode) };
    }
    pub fn deinit(self: *Schedule) void {
        self.masks.deinit(self.a);
        self.owner.destroy(self.a);
        self.a.free(self.memory);
        self.a.free(self.tables);
        self.a.free(self.program);
        self.a.free(self.main);
        self.a.free(self.fixed);
        self.* = undefined;
    }
    pub fn projectionCount(self: *const Schedule) usize {
        return self.program.len * 2 + self.tables.len;
    }
    pub fn interactionLogs(self: *const Schedule) ![]u32 {
        const logs = try self.a.alloc(u32, try std.math.add(usize, try std.math.mul(usize, self.projectionCount(), 4), try std.math.mul(usize, self.memory.len, Eval.INTERACTION_COUNT)));
        for (0..2) |part| for (self.program, 0..) |slot, i| @memset(logs[(part * self.program.len + i) * 4 ..][0..4], slot.log_size);
        const table_begin = self.program.len * 8;
        for (self.tables, 0..) |slot, i| @memset(logs[table_begin + i * 4 ..][0..4], slot.log_size);
        const memory_begin = self.projectionCount() * 4;
        for (self.memory, 0..) |slot, i| @memset(logs[memory_begin + i * Eval.INTERACTION_COUNT ..][0..Eval.INTERACTION_COUNT], slot.log_size);
        return logs;
    }
    pub fn witnessLogs(self: *const Schedule) ![]u32 {
        const logs = try self.a.alloc(u32, try std.math.mul(usize, self.memory.len, Integer.COLUMN_COUNT));
        for (self.memory, 0..) |slot, i| @memset(logs[i * Integer.COLUMN_COUNT ..][0..Integer.COLUMN_COUNT], slot.log_size);
        return logs;
    }
    pub fn projectionRanges(self: *const Schedule) ![]Selected.Range {
        const ranges = try self.a.alloc(Selected.Range, self.program.len + self.tables.len);
        for (self.program, ranges[0..self.program.len]) |slot, *range| range.* = .{ .fixed_offset = slot.fixed_selector_offset orelse 0, .fixed_width = @intFromBool(slot.fixed_selector_offset != null), .main_offset = slot.main_offset, .main_width = slot.main_columns, .log_size = slot.log_size };
        for (self.tables, ranges[self.program.len..]) |slot, *range| range.* = .{ .fixed_offset = slot.fixed_offset, .fixed_width = slot.fixed_width, .main_offset = slot.main_offset, .main_width = slot.width, .log_size = slot.log_size };
        return ranges;
    }
};
pub fn mix(channel: anytype, schedule: *const Schedule) void {
    channel.mixU32s(&.{ @intCast(schedule.program.len), @intCast(schedule.tables.len), @intCast(schedule.memory.len), schedule.split });
    for (schedule.program) |slot| {
        channel.mixU32s(&.{ @intFromEnum(slot.kind), slot.log_size, slot.active_calls, if (slot.fixed_selector_offset) |offset| @intCast(offset) else std.math.maxInt(u32), @intCast(slot.main_offset), @intCast(slot.main_columns) });
        if (slot.x0_local_custody_version != 0) channel.mixU32s(&.{ 0x58304350, slot.x0_local_custody_version });
    }
    for (schedule.tables) |slot| Algebra.mixSlot(channel, slot);
    Old.mixRoster(channel, 0, @splat(0), schedule.memory);
    channel.mixU64(schedule.all_memory_events);
    channel.mixU64(schedule.rw_events);
}
