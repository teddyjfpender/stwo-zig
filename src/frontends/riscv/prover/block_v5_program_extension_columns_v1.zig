//! Recover only caller trace columns from an already committed immutable LDE.
//! No arithmetic witness, first-round LDE or Merkle tree is constructed here.
const std = @import("std");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Slots = @import("block_v5_program_extension_slots_v1.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
pub const Columns = struct {
    pub fn init(comptime Backend: type, a: std.mem.Allocator, first: *Family.ForBackend(Backend).FirstRound, fixed_logs: []const u32, main_logs: []const u32, slots: []const Slots.Slot) !Selected.Columns {
        if (!first.owns_scheme) return error.InvalidV5WarmProgramTrees;
        return initFromScheme(a, &first.scheme, fixed_logs, main_logs, slots);
    }
    pub fn initFromScheme(a: std.mem.Allocator, scheme: anytype, fixed_logs: []const u32, main_logs: []const u32, slots: []const Slots.Slot) !Selected.Columns {
        const ranges = try a.alloc(Selected.Range, slots.len);
        defer a.free(ranges);
        for (slots, ranges) |slot, *range| {
            try Slots.validate(slot, fixed_logs, main_logs);
            range.* = .{ .fixed_offset = slot.fixed_selector_offset orelse 0, .fixed_width = @intFromBool(slot.fixed_selector_offset != null), .main_offset = slot.main_offset, .main_width = slot.main_columns, .log_size = slot.log_size };
        }
        return Selected.Columns.init(a, scheme, fixed_logs, main_logs, ranges);
    }
};
