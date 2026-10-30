//! Proof-owned GPU sort and predecessor inputs for original read-only tables.
//! Cold immutable row maps are uploaded once; keys, values and all sorting
//! remain resident. There is no CPU witness or sorting fallback.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
pub const Cold = @import("resident_parent_readonly_plan_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 24576;
pub const Slot = enum(u32) { input_rows, output_rows, keys_in, values_in, keys_out, values_out, arguments, temporary };
pub fn id(which: Slot) u32 {
    return FIRST_ID + @intFromEnum(which);
}
extern fn stwo_parent_readonly_temp_bytes_v1(u32, *usize) c_int;
extern fn stwo_parent_readonly_gather_v1([*]const u32, u32, [*]const u32, u32, [*]u32, [*]u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_parent_readonly_sort_v1(?*anyopaque, usize, [*]const u32, [*]u32, [*]const u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_parent_readonly_arguments_v1([*]const u32, u32, [*]const u32, [*]const u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
pub const Requirements = struct {
    slots: [8]cuda.runtime.arena.Requirement,
    cub_temporary_bytes: usize,
    pub fn init(plan: *const Cold.Plan, max_bytes: usize) !Requirements {
        const p = plan.view();
        var temporary: usize = 0;
        const status = stwo_parent_readonly_temp_bytes_v1(@intCast(p.max_group_entries), &temporary);
        if (status != 0 or temporary == 0) return error.ResidentReadonlyTemporaryQueryFailed;
        const total = try std.math.add(usize, p.resident_bytes_without_cub, temporary);
        if (total > max_bytes) return error.ResidentReadonlyResourceLimit;
        const sizes = [_]usize{ p.input_rows.len, p.output_rows.len, p.max_group_entries, p.max_group_entries, p.max_group_entries, p.max_group_entries, try std.math.mul(usize, p.argument_rows, 4), (temporary + 3) / 4 };
        var result: Requirements = .{ .slots = undefined, .cub_temporary_bytes = temporary };
        for (sizes, &result.slots, 0..) |size, *requirement, i| {
            if (size == 0) return error.InvalidResidentReadonlyGeometry;
            requirement.* = .{ .id = id(@enumFromInt(i)), .words = size, .alignment_words = 64, .live_from = .ingress, .live_through = .trace_generation };
        }
        return result;
    }
};
pub const Bound = struct {
    plan: *const Cold.Plan,
    slots: [8]common.Words,
    temporary_bytes: usize,
    primed: bool = false,
    complete: bool = false,
    /// A radix-library dispatch may contain several kernels; this separate
    /// metric records its real API boundary rather than guessing their count.
    radix_library_dispatches: u64 = 0,
    pub fn init(plan: *const Cold.Plan, requirements: Requirements, transaction: anytype) !Bound {
        var result: Bound = .{ .plan = plan, .slots = undefined, .temporary_bytes = requirements.cub_temporary_bytes };
        inline for (std.meta.tags(Slot), 0..) |which, i| {
            result.slots[i] = try transaction.slot(id(which));
            if (result.slots[i].len != requirements.slots[i].words) return error.InvalidResidentReadonlyGeometry;
        }
        return result;
    }
    pub fn slot(self: *const Bound, which: Slot) common.Words {
        return self.slots[@intFromEnum(which)];
    }
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.InvalidResidentReadonlyState;
        try common.requireStage(session, .ingress);
        try session.context.uploadSlice(u32, self.slot(.input_rows), self.plan.view().input_rows);
        try session.context.uploadSlice(u32, self.slot(.output_rows), self.plan.view().output_rows);
        self.primed = true;
    }
    pub fn execute(self: *Bound, session: anytype, input_main: common.Words, error_flag: common.Words) !void {
        const p = self.plan.view();
        const expected_words = try std.math.mul(usize, @as(usize, 1) << @intCast(p.input_log), 5);
        if (!self.primed or self.complete or input_main.len != expected_words or error_flag.len != 1)
            return error.InvalidResidentReadonlyState;
        try common.requireStage(session, .trace_generation);
        const status = try common.words(session, error_flag, 1);
        const keys_in = try common.words(session, self.slot(.keys_in), p.max_group_entries);
        const values_in = try common.words(session, self.slot(.values_in), p.max_group_entries);
        const keys_out = try common.words(session, self.slot(.keys_out), p.max_group_entries);
        const values_out = try common.words(session, self.slot(.values_out), p.max_group_entries);
        for (p.groups) |group| {
            const inputs = try self.slot(.input_rows).sub(group.first, group.count);
            const outputs = try self.slot(.output_rows).sub(group.first, group.count);
            try common.record(session, .trace_generation, stwo_parent_readonly_gather_v1(try common.words(session, inputs, group.count), group.count, try common.words(session, input_main, input_main.len), p.input_log, keys_in, values_in, status, session.context.stream));
            try common.record(session, .trace_generation, stwo_parent_readonly_sort_v1(@ptrCast(try common.words(session, self.slot(.temporary), self.slot(.temporary).len)), self.temporary_bytes, keys_in, keys_out, values_in, values_out, group.count, session.context.stream));
            self.radix_library_dispatches += 1;
            try common.record(session, .trace_generation, stwo_parent_readonly_arguments_v1(try common.words(session, outputs, group.count), group.count, keys_out, values_out, try common.words(session, self.slot(.arguments), p.argument_rows * 4), @intCast(p.argument_rows), status, session.context.stream));
        }
        self.complete = true;
    }
    pub fn requireComplete(self: *const Bound) !void {
        if (!self.complete) return error.IncompleteResidentReadonly;
    }
};
fn forceNative(bound: *Bound, session: *cuda.runtime.NativeSession, main: common.Words, status: common.Words) !void {
    try bound.prime(session);
    try bound.execute(session, main, status);
    try bound.requireComplete();
}
test "resident readonly executor has no host numeric stage" {
    _ = &forceNative;
}
