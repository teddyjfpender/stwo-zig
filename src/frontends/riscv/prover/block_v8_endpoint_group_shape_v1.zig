//! Allocation-bounded, independently derived runtime group inventory.
const std = @import("std");
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Layout = @import("block_v8_endpoint_group_layout_v1.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
pub const Owned = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    layout: Layout.Plan,
    logs: [][]u32,
    split: u32,
    max_log: u32,
    pub fn init(a: std.mem.Allocator, scope: *const Scope.Owned, input: Scope.Input) !*Owned {
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.* = .{ .a = a, .arena = std.heap.ArenaAllocator.init(a), .layout = try Layout.Plan.initWithProfile(input.members.len, scope.caller_count, input.profile), .logs = undefined, .split = 2, .max_log = 0 };
        errdefer self.arena.deinit();
        const t = self.arena.allocator();
        const l = self.layout;
        self.logs = try t.alloc([]u32, l.traces());
        @memset(self.logs, &.{});
        var fixed: std.ArrayList(u32) = .empty;
        for (input.members, scope.member, 0..) |member, *admitted, i| {
            try fixed.appendSlice(t, try Template.columnLogs(t, member.shape, admitted.external, .fixed));
            self.logs[l.native(i)[1]] = try @import("block_v8_native_halt_policy_v1.zig").mainLogsWithExternal(t, member.shape, admitted.external);
            self.logs[l.native(i)[2]] = try Fused.interactionLogs(t, admitted.layout.slots, &.{});
            self.split = @max(self.split, Fused.compositionSplit(admitted.layout.slots));
        }
        for (input.members, 0..) |member, i| {
            const log = try @import("block_v8_native_endpoint_local_source_v1.zig").endpointLog(member.endpoint_count);
            try fixed.appendSlice(t, try repeated(t, Endpoint.Spec.FIXED_COUNT, log));
            self.logs[l.endpoint(i)[1]] = try repeated(t, Endpoint.Spec.MAIN_COUNT, log);
            self.logs[l.endpoint(i)[2]] = try repeated(t, Endpoint.Spec.INTERACTION_COUNT, log);
        }
        try fixed.appendSlice(t, try repeated(t, 2, 16));
        self.logs[l.range()[1]] = try repeated(t, 1, 16);
        self.logs[l.range()[2]] = try repeated(t, 8, 16);
        try fixed.appendSlice(t, try repeated(t, @import("block_v5_program_table_proof_v1.zig").Air.PREPROCESSED_COLUMN_COUNT, input.program_plan.log_size));
        self.logs[l.program()[2]] = try repeated(t, @import("block_v5_program_table_proof_v1.zig").Air.INTERACTION_COLUMN_COUNT, input.program_plan.log_size);
        try fixed.appendSlice(t, try input.lookup_layout.logs(t, 0));
        self.logs[l.lookup()[1]] = try input.lookup_layout.logs(t, 1);
        self.logs[l.lookup()[2]] = try input.lookup_layout.logs(t, 2);
        for (scope.member) |*admitted| if (admitted.caller_index) |index| {
            const caller = &admitted.caller_plan.?;
            try fixed.appendSlice(t, caller.schedule.fixed);
            self.logs[l.caller(index)[1]] = try @import("block_v8_caller_halt_component_v1.zig").mainLogs(t, caller);
            self.logs[l.caller(index)[2]] = try t.dupe(u32, caller.interaction_logs[0..caller.offsets.program]);
            self.logs[l.caller(index)[3]] = try t.dupe(u32, caller.interaction_logs[caller.offsets.program..]);
            self.split = @max(self.split, caller.schedule.split);
        };
        self.logs[0] = try fixed.toOwnedSlice(t);
        for (self.logs) |logs| for (logs) |log| {
            self.max_log = @max(self.max_log, log);
        };
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.a;
        self.arena.deinit();
        a.destroy(self);
    }
};
fn repeated(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
    if (log > 24) return error.InvalidEndpointGroupGeometry;
    const logs = try a.alloc(u32, count);
    @memset(logs, log);
    return logs;
}
