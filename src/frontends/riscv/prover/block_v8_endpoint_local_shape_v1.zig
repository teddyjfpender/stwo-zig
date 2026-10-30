//! Exact finite column inventory for B8 transport preflight. This predicts
//! no witness values and authenticates no proof. Source scopes and original
//! components independently validate every geometry and mask after decoding.
const std = @import("std");
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Layout = @import("block_v8_native_endpoint_layout_v1.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Local = @import("block_v8_native_endpoint_local_source_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const P = @import("block_v8_endpoint_local_placement_v1.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    logs: [P.TRACE_TREES][]u32,
    split: u32,
    max_log: u32,
    pub fn init(a: std.mem.Allocator, admitted: *const Scope.Owned, input: Scope.Input) !*Owned {
        if (admitted.rom_flavor != input.rom_flavor or (input.rom_flavor == .sparse_elf and admitted.sparse_rom.?.log_size != input.program_plan.log_size)) return error.UntrustedSparseLocalDescriptor;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const t = self.arena.allocator();
        var layout = try @import("block_v8_native_endpoint_profile_v1.zig").layout(t, input.shape, input.native_profile);
        defer layout.deinit();
        const endpoint_log = try Local.endpointLog(input.endpoint_count);
        self.split = @max(@as(u32, 2), Fused.compositionSplit(layout.slots));
        self.logs[1] = try @import("block_v8_native_endpoint_profile_v1.zig").mainLogs(t, input.shape, input.native_profile);
        self.logs[2] = try repeated(t, Endpoint.Spec.MAIN_COUNT, endpoint_log);
        self.logs[3] = try repeated(t, Range.Spec.MAIN_COUNT, 16);
        self.logs[4] = &.{};
        self.logs[5] = try input.lookup_layout.logs(t, 1);
        self.logs[6] = try @import("block_v8_native_endpoint_profile_v1.zig").interactionLogs(t, input.shape, layout.slots, input.native_profile);
        self.logs[7] = try repeated(t, Endpoint.Spec.INTERACTION_COUNT, endpoint_log);
        self.logs[8] = try repeated(t, Range.Spec.INTERACTION_COUNT, 16);
        self.logs[9] = try repeated(t, @import("block_v5_program_table_proof_v1.zig").Air.INTERACTION_COLUMN_COUNT, input.program_plan.log_size);
        self.logs[10] = try input.lookup_layout.logs(t, 2);
        var fixed: std.ArrayList(u32) = .empty;
        try fixed.appendSlice(t, try Template.columnLogs(t, input.shape, 0, .fixed));
        try fixed.appendSlice(t, try repeated(t, Endpoint.Spec.FIXED_COUNT, endpoint_log));
        try fixed.appendSlice(t, try repeated(t, Range.Spec.FIXED_COUNT, 16));
        try fixed.appendSlice(t, try repeated(t, @import("block_v5_program_table_proof_v1.zig").Air.PREPROCESSED_COLUMN_COUNT, input.program_plan.log_size));
        try fixed.appendSlice(t, try input.lookup_layout.logs(t, 0));
        self.logs[0] = try fixed.toOwnedSlice(t);
        self.max_log = 0;
        for (self.logs) |logs| for (logs) |log| {
            self.max_log = @max(self.max_log, log);
        };
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
};
fn repeated(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
    if (log > 24) return error.InvalidEndpointWireGeometry;
    const result = try a.alloc(u32, count);
    @memset(result, log);
    return result;
}
