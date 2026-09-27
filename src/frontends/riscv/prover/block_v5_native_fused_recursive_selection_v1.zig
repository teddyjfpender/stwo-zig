//! Optional fused companions are selected by independently admitted native
//! recipes, never by received file indices. This is census authority only;
//! each selected companion still needs its original fresh recursive verifier.
const std = @import("std");
const Native = @import("block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Shared = @import("block_v5_recursive_leaf_store_core_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;

pub const Limits = struct {
    max_executions: usize = 1 << 16,
    max_metadata_bytes: usize = 64 << 20,
    fn require(self: Limits, count: usize) !void {
        if (self.max_executions == 0 or self.max_metadata_bytes == 0)
            return error.InvalidNativeFusedSelectionLimits;
        if (count > self.max_executions or
            try std.math.mul(usize, count, @sizeOf(*const Native) + @sizeOf(u32)) > self.max_metadata_bytes)
            return error.NativeFusedSelectionResourceLimit;
    }
};

pub const Selection = struct {
    allocator: std.mem.Allocator,
    /// Shapes, catalogues and original source roster remain immutable and
    /// alive through store admission and all joined leaf readers.
    natives: []*const Native,
    storage: []u32,
    indices: []const u32,
    limits: Limits,

    pub fn init(a: std.mem.Allocator, roster: Shared.Roster, natives: []const *const Native, limits: Limits) !Selection {
        try limits.require(natives.len);
        try roster.require();
        if (natives.len != roster.sealed.execution_instance_count)
            return error.IncompleteNativeFusedSelection;
        const owned = try a.dupe(*const Native, natives);
        errdefer a.free(owned);
        const storage = try a.alloc(u32, natives.len);
        errdefer a.free(storage);
        var count: usize = 0;
        for (owned, 0..) |native, index| {
            try requireNative(roster, native, index);
            if (try needsCompanion(a, native)) {
                storage[count] = @intCast(index);
                count += 1;
            }
        }
        return .{ .allocator = a, .natives = owned, .storage = storage, .indices = storage[0..count], .limits = limits };
    }

    pub fn deinit(self: *Selection) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.natives);
        self.* = undefined;
    }

    /// Reconstruct absence from the original opcode/projection and memory
    /// recipes. A changed retained vector cannot omit a required proof.
    pub fn require(self: *const Selection, roster: Shared.Roster) !void {
        try self.limits.require(self.natives.len);
        try roster.require();
        if (self.natives.len != roster.sealed.execution_instance_count or
            self.storage.len != self.natives.len or self.indices.ptr != self.storage.ptr or
            self.indices.len > self.storage.len)
            return error.IncompleteNativeFusedSelection;
        var count: usize = 0;
        for (self.natives, 0..) |native, index| {
            try requireNative(roster, native, index);
            if (try needsCompanion(self.allocator, native)) {
                if (count >= self.indices.len or self.indices[count] != index)
                    return error.UntrustedNativeFusedSelection;
                count += 1;
            }
        }
        if (count != self.indices.len) return error.UntrustedNativeFusedSelection;
    }
};

fn requireNative(roster: Shared.Roster, native: *const Native, index: usize) !void {
    try native.validate(native.template_id);
    if (native.index != index or !std.meta.eql(native.sealed, roster.sealed) or
        !std.meta.eql(native.pins, roster.pins) or native.entries.len != roster.entries.len)
        return error.UntrustedNativeFusedSelectionRoster;
    // Equal independent source contents suffice; receiver reconstruction need
    // not preserve the producer's original slice address.
    for (native.entries, roster.entries) |actual, expected|
        if (!std.meta.eql(actual, expected)) return error.UntrustedNativeFusedSelectionRoster;
    const first = roster.pins.counts[@intFromEnum(@import("block_v5_source_seal_v1.zig").Family.program) - 1];
    const execution = roster.entries[first + index];
    const instance = try Capacity.instanceId(native.template_id, native.shape, native.external_retirements, native.pin, execution.roots, native.index);
    if (execution.family != .execution or execution.index != index or
        !std.meta.eql(execution.instance_id, instance) or
        !std.meta.eql(execution.roots[0], native.template.fixed_root))
        return error.UntrustedNativeFusedSelectionRoster;
}

fn needsCompanion(a: std.mem.Allocator, native: *const Native) !bool {
    const mode = native.sealed.register_custody_mode;
    const projections = try Source.slotsFromShapeForMode(a, native.shape, native.external_retirements, mode);
    defer a.free(projections);
    const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = native.pin.context.first_cycle, .cycle_count = native.shape.public_data.clock };
    const slots = try Source.memorySlots(a, native.shape, native.external_retirements, frame, mode);
    defer a.free(slots);
    return projections.len != 0 or slots.len != 0;
}
