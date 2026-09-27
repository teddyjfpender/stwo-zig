//! Warm producer callback: one program + table/state/register PCS proof from
//! the live native prefix. The original native scheme stays owned and intact.
const std = @import("std");
const ProducerModule = @import("block_v5_block_producer_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Projection = @import("block_v5_native_projection_fused_proof_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Receiver = @import("block_v5_native_projection_fused_receiver_v1.zig");
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership. Errors leave the proof with this callback.
    put_fused: *const fn (*anyopaque, u32, *Projection.Proof) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Producer = ProducerModule.ForLightweightBackend(Backend);
        sink: Sink,
        pub fn hooks(self: *Self) Producer.Hooks {
            return .{ .context = self, .on_first_round = onFirstRound };
        }
        fn onFirstRound(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmExecution) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            const owner = warm.replay.owner;
            if (!warm.first.owns_scheme or warm.first.index != warm.index or warm.first.native != owner or
                !owner.native_only_v5 or !owner.tables_ready or owner.failed or owner.interaction_ready or
                warm.first.scheme.trees.items.len != 2 or !std.meta.eql(warm.first.pin, warm.replay.admission) or
                !std.meta.eql(warm.first.scheme.config, warm.pins.config) or
                warm.first.template.external_retirements != owner.external_retirements)
                return error.UntrustedV5WarmFusedProjection;
            const pin = Receiver.InstancePin{ .shape = &owner.statement, .admission = warm.replay.admission, .template = warm.first.template, .template_id = warm.first.template_id, .profile = warm.replay.profile };
            const slots = try Source.slotsFromShapeForMode(a, pin.shape, owner.external_retirements, warm.sealed.register_custody_mode);
            defer a.free(slots);
            const roots = try Receiver.admit(warm.index, pin, warm.sealed, warm.pins, warm.entries, warm.catalog, slots);
            if (!std.meta.eql(roots, warm.first.roots)) return error.UntrustedV5WarmFusedProjection;
            try Native.admitEntry(warm.index, warm.first.roots, warm.first.instance_id, warm.sealed, warm.entries);
            if (slots.len == 0) {
                try @import("block_v5_empty_native_tables_v1.zig").validateShape(a, pin.shape, owner.external_retirements);
                return;
            }
            const Api = Projection.ForBackend(Backend);
            var first = try Api.borrowFirstRound(a, &warm.first.scheme, owner.main.items, slots, warm.first.template_id, warm.first.instance_id, warm.index);
            defer first.deinit(a);
            for (first.scheme.trees.items, warm.first.scheme.trees.items) |lease, tree| {
                if (lease.columns.len != tree.columns.len) return error.UnsharedV5WarmFusedProjection;
                for (lease.columns, tree.columns) |column, original| {
                    if (column.values.ptr != original.values.ptr or column.values.len != original.values.len or
                        column.log_size != original.log_size) return error.UnsharedV5WarmFusedProjection;
                }
            }
            var proof = try Api.prove(a, &first, owner.main.items, slots, warm.sealed, warm.first.template_id, warm.first.instance_id, warm.index, roots);
            var owns = true;
            defer if (owns) proof.deinit(a);
            if (!warm.first.owns_scheme or warm.first.scheme.trees.items.len != 2)
                return error.ConsumedV5WarmFusedProjection;
            try self.sink.put_fused(self.sink.context, warm.index, &proof);
            owns = false;
        }
    };
}
