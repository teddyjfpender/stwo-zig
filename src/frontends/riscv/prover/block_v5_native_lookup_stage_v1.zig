//! Same-root native table/state projection while a lightweight native first
//! round is warm. The adapter releases all immutable leases in one callback;
//! its typed sink stages provisional proof bytes, never verified authority.
const std = @import("std");
const ProducerModule = @import("block_v5_block_producer_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Projection = @import("block_v5_native_lookup_request_proof_v1.zig");
const Source = @import("block_v5_native_lookup_request_source_v1.zig");
const Empty = @import("block_v5_empty_native_tables_v1.zig");

pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership; error leaves it with this callback.
    /// Empty external-only instances have no projection artifact or receipt.
    put_projection: *const fn (*anyopaque, u32, *Projection.Proof) anyerror!void,
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
            if (!warm.first.owns_scheme or warm.first.index != warm.index or
                warm.first.native != owner or !owner.native_only_v5 or
                !owner.tables_ready or owner.failed or owner.interaction_ready or
                warm.replay.admission.context.execution_index != warm.index or
                warm.first.scheme.trees.items.len != 2 or
                !std.meta.eql(warm.first.scheme.config, warm.pins.config) or
                !std.meta.eql(warm.first.pin, warm.replay.admission) or
                warm.first.template.execution_profile != warm.replay.profile or
                warm.first.template.external_retirements != owner.external_retirements or
                !std.meta.eql(warm.first.template.config, warm.pins.config)) return error.UntrustedV5WarmNativeLookup;
            try warm.sealed.require(warm.pins, warm.entries);
            try warm.replay.admission.require(warm.pins, &owner.statement.public_data);
            try warm.first.template.admit(&owner.statement, warm.first.template_id);
            try warm.catalog.admit(warm.pins, warm.sealed, warm.index, warm.first.template, warm.first.template_id);
            if (!std.meta.eql(warm.first.instance_id, try Template.instanceId(warm.first.template_id, &owner.statement, warm.replay.admission, warm.first.roots, warm.index))) return error.UntrustedV5WarmNativeLookup;
            try Native.admitEntry(warm.index, warm.first.roots, warm.first.instance_id, warm.sealed, warm.entries);
            const slots = try Source.slotsFromShapeForMode(a, &owner.statement, owner.external_retirements, warm.sealed.register_custody_mode);
            defer a.free(slots);
            if (slots.len == 0) {
                // Absence is derived from the independently matched shape. A
                // clock-only native branch still has slots and must prove them.
                try Empty.validateShape(a, &owner.statement, owner.external_retirements);
                return;
            }
            const Api = Projection.ForBackend(Backend);
            var first = try Api.borrowFirstRound(a, &warm.first.scheme, owner.main.items, slots, warm.first.template_id, warm.first.instance_id, warm.index);
            defer first.deinit(a);
            if (!std.meta.eql(first.roots, warm.first.roots)) return error.UnsharedV5WarmNativeLookup;
            // Check every borrowed fixed/main column, rather than just one
            // representative lane; no trace FFT/LDE/Merkle build is repeated.
            for (first.scheme.trees.items, warm.first.scheme.trees.items) |lease, source_tree| {
                if (lease.columns.len != source_tree.columns.len) return error.UnsharedV5WarmNativeLookup;
                for (lease.columns, source_tree.columns) |column, source_column| {
                    if (column.values.ptr != source_column.values.ptr or column.values.len != source_column.values.len or
                        column.log_size != source_column.log_size) return error.UnsharedV5WarmNativeLookup;
                }
            }
            var proof = try Api.prove(a, &first, owner.main.items, slots, warm.sealed, warm.first.template_id, warm.first.instance_id, warm.index, warm.first.roots);
            var owned = true;
            defer if (owned) proof.deinit(a);
            // Proving the projection consumes only its own lease, channel,
            // interaction and opening. The original native scheme stays warm.
            if (!warm.first.owns_scheme or warm.first.scheme.trees.items.len != 2 or
                !std.meta.eql(warm.first.entry().roots, first.roots)) return error.ConsumedV5WarmNativeLookup;
            try self.sink.put_projection(self.sink.context, warm.index, &proof);
            owned = false;
        }
    };
}
