//! Genuine original child verifier rows plus public-window equations and the
//! actual B5SS challenge bridge, all under one new independently admitted key.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const OriginalModule = @import("block_v5_wide_original_child_source_v1.zig");
const Original = OriginalModule.ForSubtype(.capacity_v1);
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
pub fn ForModules(comptime Public: type, comptime Bus: type, comptime Graph: type, comptime Protocol: type, comptime Binding: type) type {
    return struct {
        const Rows = @import("air/block_v5_global_public_export_rows_v1.zig").ForModules(Public, Graph, Bus);
        pub const Limits = struct { max_preparation_bytes: usize = 4 << 30 };
        pub const Prepared = struct {
            budget: *Budget,
            backing_owner: ?*Budget,
            recursive: Parent.Prepared,
            wires: []Bus.Wire,
            pub const complete_block_authority = false;
            pub fn deinit(self: *Prepared) void {
                self.recursive.rows.allocator.free(self.wires);
                self.recursive.deinit();
                self.budget.destroy();
                if (self.backing_owner) |owner| owner.destroy();
                self.* = undefined;
            }
        };
        fn translate(wire: @import("block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire) !Bus.Wire {
            return .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .source = .{ .original = .{ .child = wire.child, .kind = switch (wire.kind) {
                .child_cell => if (wire.part != null) .pairing_coordinate else .frame_cell,
                .child_term => .child_supply_packed,
                else => return error.UnexpectedWidePublicSpanInput,
            }, .coordinate = wire.coordinate, .part = wire.part orelse 0 } } };
        }
        pub fn prepare(backing: std.mem.Allocator, public: *const Public.Owner, fresh: []const Original.Fresh, capacity: u32, limits: Limits) !Prepared {
            if (capacity == 0 or limits.max_preparation_bytes == 0 or fresh.len != public.sources.len or fresh.len == 0) return error.InvalidWidePublicPreparation;
            try public.validate();
            const backing_owner = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
            errdefer if (backing_owner) |owner| owner.destroy();
            const budget = try Budget.create(backing, limits.max_preparation_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            var combined: ?Parent.Prepared = null;
            errdefer if (combined) |*value| value.deinit();
            var wires: std.ArrayList(Bus.Wire) = .empty;
            errdefer wires.deinit(a);
            var next: u32 = 1;
            var identities: [5]core.channel.blake3.Channel = @splat(.{});
            for (&identities, 0..) |*channel, index| {
                channel.mixU32s(&.{ 0x42354d52, Public.VERSION, @intCast(index), @intCast(fresh.len) });
                channel.mixRoot(Protocol.sourceAuthority());
                channel.mixRoot(public.policy.coverage.pinned_digest);
            }
            for (fresh, public.sources, 0..) |*verified, *source, index| {
                try verified.validate();
                if (!std.meta.eql(verified.source.policy, source.policy) or !std.meta.eql(verified.source.public_input_digest, source.public_input_digest)) return error.UnpairedWidePublicChild;
                const admission = Original.Admission.init(&verified.source);
                var child = try Child.prepare(a, admission, &verified.equation, @intCast(index), OriginalModule.PUBLIC_CIRCUIT, next, capacity);
                defer child.deinit();
                for (child.wires) |wire| try wires.append(a, try translate(wire));
                for (&identities) |*channel| {
                    channel.mixRoot(source.policy.key_id);
                    channel.mixRoot(source.policy.physical.instance_id);
                    channel.mixRoot(child.namespace_identity);
                    channel.mixRoot(source.public_input_digest);
                }
                for (identities[1..4], child.recursive.context.graph_ids) |*channel, id| channel.mixRoot(id);
                identities[4].mixRoot(child.recursive.context.transcript_plan_id);
                if (combined) |*value| {
                    const joined = try Join.joinDraining(a, &value.rows, &child.recursive.rows, .{ .{ .first = 1, .end = next }, .{ .first = next, .end = child.next_namespace } });
                    value.rows.deinit();
                    value.rows = joined;
                } else {
                    combined = child.recursive;
                    child.recursive.allocation_budget = null;
                    child.recursive.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
                    inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| child.recursive.rows.fixed[i] = &.{};
                }
                next = child.next_namespace;
            }
            try Binding.attach(a, public, &combined.?, &wires, &next, &identities, limits.max_preparation_bytes);
            var graph = try Graph.prepare(a, public);
            defer graph.deinit();
            var rows = try Rows.prepare(a, public, &graph, capacity);
            defer rows.deinit();
            var namespace = try Rebase.prepare(a, &rows.rows, next);
            defer namespace.deinit();
            const end = try namespace.end();
            const namespace_id = try namespace.identity();
            for (rows.wires) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingWidePublicNamespace;
            try wires.appendSlice(a, rows.wires);
            try Rebase.apply(&rows.rows, &namespace, namespace_id);
            const joined = try Join.joinDraining(a, &combined.?.rows, &rows.rows, .{ .{ .first = 1, .end = next }, .{ .first = next, .end = end } });
            combined.?.rows.deinit();
            combined.?.rows = joined;
            for (&identities) |*channel| {
                channel.mixRoot(rows.identity);
                channel.mixRoot(namespace_id);
            }
            combined.?.context = .{ .child_key_id = identities[0].digestBytes(), .child_config = public.policy.instances[0].key.config, .graph_ids = .{ identities[1].digestBytes(), identities[2].digestBytes(), identities[3].digestBytes() }, .transcript_plan_id = identities[4].digestBytes() };
            std.mem.sort(Bus.Wire, wires.items, {}, struct {
                fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
                    return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
                }
            }.less);
            _ = try Bus.scheduleDigest(wires.items);
            const owned = try wires.toOwnedSlice(a);
            const result = combined.?;
            combined = null;
            return .{ .budget = budget, .backing_owner = backing_owner, .recursive = result, .wires = owned };
        }
    };
}
