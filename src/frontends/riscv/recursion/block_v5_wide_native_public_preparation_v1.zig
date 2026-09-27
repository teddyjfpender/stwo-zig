//! Actual original verifier plus B5WP byte bridge in the same parent AIR.
//! No old span-normalization cutoff is widened or replaced by host metadata.
const std = @import("std");
const core = @import("stwo_core");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Original = @import("block_v5_wide_original_child_source_v1.zig");
const Public = @import("block_v5_wide_native_public_values_v1.zig");
const Protocol = @import("block_v5_reusable_wide_native_public_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Limits = struct { max_preparation_bytes: usize = 4 << 30 };
pub const Prepared = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    pub fn deinit(self: *Prepared) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn ForSubtype(comptime subtype: Coverage.Subtype) type {
    const Stack = Original.ForSubtype(subtype);
    const P = Public.ForSubtype(subtype);
    const Grammar = Protocol.ForSubtype(subtype);
    return struct {
        /// Fresh retains the actual original recursive proof capture. Values
        /// independently reconstruct raw fields from the admitted original
        /// source, while the new graph proves their exact B5PD equality.
        pub fn prepare(backing: std.mem.Allocator, fresh: *const Stack.Fresh, values: *const P.Values, capacity: u32, limits: Limits) !Prepared {
            if (capacity == 0 or limits.max_preparation_bytes == 0 or values.source != &fresh.source) return error.UnpairedWideNativePublicSource;
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_preparation_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            try values.validate();
            const admission = Stack.Admission.init(&fresh.source);
            var child = try Child.prepare(a, admission, &fresh.equation, 0, Original.PUBLIC_CIRCUIT, 1, capacity);
            defer child.deinit();
            var graph = try @import("air/block_v5_wide_native_public_graph_v1.zig").prepare(a, values);
            defer graph.deinit();
            try graph.validate(values);
            var sources: [@import("air/block_v5_wide_native_public_graph_v1.zig").INPUT_COUNT]Bus.Wire = undefined;
            for (&sources, graph.sources) |*source, coordinate| source.* = .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 1, .coordinate = coordinate.cell, .part = coordinate.part };
            const lowered_graph = @import("air/block_v5_heterogeneous_scoped_graph_rows_v1.zig").Graph{ .circuit = &graph.circuit, .inputs = &graph.inputs, .values = graph.values, .sources = &sources };
            var wires: std.ArrayList(Bus.Wire) = .empty;
            errdefer wires.deinit(a);
            try wires.appendSlice(a, child.wires);
            var next = child.next_namespace;
            const graph_identity = try @import("air/block_v5_scoped_admitted_graph_attach_v1.zig").attach(a, &child.recursive, &wires, lowered_graph, Grammar.Values{ .public = values }, &next);
            var channels: [5]core.channel.blake3.Channel = @splat(.{});
            for (&channels, 0..) |*channel, index| {
                channel.mixU32s(&.{ 0x42355752, 1, @intFromEnum(subtype), @intCast(index) });
                channel.mixRoot(Protocol.sourceAuthority());
                channel.mixRoot(fresh.source.policy.key_id);
                channel.mixRoot(fresh.source.policy.physical.instance_id);
                channel.mixU32s(&.{ @intFromEnum(fresh.source.policy.physical.kind), @intFromEnum(subtype), fresh.source.policy.physical.index, fresh.source.policy.physical.logical_count });
                channel.mixRoot(fresh.source.policy.source_seal);
                channel.mixRoot(graph_identity);
                channel.mixRoot(child.namespace_identity);
            }
            for (channels[1..4], child.recursive.context.graph_ids) |*channel, id| channel.mixRoot(id);
            channels[4].mixRoot(child.recursive.context.transcript_plan_id);
            child.recursive.context = .{ .child_key_id = channels[0].digestBytes(), .child_config = fresh.source.policy.key.config, .graph_ids = .{ channels[1].digestBytes(), channels[2].digestBytes(), channels[3].digestBytes() }, .transcript_plan_id = channels[4].digestBytes() };
            std.mem.sort(Bus.Wire, wires.items, {}, struct {
                fn less(_: void, left: Bus.Wire, right: Bus.Wire) bool {
                    return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
                }
            }.less);
            _ = try Bus.scheduleDigest(wires.items);
            const output_wires = try wires.toOwnedSlice(a);
            const result = child.recursive;
            child.recursive.allocation_budget = null;
            child.recursive.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
            inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| child.recursive.rows.fixed[i] = &.{};
            return .{ .budget = budget, .recursive = result, .wires = output_wires };
        }
    };
}
