//! Shared typed page-binding kernel; schemas fix exact original source
//! inventory and grammar. No host/source descriptor grants proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const LowerCounts = @import("../recursion/air/verifier_arithmetic_lowering_reference.zig");
const Placement = @import("../air/block/memory_component_trace.zig");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Independently reconstructed page graph routing. No witness-selected graph,
        //! input node, kind, use count or circuit namespace is accepted.
        const M = core.fields.m31.M31;
        const First = Schema.Protocol;
        const Page = Schema.Page;
        const Source = Schema.Source;
        const Stream = Schema.Stream;
        const Circuit = Schema.Circuit;
        const Eq = Schema.Equations;
        // Reuse the actual authoritative count implementation; do not transcribe
        // arithmetic operation/public-anchor selection into a host planner.
        pub const ROUTING_COUNT = 1 + 2 * Eq.BIT_COUNT;
        pub const Limits = struct { max_routing_cells: usize = 1 << 24, max_wire_requests: u64 = 500_000_000, max_arithmetic_rows: usize = 1 << 22 };
        pub const Plan = struct {
            allocator: std.mem.Allocator,
            first: First.Pin,
            routing: []M,
            graph_ids: [][32]u8,
            total_uses: u64,
            arithmetic_counts: Lower.Counts,
            arithmetic_signed_mass: u64,
            identity: [32]u8,
            pub fn deinit(self: *Plan) void {
                self.allocator.free(self.graph_ids);
                self.allocator.free(self.routing);
                self.* = undefined;
            }
            pub fn rows(self: *const Plan) usize {
                return @as(usize, 1) << @intCast(self.first.page.row_log);
            }
            pub fn column(self: *const Plan, at: usize) []const M {
                return self.routing[at * self.rows() ..][0..self.rows()];
            }
            /// One independently derived source graph lives at a time. The complete
            /// page stores only fixed routing columns and graph identities, not DAGs.
            pub fn init(a: std.mem.Allocator, admitted: *const Source.Admitted, first_plan: First.Plan, first: First.Pin, source_challenges: Source.Challenges, first_limits: First.Limits, limits: Limits) !Plan {
                try first_plan.require(admitted, first_limits);
                try first.require(first_plan);
                if (limits.max_wire_requests == 0 or limits.max_wire_requests >= core.fields.m31.Modulus or limits.max_arithmetic_rows == 0) return error.MemorySourceBindingResourceLimit;
                const rows_count = @as(usize, 1) << @intCast(first.page.row_log);
                const cells = try std.math.mul(usize, rows_count, ROUTING_COUNT);
                if (cells > limits.max_routing_cells) return error.MemorySourceBindingResourceLimit;
                const routing = try a.alloc(M, cells);
                errdefer a.free(routing);
                @memset(routing, M.zero());
                const graph_ids = try a.alloc([32]u8, first.page.chunks);
                errdefer a.free(graph_ids);
                var total: u64 = 0;
                var arithmetic_counts = Lower.Counts{};
                var arithmetic_signed_mass: u64 = 0;
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(&Page.abiId());
                hash.update(&(try first.identity(first_plan)));
                for (0..first.page.chunks) |logical| {
                    const ordinal = first.page.first_chunk + logical;
                    const kind = try Stream.kindAt(admitted, ordinal);
                    // Zero inputs are topology-only placeholders, never equation
                    // authority. Existing circuit construction cannot branch on them.
                    const graph_owner = try Circuit.prepareWithChallenges(a, admitted, kind, .{}, .{}, source_challenges);
                    defer graph_owner.deinit();
                    const graph = graph_owner.circuit.?.graph();
                    try graph.validate();
                    graph_ids[logical] = graph.identity_digest;
                    hash.update(&graph_ids[logical]);
                    const scratch = try a.alloc(u32, graph.nodes.len);
                    defer a.free(scratch);
                    const uses = try Lower.computeUseCountsInto(graph, scratch);
                    arithmetic_counts = try arithmetic_counts.add(try LowerCounts.countGraph(graph, uses));
                    const arithmetic_rows = try std.math.add(usize, arithmetic_counts.multiply, try std.math.add(usize, arithmetic_counts.inverse, arithmetic_counts.linear));
                    if (arithmetic_rows > limits.max_arithmetic_rows) return error.MemorySourceBindingResourceLimit;
                    for (uses) |count| arithmetic_signed_mass = try std.math.add(u64, arithmetic_signed_mass, try std.math.mul(u64, count, 2));
                    if (arithmetic_signed_mass > limits.max_wire_requests) return error.MemorySourceBindingResourceLimit;
                    const physical = Placement.committedRow(logical, first.page.row_log);
                    routing[physical] = M.fromCanonical(try Page.circuitId(ordinal));
                    var input: usize = 0;
                    for (graph.nodes, uses, 0..) |node, count, node_id| {
                        if (std.meta.activeTag(node.op) != .input) continue;
                        if (input < Eq.BIT_COUNT) {
                            if (node_id >= core.fields.m31.Modulus or count >= core.fields.m31.Modulus) return error.InvalidMemorySourceInputNode;
                            routing[(1 + 2 * input) * rows_count + physical] = M.fromCanonical(@intCast(node_id));
                            routing[(2 + 2 * input) * rows_count + physical] = M.fromCanonical(count);
                            total = try std.math.add(u64, total, count);
                            if (total > limits.max_wire_requests) return error.MemorySourceBindingResourceLimit;
                        }
                        input += 1;
                    }
                    if (input != Circuit.CIRCUIT_INPUT_COUNT) return error.InvalidMemorySourceInputNode;
                }
                // Canonical fixed data, including zero padding, is part of this exact
                // identity. A verifier must independently reconstruct/recommit it.
                for (routing) |value| {
                    var raw: [4]u8 = undefined;
                    std.mem.writeInt(u32, &raw, value.toU32(), .little);
                    hash.update(&raw);
                }
                return .{ .allocator = a, .first = first, .routing = routing, .graph_ids = graph_ids, .total_uses = total, .arithmetic_counts = arithmetic_counts, .arithmetic_signed_mass = arithmetic_signed_mass, .identity = hash.finalResult() };
            }
        };
    };
}
