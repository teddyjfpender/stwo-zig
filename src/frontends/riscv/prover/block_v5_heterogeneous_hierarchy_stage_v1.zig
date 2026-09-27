//! Exact Coverage nodes, bounded live genuine captures, fresh parent on every
//! publication. Independently selected node templates remain external policy.
const std = @import("std");
const Topology = @import("../recursion/block_v5_heterogeneous_hierarchy_plan_v1.zig");
const Frames = @import("../recursion/block_v5_heterogeneous_hierarchy_frames_v1.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_hierarchy_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_heterogeneous_hierarchy_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_heterogeneous_hierarchy_receiver_v1.zig");
const Rows = @import("../recursion/block_v5_heterogeneous_hierarchy_preparation_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const Loader = struct {
    context: *anyopaque,
    /// Reloads original leaf or lower parent bytes. No host export substitutes.
    take_bytes: *const fn (*anyopaque, std.mem.Allocator, Topology.Ref) anyerror![]u8,
};
pub const Artifact = struct {
    ref: Topology.Ref,
    bytes: []u8,
    /// Proposals only: detached consumers use independent admission below.
    key: ?Protocol.Key,
    key_id: [32]u8,
    wires: []Bus.Wire,
    coverage: [32]u8,
    public_input: [32]u8,
    pub const source_authorities_pending = @import("block_v5_recursive_coverage_plan_v1.zig").SOURCE_COUNT;
    pub const aggregate_joins_pending = true;
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.wires);
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success consumes bytes/wires; error leaves both with stage.
    put_hierarchy: *const fn (*anyopaque, *Artifact) anyerror!void,
};
pub const Limits = struct {
    max_owned_bytes: usize = 4 << 30,
    max_child_bytes: usize = 128 << 20,
    max_parent_bytes: usize = 512 << 20,
    transcript_capacity: u32 = 2,
    rows: Rows.Limits = .{},
};
/// Every node's authority comes from independent setup/public policy, never
/// the lower proof file or the producer's newly derived key.
pub fn admit(plan: *const Topology.Plan, nodes: []const Protocol.Admission, limits: Limits) !void {
    try plan.validate();
    if (nodes.len != plan.full.plan.meta.nodes.len or limits.max_owned_bytes == 0 or limits.max_child_bytes == 0 or limits.max_parent_bytes == 0 or limits.transcript_capacity == 0) return error.HeterogeneousHierarchyResourceLimit;
    var source_words: usize = 0;
    for (nodes, 0..) |*node, index| {
        try node.validate();
        if (node.values.index != index or !std.meta.eql(node.values.plan.expected_coverage, plan.expected_coverage) or !std.meta.eql(try node.values.plan.nodeIdentity(@intCast(index)), try plan.nodeIdentity(@intCast(index))) or !std.meta.eql(node.key.config, plan.full.plan.meta.security.recursive)) return error.UntrustedHeterogeneousHierarchy;
        source_words = try std.math.add(usize, source_words, try Frames.nodeWordCount(node.*));
        if (source_words > plan.limits.max_total_source_cells) return error.HeterogeneousHierarchyResourceLimit;
    }
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn publish(backing: std.mem.Allocator, plan: *const Topology.Plan, nodes: []const Protocol.Admission, loader: Loader, limits: Limits, sink: Sink) !void {
            try admit(plan, nodes, limits);
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            if (plan.full.plan.meta.root == .leaf) {
                const ordinal = plan.full.plan.meta.root.leaf;
                const bytes = try loader.take_bytes(loader.context, a, .{ .leaf = ordinal });
                defer a.free(bytes);
                if (bytes.len == 0 or bytes.len > limits.max_child_bytes) return error.HeterogeneousHierarchyResourceLimit;
                var checked = try Receiver.verifyLeaf(a, bytes, plan, ordinal);
                defer checked.deinit();
                try deliver(backing, sink, .{ .leaf = ordinal }, bytes, null, checked.source.expected_id, &.{}, plan.expected_coverage, checked.source.public_input_digest);
                return;
            }
            for (nodes, 0..) |authority, index| {
                const node = plan.full.plan.meta.nodes[index];
                var fresh: [4]Receiver.Fresh = undefined;
                var initialized: usize = 0;
                defer for (fresh[0..initialized]) |*child| child.deinit();
                var sources: [4]Frames.Source = undefined;
                var captures: [4]*const @import("../recursion/blake3_native_parent_verifier.zig").Verified = undefined;
                for (node.children[0..node.child_count], 0..) |ref, slot| {
                    const bytes = try loader.take_bytes(loader.context, a, ref);
                    defer a.free(bytes);
                    if (bytes.len == 0 or bytes.len > limits.max_child_bytes) return error.HeterogeneousHierarchyResourceLimit;
                    fresh[slot] = switch (ref) {
                        .leaf => |ordinal| try Receiver.verifyLeaf(a, bytes, plan, ordinal),
                        .node => |ordinal| try Receiver.verify(a, bytes, nodes[ordinal]),
                    };
                    initialized += 1;
                    sources[slot] = fresh[slot].source; // Borrow; Fresh owns.
                    captures[slot] = &fresh[slot].equation;
                }
                const values = Bus.Values{ .plan = plan, .index = @intCast(index), .children = sources[0..initialized], .pins = authority.values.pins };
                try values.validate();
                var rows = try Rows.prepareVerifierRows(a, values, captures[0..initialized], limits.transcript_capacity, limits.rows);
                defer rows.deinit();
                const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, authority.key.profile);
                const actual = try Protocol.Key.fromGeometry(geometry, rows.wires);
                if (!std.meta.eql(actual, authority.key) or !std.meta.eql(try actual.identity(), authority.expected_id) or !sameWires(rows.wires, authority.wires)) return error.UntrustedHeterogeneousHierarchyGeometry;
                const live = try Protocol.Admission.init(actual, authority.expected_id, rows.wires, values);
                if (!std.meta.eql(try live.publicInputIdentity(), try authority.publicInputIdentity())) return error.UntrustedHeterogeneousHierarchySource;
                const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
                const producer = try Producer.init(a, &rows.recursive.rows, live);
                defer producer.deinit();
                var proof = try producer.prove(a, &rows.recursive.rows);
                defer proof.deinit();
                const bytes = try Parent.codec.encode(a, &proof, &live);
                defer a.free(bytes);
                if (bytes.len > limits.max_parent_bytes) return error.HeterogeneousHierarchyResourceLimit;
                var checked = try Receiver.verify(a, bytes, authority);
                defer checked.deinit();
                try deliver(backing, sink, .{ .node = @intCast(index) }, bytes, actual, live.expected_id, rows.wires, plan.expected_coverage, checked.source.public_input_digest);
            }
        }
    };
}
fn deliver(a: std.mem.Allocator, sink: Sink, ref: Topology.Ref, raw: []const u8, key: ?Protocol.Key, id: [32]u8, schedule: []const Bus.Wire, coverage: [32]u8, public_input: [32]u8) !void {
    const bytes = try a.dupe(u8, raw);
    errdefer a.free(bytes);
    const wires = try a.dupe(Bus.Wire, schedule);
    errdefer a.free(wires);
    var artifact = Artifact{ .ref = ref, .bytes = bytes, .key = key, .key_id = id, .wires = wires, .coverage = coverage, .public_input = public_input };
    try sink.put_hierarchy(sink.context, &artifact);
}

fn sameWires(left: []const Bus.Wire, right: []const Bus.Wire) bool {
    if (left.len != right.len) return false;
    for (left, right) |l, r| if (!std.meta.eql(l, r)) return false;
    return true;
}
