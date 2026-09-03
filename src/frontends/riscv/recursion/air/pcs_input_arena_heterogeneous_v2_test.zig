const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const circuit = @import("composition_circuit.zig");
const pcs = @import("pcs_deep_input_witness.zig");
const subject = @import("pcs_input_arena_heterogeneous_v2.zig");

test "R-012 heterogeneous PCS arena admits exact variable lane offsets" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var values = try Values.init(std.testing.allocator, reference, .binary_node);
    defer values.deinit();
    var arena = try subject.Arena.init(
        std.testing.allocator,
        reference,
        .binary_node,
        values.lanes(),
    );
    defer arena.deinit();
    try arena.validateAgainst(reference);

    try std.testing.expectEqual(@as(usize, 0), arena.offsets[0]);
    for (reference.lanes, 0..) |lane, lane_index| {
        try std.testing.expectEqual(
            arena.offsets[lane_index] + lane.bindings.len,
            arena.offsets[lane_index + 1],
        );
        try std.testing.expectEqualSlices(
            M31,
            values.lanes()[lane_index],
            arena.laneValues(lane_index),
        );
    }
    try std.testing.expect(reference.lanes[0].bindings.len !=
        reference.lanes[1].bindings.len);
    try std.testing.expect(reference.lanes[1].bindings.len !=
        reference.lanes[2].bindings.len);
}

test "R-012 heterogeneous PCS arena rejects offset graph and value mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var values = try Values.init(std.testing.allocator, reference, .binary_node);
    defer values.deinit();
    var arena = try subject.Arena.init(
        std.testing.allocator,
        reference,
        .binary_node,
        values.lanes(),
    );
    defer arena.deinit();

    arena.offsets[2] += 1;
    try std.testing.expectError(
        error.InvalidHeterogeneousPcsArena,
        arena.validateAgainst(reference),
    );
    arena.offsets[2] -= 1;

    arena.storage[arena.offsets[1] + 1] = M31.zero();
    try std.testing.expectError(
        error.InvalidHeterogeneousPcsArena,
        arena.validateAgainst(reference),
    );
    arena.storage[arena.offsets[1] + 1] = M31.fromCanonical(1_002);

    arena.witness.lanes[2].graph_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidHeterogeneousPcsArena,
        arena.validateAgainst(reference),
    );
}

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    lanes: [3]OwnedLane,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        var lanes: [3]OwnedLane = undefined;
        var initialized: usize = 0;
        errdefer for (lanes[0..initialized]) |*lane| lane.deinit();
        lanes[0] = try OwnedLane.init(allocator, 1, 1, &.{5});
        initialized += 1;
        lanes[1] = try OwnedLane.init(allocator, 2, 2, &.{ 6, 5 });
        initialized += 1;
        lanes[2] = try OwnedLane.init(allocator, 1, 3, &.{ 7, 6, 5 });
        return .{ .allocator = allocator, .lanes = lanes };
    }

    pub fn deinit(self: *Fixture) void {
        for (&self.lanes) |*lane| lane.deinit();
        self.* = undefined;
    }

    pub fn reference(self: *const Fixture) !pcs.Reference {
        var lanes: [3]pcs.Lane = undefined;
        for (&lanes, &self.lanes, 0..) |*target, *owned, index| target.* = .{
            .verifier_id = @intCast(index),
            .circuit_id = @intCast(701 + index),
            .profile = owned.profile,
            .graph = owned.graph,
            .bindings = owned.bindings,
        };
        return pcs.Reference.authenticate(lanes, pcs.computeReferenceDigest(lanes));
    }
};

const OwnedLane = struct {
    allocator: std.mem.Allocator,
    tree_logs: []u32,
    trees: []pcs.TreeProfile,
    profile: pcs.LaneProfile,
    nodes: []circuit.Node,
    outputs: []u32,
    bindings: []pcs.InputBinding,
    graph: circuit.CircuitGraph,

    fn init(
        allocator: std.mem.Allocator,
        sample_count: u32,
        query_count: u32,
        tree_logs: []const u32,
    ) !OwnedLane {
        const owned_logs = try allocator.dupe(u32, tree_logs);
        errdefer allocator.free(owned_logs);
        const trees = try allocator.alloc(pcs.TreeProfile, 1);
        errdefer allocator.free(trees);
        trees[0] = .{ .column_log_sizes = owned_logs };
        const profile = pcs.LaneProfile{
            .sample_count = sample_count,
            .query_count = query_count,
            .lifting_log_size = 8,
            .trees = trees,
        };
        const count = try profile.inputCount();
        const nodes = try allocator.alloc(circuit.Node, count);
        errdefer allocator.free(nodes);
        for (nodes) |*node| node.* = .{ .op = .input };
        const outputs = try allocator.alloc(u32, 1);
        errdefer allocator.free(outputs);
        outputs[0] = 0;
        const bindings = try allocator.alloc(pcs.InputBinding, count);
        errdefer allocator.free(bindings);
        for (bindings, 0..) |*binding, index| binding.* = .{
            .node_id = @intCast(index),
            .source = (try pcs.expectedSource(profile, index)).?,
        };
        const graph_digest = circuit.computeGraphDigest(nodes, outputs);
        return .{
            .allocator = allocator,
            .tree_logs = owned_logs,
            .trees = trees,
            .profile = profile,
            .nodes = nodes,
            .outputs = outputs,
            .bindings = bindings,
            .graph = try circuit.CircuitGraph.authenticate(nodes, outputs, graph_digest),
        };
    }

    fn deinit(self: *OwnedLane) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.allocator.free(self.trees);
        self.allocator.free(self.tree_logs);
        self.* = undefined;
    }
};

pub const Values = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    offsets: [4]usize,

    pub fn init(
        allocator: std.mem.Allocator,
        reference: pcs.Reference,
        kind: pcs.ProofKind,
    ) !Values {
        var offsets = [_]usize{0} ** 4;
        for (reference.lanes, 0..) |lane, index|
            offsets[index + 1] = offsets[index] + lane.bindings.len;
        const storage = try allocator.alloc(M31, offsets[3]);
        errdefer allocator.free(storage);
        for (reference.lanes, 0..) |lane, lane_index| {
            const active = switch (lane.verifier_id) {
                pcs.SEGMENT_VERIFIER_ID => kind == .segment_leaf,
                pcs.LEFT_RECURSION_VERIFIER_ID, pcs.RIGHT_RECURSION_VERIFIER_ID => kind == .binary_node,
                else => unreachable,
            };
            for (storage[offsets[lane_index]..offsets[lane_index + 1]], lane.bindings, 0..) |
                *value,
                binding,
                index,
            | value.* = if (!active)
                M31.zero()
            else if (std.meta.activeTag(binding.source) == .active_selector)
                M31.one()
            else
                M31.fromCanonical(@intCast(1_000 * lane_index + index + 1));
        }
        return .{ .allocator = allocator, .storage = storage, .offsets = offsets };
    }

    pub fn deinit(self: *Values) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn lanes(self: *const Values) [3][]const M31 {
        return .{
            self.storage[self.offsets[0]..self.offsets[1]],
            self.storage[self.offsets[1]..self.offsets[2]],
            self.storage[self.offsets[2]..self.offsets[3]],
        };
    }
};
