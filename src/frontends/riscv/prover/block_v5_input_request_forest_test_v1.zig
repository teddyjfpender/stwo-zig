//! Pure topology/equation/transport fixtures. No proof, guest or PCS is run.
//! Descriptors here are routing fixtures, never positive cryptographic admission.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Plan = @import("../recursion/block_v5_input_request_forest_plan_v1.zig");
const Graph = @import("../recursion/air/block_v5_input_request_forest_graph_v1.zig");
const Bus = @import("../recursion/block_v5_input_request_forest_bus_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Run = @import("block_v5_input_request_forest_run_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
test "input request forest: prefix retains exact original canonical and extended packed config words" {
    const Layout = @import("../recursion/block_v5_input_request_forest_public_v1.zig");
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    // Prefix framing only: unused key/policy fields stay undefined, and no
    // positive admission or verification receives these metadata proposals.
    var spec: Layout.Spec = undefined;
    spec.geometry.profile = .csp_q70_pow26;
    spec.geometry.config = Base.CSP_CONFIG;
    spec.expected_id = @splat(0xdd);
    var policy: Layout.Policy = undefined;
    policy.index = 0;
    policy.specs = (&spec)[0..1];
    const canonical = try Bus.nodePrefix(policy);
    try std.testing.expectEqual(@as(u32, 15), canonical.len);
    try std.testing.expectEqualSlices(u32, &.{ 0x42354d50, 4, 2, 26, 1, 70, 0 }, canonical.words[0..7]);
    for (canonical.words[7..canonical.len]) |value| try std.testing.expectEqual(@as(u32, 0xdddddddd), value);
    spec.geometry.config.fri_config.fold_step = 2;
    spec.geometry.config.lifting_log_size = 22;
    const extended = try Bus.nodePrefix(policy);
    try std.testing.expectEqual(@as(u32, 19), extended.len);
    try std.testing.expectEqualSlices(u32, &.{ 0x42354d50, 4, 2, 26, 1, 70, 0, 2, 22, 0, 0 }, extended.words[0..11]);
    for (extended.words[11..extended.len]) |value| try std.testing.expectEqual(@as(u32, 0xdddddddd), value);
}
fn topologyFixture(a: std.mem.Allocator) !void {
    var ranges: [17]Plan.Range = undefined;
    for (&ranges, 0..) |*range, index| range.* = .{ .first = @intCast(index * 4), .count = if (index == 16) 1 else 4, .leaves = 1 };
    var geometry = try Plan.derive(a, &ranges, 65, .{});
    defer geometry.deinit();
    try std.testing.expectEqual(@as(usize, 7), geometry.nodes.len);
    const root = geometry.nodes[geometry.root];
    try std.testing.expectEqual(@as(u32, 1), root.child_count);
    try std.testing.expect(root.kind == .carrier);
    try std.testing.expectEqualDeep(Plan.Range{ .first = 0, .count = 65, .leaves = 17 }, root.range);
    var provider_nodes: usize = 0;
    var leaf_uses: [17]u32 = @splat(0);
    var node_uses: [7]u32 = @splat(0);
    for (geometry.nodes, 0..) |node, index| {
        provider_nodes += @intFromBool(node.kind == .carrier);
        try std.testing.expect(node.child_count > 0 and node.child_count <= Plan.FAN_IN);
        for (node.children[0..node.child_count]) |child| switch (child) {
            .leaf => |leaf| leaf_uses[leaf] += 1,
            .node => |prior| {
                try std.testing.expect(prior < index);
                node_uses[prior] += 1;
            },
        };
    }
    try std.testing.expectEqual(@as(usize, 1), provider_nodes);
    for (leaf_uses) |uses| try std.testing.expectEqual(@as(u32, 1), uses);
    for (node_uses, 0..) |uses, index| try std.testing.expectEqual(@as(u32, if (index == geometry.root) 0 else 1), uses);
}
test "input request forest: uneven 17 leaves exact once with one common carrier" {
    try topologyFixture(std.testing.allocator);
}
test "input request forest: every topology allocation failure releases all geometry" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, topologyFixture, .{});
}
test "input request forest: carry short remainders to attain minimum exact merge count" {
    const a = std.testing.allocator;
    for ([_]usize{ 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 64, 65, 66, 67, 257 }) |count| {
        const ranges = try a.alloc(Plan.Range, count);
        defer a.free(ranges);
        for (ranges, 0..) |*range, index| range.* = .{ .first = @intCast(index), .count = 1, .leaves = 1 };
        var geometry = try Plan.derive(a, ranges, @intCast(count), .{});
        defer geometry.deinit();
        // Every merge reduces the live reference count by at most three.
        const minimum_merges = (count - 1 + Plan.FAN_IN - 2) / (Plan.FAN_IN - 1);
        try std.testing.expectEqual(minimum_merges + 1, geometry.nodes.len);
        const leaf_uses = try a.alloc(u32, count);
        defer a.free(leaf_uses);
        const node_uses = try a.alloc(u32, geometry.nodes.len);
        defer a.free(node_uses);
        @memset(leaf_uses, 0);
        @memset(node_uses, 0);
        for (geometry.nodes, 0..) |node, index| {
            if (node.kind == .merge) try std.testing.expect(node.child_count >= 2 and node.child_count <= Plan.FAN_IN);
            for (node.children[0..node.child_count]) |ref| switch (ref) {
                .leaf => |leaf| leaf_uses[leaf] += 1,
                .node => |prior| {
                    try std.testing.expect(prior < index);
                    node_uses[prior] += 1;
                },
            };
        }
        for (leaf_uses) |uses| try std.testing.expectEqual(@as(u32, 1), uses);
        for (node_uses, 0..) |uses, index| try std.testing.expectEqual(@as(u32, if (index == geometry.root) 0 else 1), uses);
        try std.testing.expectEqualDeep(Plan.Range{ .first = 0, .count = @intCast(count), .leaves = @intCast(count) }, geometry.nodes[geometry.root].range);
    }
}
test "input request forest: missing repeated reordered rounded or oversized ranges reject" {
    const a = std.testing.allocator;
    const valid = [_]Plan.Range{ .{ .first = 0, .count = 4, .leaves = 1 }, .{ .first = 4, .count = 1, .leaves = 1 } };
    var geometry = try Plan.derive(a, &valid, 5, .{});
    defer geometry.deinit();
    for (0..4) |fault| {
        var ranges = valid;
        switch (fault) {
            0 => ranges[1].first = 0,
            1 => ranges[1].first = 5,
            2 => ranges[0].count = 5,
            3 => ranges[1].leaves = 2,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidInputRequestForest, Plan.derive(a, &ranges, 5, .{}));
    }
    try std.testing.expectError(error.InvalidInputRequestForest, Plan.derive(a, &valid, 6, .{}));
    try std.testing.expectError(error.InputRequestForestResourceLimit, Plan.derive(a, &valid, 5, .{ .max_nodes = 1 }));
    try std.testing.expectError(error.InputRequestForestResourceLimit, Plan.derive(a, &valid, 1 << 30, .{}));
}
const Values = struct {
    own: [100]u32 = @splat(0),
    child: [3][30]u32 = @splat(@splat(0)),
    pub fn at(self: *const @This(), wire: Bus.Wire) ![4]M {
        const raw = switch (wire.kind) {
            .output_slot => if (wire.coordinate < self.own.len) self.own[wire.coordinate] else return error.InvalidFixtureCell,
            .child_cell => if (wire.child < self.child.len and wire.coordinate < self.child[wire.child].len) self.child[wire.child][wire.coordinate] else return error.InvalidFixtureCell,
            else => return error.InvalidFixtureCell,
        };
        const part = wire.part orelse return error.InvalidFixtureCell;
        return .{ M.fromCanonical((raw >> @as(u5, @intCast(8 * @as(u32, part)))) & 255), M.zero(), M.zero(), M.zero() };
    }
};
const Fixture = struct {
    values: Values,
    cvs: [3][1]Graph.Coordinate,
    children: [2]Graph.Child,
    provider: Graph.Child,
    fn init(self: *@This()) void {
        self.values = .{};
        self.values.own[4] = 0;
        self.values.own[5] = 7;
        self.values.own[6] = 2;
        const first: u64 = 0x2ffffffff;
        const split: u64 = first + 10;
        const last: u64 = split + 20;
        self.values.own[32] = @truncate(first);
        self.values.own[33] = @truncate(first >> 32);
        self.values.own[34] = @truncate(last);
        self.values.own[35] = @truncate(last >> 32);
        self.values.own[38] = 300;
        for (0..8) |i| {
            self.values.own[49 + i] = @as(u32, @intCast(i)) * 0x11111111;
            self.values.own[61 + i] = 0xf0000000 + @as(u32, @intCast(i));
        }
        self.values.own[57] = 0xffffffff;
        self.values.own[58] = 0x80000000;
        for (0..3) |index| {
            @memcpy(self.values.child[index][0..8], self.values.own[49..57]);
            self.values.child[index][8] = 300;
            @memcpy(self.values.child[index][9..11], self.values.own[57..59]);
            @memcpy(self.values.child[index][11..19], self.values.own[61..69]);
            self.cvs[index][0] = .{ .child = @intCast(index), .first_cell = 11, .word_count = 8 };
        }
        for (&self.children, 0..) |*child, index| {
            const begin = if (index == 0) first else split + 1;
            const end = if (index == 0) split else last;
            self.values.child[index][20] = @truncate(begin);
            self.values.child[index][21] = @truncate(begin >> 32);
            self.values.child[index][22] = @truncate(end);
            self.values.child[index][23] = @truncate(end >> 32);
            self.values.child[index][24] = if (index == 0) 0 else 4;
            self.values.child[index][25] = if (index == 0) 4 else 3;
            self.values.child[index][26] = 1;
            child.* = self.descriptor(@intCast(index), true);
        }
        self.provider = self.descriptor(2, false);
    }
    fn descriptor(self: *@This(), index: u32, clocks: bool) Graph.Child {
        return .{ .root = .{ .child = index, .first_cell = 0, .word_count = 8 }, .length = .{ .child = index, .first_cell = 8, .word_count = 1 }, .prefix = .{ .child = index, .first_cell = 9, .word_count = 2 }, .frontier = &self.cvs[index], .first_cycle = if (clocks) .{ .child = index, .first_cell = 20, .word_count = 2 } else null, .last_cycle = if (clocks) .{ .child = index, .first_cell = 22, .word_count = 2 } else null, .first_window = if (clocks) .{ .child = index, .first_cell = 24, .word_count = 1 } else null, .window_count = if (clocks) .{ .child = index, .first_cell = 25, .word_count = 1 } else null, .leaf_count = if (clocks) .{ .child = index, .first_cell = 26, .word_count = 1 } else null };
    }
};
const desc = Graph.Descriptor{ .carrier = true, .child_count = 2, .range = .{ .first = 0, .count = 7, .leaves = 2 }, .prefix_words = 2, .frontier_count = 1 };
const graph_ranges = [_]Plan.Range{ .{ .first = 0, .count = 4, .leaves = 1 }, .{ .first = 4, .count = 3, .leaves = 1 } };
fn graphFixture(a: std.mem.Allocator) !void {
    var fixture: Fixture = undefined;
    fixture.init();
    var graph = try Graph.prepareForDescriptor(a, &fixture.values, desc, &fixture.children, fixture.provider, &graph_ranges);
    defer graph.deinit();
    // The exact original Builder ABI has all source inputs before operations.
    for (graph.circuit.nodes[0..graph.inputs.len]) |node| try std.testing.expect(node.op == .input);
    const inputs = try a.dupe(Q, graph.inputs);
    defer a.free(inputs);
    inputs[0] = inputs[0].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, graph.values));
}
test "input request forest: true u64 adjacency prefix frontier and census equations" {
    try graphFixture(std.testing.allocator);
}
test "input request forest: graph recording allocation rollback preserves original errors" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, graphFixture, .{});
}
test "input request forest: independent source mutations violate actual equations" {
    for ([_]struct { child: usize, word: usize }{ .{ .child = 0, .word = 0 }, .{ .child = 0, .word = 8 }, .{ .child = 1, .word = 9 }, .{ .child = 2, .word = 18 }, .{ .child = 1, .word = 21 }, .{ .child = 1, .word = 24 }, .{ .child = 0, .word = 25 }, .{ .child = 1, .word = 26 } }) |fault| {
        var fixture: Fixture = undefined;
        fixture.init();
        fixture.values.child[fault.child][fault.word] ^= 1;
        try std.testing.expectError(error.UnsatisfiedCircuit, Graph.prepareForDescriptor(std.testing.allocator, &fixture.values, desc, &fixture.children, fixture.provider, &graph_ranges));
    }
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.provider.first_cycle = fixture.children[0].first_cycle;
    try std.testing.expectError(error.UntrustedInputRequestGraph, Graph.prepareForDescriptor(std.testing.allocator, &fixture.values, desc, &fixture.children, fixture.provider, &graph_ranges));
}
test "input request forest: ordinary selection is explicit and missing authority rejects" {
    const Selection = @import("block_v5_cpu_input_request_forest_v1.zig");
    try Selection.requireSelection(false, null);
    try std.testing.expectError(error.MissingIndependentInputRequestForestPolicy, Selection.requireSelection(true, null));
    try std.testing.expect(!Selection.complete_block_authority);
}
test "input request forest: durable pins have no proof authority and strict failure cleanup" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var buffer: [96]u8 = undefined;
    const path = try Run.filename(&buffer, 12);
    const raw = "not a recursive proof";
    try Files.publish(dir.dir, path, raw);
    try std.testing.expectError(error.ExistingV5BundleArtifact, Files.publish(dir.dir, path, raw));
    const bytes = try Files.readPinned(std.testing.allocator, dir.dir, path, raw.len, Files.hash(raw), 100);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings(raw, bytes);
    var tampered = Files.hash(raw);
    tampered[0] ^= 1;
    try std.testing.expectError(error.TamperedV5BundleFileHash, Files.readPinned(std.testing.allocator, dir.dir, path, raw.len, tampered, 100));
    try std.testing.expectError(error.V5BundleFileResourceLimit, Files.readPinned(std.testing.allocator, dir.dir, path, raw.len, Files.hash(raw), 1));
}
test "input request forest: geometry heap owner can release only after its lease" {
    const owner = try Budget.create(std.testing.allocator, 1 << 20);
    const lease = owner.retain();
    var geometry = try Plan.derive(owner.allocator(), &graph_ranges, 7, .{});
    owner.destroy();
    geometry.deinit();
    lease.destroy();
}
test "input request forest: actual artifact teardown retains heap after original budget release" {
    const Stage = @import("block_v5_input_request_forest_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const owner = try Budget.create(std.testing.allocator, 1 << 20);
    const a = owner.allocator();
    const bytes = try a.dupe(u8, "deinit-only fixture, never a proof");
    const schedule = try a.alloc(Bus.Wire, 0);
    // Only fields read by deinit are initialized; no key/admission/capture/leaf
    // positive path can receive this teardown fixture.
    var artifact: Stage.Artifact = undefined;
    artifact.allocator = a;
    artifact.owner = owner.retain();
    artifact.bytes = bytes;
    artifact.schedule = schedule;
    owner.destroy();
    artifact.deinit();
}
