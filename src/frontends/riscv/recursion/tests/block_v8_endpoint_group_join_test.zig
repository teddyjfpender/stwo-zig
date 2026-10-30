const std = @import("std");
const core = @import("stwo_core");
const Saved = @import("../block_v8_endpoint_group_join_saved_v1.zig");
const Receiver = @import("../block_v8_endpoint_group_join_receiver_v1.zig");
const Source = @import("../block_v8_endpoint_group_join_source_v1.zig");
const Observer = struct {
    pub const budget_bytes = 32 << 30;
    pub fn observeFiles(a: std.mem.Allocator, dir: std.fs.Dir, external: Saved.External) !void {
        var original = try Saved.produce(a, dir, external, .{});
        var live = true;
        defer if (live) original.deinit();
        try std.testing.expectEqual(@as(u32, 2), original.data.cohort_policy.cohort_count);
        // Persist the parent and only its public operands. All captures, child
        // proof decoders, fixed keys and profiles are already gone on return.
        try dir.writeFile(.{ .sub_path = "group-root.proof", .data = original.root.bytes });
        try dir.writeFile(.{ .sub_path = "group-root-claims.bin", .data = original.claims });
        const metadata = try a.dupe(u8, original.metadata);
        defer a.free(metadata);
        const addresses = try a.dupe(u32, original.data.selected_initial_addresses);
        defer a.free(addresses);
        const roots = original.data.memory_roots;
        const policy = original.data.cohort_policy;
        const proof_ns = original.root.proof_ns;
        const whole_ns = original.root.whole_ns;
        const root_len = original.root.bytes.len;
        original.deinit();
        live = false;
        const bytes = try dir.readFileAlloc(a, "group-root.proof", 16 << 20);
        defer a.free(bytes);
        const claims = try dir.readFileAlloc(a, "group-root-claims.bin", 16 << 20);
        defer a.free(claims);
        // Receiver never reads any original body or a previously successful
        // verification receipt. Its key is rebuilt from ELF + public metadata.
        const input = Receiver.Input{ .root = bytes, .physical_claims = claims, .group_metadata = metadata, .global_roots = roots, .cohort_policy = policy, .selected_addresses = addresses };
        var verified = try Receiver.verify(a, external, input);
        verified.deinit();
        var bad = input;
        bad.cohort_policy.cohort_count = 1;
        if (Receiver.verify(a, external, bad)) |value| {
            var v = value;
            v.deinit();
            return error.AcceptedDroppedGroupMember;
        } else |_| {}
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &sha, .{});
        std.debug.print("B8_GROUP_SINGLE_DAG queries=70 pow=26 cohorts=2 group_bodies=1 bridge_bodies=1 compact_bodies=1 root_bytes={d} root_sha256={s} proof_ns={d} whole_ns={d} freshly_file_verified=true\n", .{ root_len, std.fmt.bytesToHex(sha, .lower), proof_ns, whole_ns });
    }
};
test "canonical Group three originals close in ONE root and fresh file receiver" {
    try @import("../../prover/tests/block_v8_endpoint_group_execution_test.zig").qualifyPipelineWithObserver(.compact_v1, Observer);
}

test "Group join closure graph rejects changed transition root and CPU coordinates" {
    const Public = @import("../block_v8_endpoint_group_join_public_v1.zig");
    const Graph = @import("../block_v8_endpoint_group_join_graph_v1.zig");
    const a = std.testing.allocator;
    var children: [3]Source.Value = undefined;
    var count: usize = 0;
    defer for (children[0..count]) |*child| child.deinit();
    for (&children, [_]usize{ 8, 3, 4 }, 0..) |*child, roots, i| {
        const words = try a.alloc(u32, 8 * roots);
        @memset(words, 0);
        const public = try a.alloc(core.fields.qm31.QM31, if (i == 0) 832 else if (i == 1) 3 else 10);
        @memset(public, core.fields.qm31.QM31.zero());
        child.* = .{ .allocator = a, .template = @splat(1), .statement = .{ .allocator = a, .words = words, .felts = &.{}, .first = &.{}, .claims = &.{}, .sealed_offset = 0, .roots_offset = @splat(0) }, .public = public, .roots_count = roots };
        count += 1;
    }
    const extra: [264]core.fields.qm31.QM31 = @splat(core.fields.qm31.QM31.zero());
    const values = Public.Values{ .children = &children, .extra = &extra };
    var graph = try Graph.Owned.compile(a, values, 2);
    defer graph.deinit();
    const inputs = try a.alloc(core.fields.qm31.QM31, graph.sources.len);
    defer a.free(inputs);
    const evaluation = try a.alloc(core.fields.qm31.QM31, graph.circuit.nodes.len);
    defer a.free(evaluation);
    try graphInputs(values, graph.sources, inputs);
    try graph.circuit.evaluateInto(inputs, evaluation);
    children[2].public[0] = core.fields.qm31.QM31.one();
    try graphInputs(values, graph.sources, inputs);
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, evaluation));
    children[2].public[0] = core.fields.qm31.QM31.zero();
    children[0].statement.words[24] = 1;
    try graphInputs(values, graph.sources, inputs);
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, evaluation));
    children[0].statement.words[32] = core.fields.m31.Modulus - 1;
    try graphInputs(values, graph.sources, inputs);
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, evaluation));
    children[0].statement.words[24] = 0;
    children[0].statement.words[32] = 0;
    children[0].public[4 * 35] = core.fields.qm31.QM31.one();
    try graphInputs(values, graph.sources, inputs);
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(inputs, evaluation));
}
fn graphInputs(values: @import("../block_v8_endpoint_group_join_public_v1.zig").Values, sources: []const @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire, inputs: []core.fields.qm31.QM31) !void {
    for (sources, inputs) |wire, *value| value.* = core.fields.qm31.QM31.fromM31Array(try (@import("../block_v8_endpoint_group_join_public_v1.zig").View{ .values = values }).at(wire));
}
