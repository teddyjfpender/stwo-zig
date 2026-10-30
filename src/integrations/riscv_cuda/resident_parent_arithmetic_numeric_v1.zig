//! Independent CPU recorder evaluation versus GPU graph replay, test-only.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const P = @import("resident_parent_arithmetic_plan_v1.zig");
const Recorder = @import("../../frontends/riscv/recursion/air/composition_graph_recorder.zig");
const Base = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
pub fn exportVectors(backing: std.mem.Allocator, path: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    var source: std.Io.Writer.Allocating = .init(a);
    try source.writer.writeAll(Base.preamble);
    try source.writer.writeAll(@embedFile("resident_parent_arithmetic_v1.cuh"));
    try dir.writeFile(.{ .sub_path = "arithmetic.cu", .data = source.written() });
    try dir.writeFile(.{ .sub_path = "numeric_runner.cu", .data = @embedFile("resident_parent_arithmetic_numeric_runner_v1.cpp") });
    const sizes = [_]usize{ 17, 128, 4096 };
    var circuits: [3]Recorder.Circuit = undefined;
    var graphs: [3]P.Original.CircuitGraph = undefined;
    for (sizes, &circuits, &graphs) |size, *c, *g| {
        const nodes = try a.alloc(P.Original.Node, size + 3);
        for (nodes[0..size], 0..) |*n, i| n.* = if (i < 8) .{ .op = .input } else switch (i % 6) {
            0 => .{ .op = .{ .constant = .{ 7, 9, 11, 13 } } },
            1 => .{ .op = .{ .add = .{ .lhs = @intCast(i - 1), .rhs = @intCast(i % 8) } } },
            2 => .{ .op = .{ .sub = .{ .lhs = @intCast(i - 1), .rhs = @intCast(i % 8) } } },
            3 => .{ .op = .{ .mul = .{ .lhs = @intCast(i - 1), .rhs = @intCast(i % 8) } } },
            4 => .{ .op = .{ .neg = @intCast(i - 1) } },
            else => .{ .op = .{ .inverse = 0 } },
        };
        nodes[size] = .{ .op = .{ .sub = .{ .lhs = @intCast(size - 1), .rhs = @intCast(size - 1) } } };
        nodes[size + 1] = .{ .op = .{ .constant = .{ 2, 3, 5, 7 } } };
        nodes[size + 2] = .{ .op = .{ .sub = .{ .lhs = 0, .rhs = @intCast(size + 1) } } };
        const outputs = try a.dupe(u32, &.{ @intCast(size), @intCast(size + 2) });
        const identity = P.Original.computeGraphDigest(nodes, outputs);
        c.* = .{ .allocator = a, .nodes = nodes, .outputs = outputs, .input_count = 8, .identity_digest = identity };
        g.* = c.graph();
    }
    var plan = try P.Plan.init(a, &graphs, .{});
    defer plan.deinit();
    const inputs = try a.alloc(Q, plan.input_words / 4);
    for (inputs, 0..) |*q, i| q.* = if (i % 8 == 0) Q.fromU32Unchecked(2, 3, 5, 7) else Q.fromU32Unchecked(@intCast(i + 19), @intCast(i * 3 + 23), @intCast(i * 5 + 41), @intCast(i * 7 + 53));
    const expected = try a.alloc(Q, plan.value_words / 4);
    for (&circuits, plan.graphs) |*c, g| try c.evaluateInto(inputs[g.input_first..][0..g.input_count], expected[g.node_first..][0..g.node_count]);
    var b: std.Io.Writer.Allocating = .init(a);
    try words(&b.writer, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(plan.graphs)));
    try words(&b.writer, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(plan.nodes)));
    try words(&b.writer, plan.level_nodes);
    try words(&b.writer, plan.level_offsets);
    try words(&b.writer, plan.outputs);
    try qs(&b.writer, inputs);
    try qs(&b.writer, expected);
    try dir.writeFile(.{ .sub_path = "numeric.bin", .data = b.written() });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source.written(), &digest, .{});
    const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-resident-original-arithmetic-v1", .graphs = 3, .nodes = plan.nodes.len, .source_sha256 = std.fmt.bytesToHex(digest, .lower), .scope = "original arithmetic replay primitive, not complete child verifier", .expected_values = "CPU original Circuit.evaluateInto test oracle only" }, .{ .whitespace = .indent_2 });
    try dir.writeFile(.{ .sub_path = "source_manifest.json", .data = json });
}
fn word(w: anytype, x: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, x, .little);
    try w.writeAll(&b);
}
fn words(w: anytype, x: []align(1) const u32) !void {
    try word(w, @intCast(x.len));
    for (x) |v| try word(w, v);
}
fn qs(w: anytype, x: []const Q) !void {
    try word(w, @intCast(x.len * 4));
    for (x) |q| for (q.toM31Array()) |m| try word(w, m.v);
}
