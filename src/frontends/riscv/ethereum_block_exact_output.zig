//! Persist and re-decode the exact-count V2 proof forest. The JSON roster is
//! transport only; a receiver must independently pin its roster digest.
const std = @import("std");
const spans = @import("recursion/span_statement_blake3.zig");
const parent = @import("recursion/blake3_execution_parent_protocol.zig");
const frontier = @import("recursion/blake3_stream_frontier.zig");
const transport = @import("recursion/blake3_exact_forest_transport.zig");

pub const Published = struct {
    roster_digest: [32]u8,
    proof_count: usize,
    proof_bytes: u64,
};
const BundleMember = struct {
    statement: spans.SpanStatement,
    admission: parent.Admission,
    proof_path: []const u8,
};

pub fn publish(a: std.mem.Allocator, bundle_path: []const u8, forest: *const frontier.Frontier.ExactForest) !Published {
    _ = try forest.validate();
    const roster_digest = try forest.rosterDigest();
    var members: [spans.MAX_SLOT_HEIGHT + 1]BundleMember = undefined;
    var receipts: [spans.MAX_SLOT_HEIGHT + 1]transport.Member = undefined;
    var paths: [spans.MAX_SLOT_HEIGHT + 1][]u8 = undefined;
    var path_count: usize = 0;
    defer for (paths[0..path_count]) |path| a.free(path);
    var total_bytes: u64 = 0;
    for (forest.nodes[0..forest.count], 0..) |node, i| {
        const bytes = node.transport_bytes orelse return error.MissingExactForestProof;
        const path = try std.fmt.allocPrint(a, "{s}.node-{d}.proof", .{ bundle_path, i });
        paths[i] = path;
        path_count += 1;
        members[i] = .{ .statement = node.statement, .admission = node.admission, .proof_path = path };
        receipts[i] = .{ .statement = node.statement, .admission = node.admission, .proof_bytes = bytes };
        total_bytes = try std.math.add(u64, total_bytes, bytes.len);
    }
    // Re-decode and verify canonical transport before publishing any paths.
    _ = try transport.verifyStreamingBytes(a, forest.job, receipts[0..forest.count], roster_digest);
    for (members[0..forest.count], receipts[0..forest.count]) |member, receipt| try writeNew(member.proof_path, receipt.proof_bytes);
    const bundle = try std.json.Stringify.valueAlloc(a, .{
        .version = transport.VERSION,
        .job = forest.job,
        .members = members[0..forest.count],
    }, .{ .whitespace = .indent_2 });
    defer a.free(bundle);
    try writeNew(bundle_path, bundle);
    return .{ .roster_digest = roster_digest, .proof_count = forest.count, .proof_bytes = total_bytes };
}

fn writeNew(path: []const u8, bytes: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
