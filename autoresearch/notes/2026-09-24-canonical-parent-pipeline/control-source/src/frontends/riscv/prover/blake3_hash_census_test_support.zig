//! Hash-work census only: candidate sharing is not a proof or circuit admission.
const std = @import("std");
const group = @import("../recursion/air/blake3_merkle_group_witness.zig");
const Counts = struct { actual: usize = 0, payload: usize = 0, ancestor: usize = 0, candidate: usize = 0 };
pub fn check(a: std.mem.Allocator, proof: anytype, state: anytype) !void {
    var total = Counts{};
    for (proof.column_log_sizes, proof.trace_paths, 0..) |columns, path, index|
        try add(a, &total, "trace", index, 1, @intCast(columns.len), path.path_depth, path.positions, 0);
    for (proof.fri.layers, 0..) |layer, index| {
        const width: u32 = if (layer.fold_step > 1) 4 else 1;
        try add(a, &total, "fri", index, layer.fold_width / width, width * 4, layer.path_depth, layer.positions, layer.fold_step);
    }
    try std.testing.expectEqual(state.paths.live.g_rows.len, total.actual);
    const transcript = state.transcript.live.g_rows.len;
    std.debug.print("BLAKE3_HASH_CENSUS_TOTAL transcript_g={d} payload_and_subtree_g={d} ancestor_g={d} actual_g={d} shared_candidate_g={d} candidate_only=true shared_topology_checked=true\n", .{ transcript, total.payload, total.ancestor, transcript + total.actual, transcript + total.candidate });
}
fn add(a: std.mem.Allocator, total: *Counts, kind: []const u8, index: usize, leaves: u32, words: u32, depth: u32, positions: []const usize, shift: u32) !void {
    var statement = group.Statement{ .namespace = 2_000_000, .payload = .{ .circuit = 3_000_000, .first_wire = 0 }, .leaf_count = leaves, .words_per_leaf = words, .index = 0, .depth = @intCast(depth), .root = @splat(0) };
    const full = try group.requiredHashRows(a, statement);
    statement.depth = 0;
    const payload = try group.requiredHashRows(a, statement);
    const node_g = if (depth == 0) 0 else (full.g - payload.g) / depth;
    try std.testing.expectEqual(full.g, payload.g + node_g * depth);
    var unique = std.AutoHashMap(struct { level: u32, position: usize }, void).init(a);
    defer unique.deinit();
    var unique_payloads: usize = 0;
    var unique_ancestors: usize = 0;
    for (positions) |position| {
        const node = position >> @intCast(shift);
        for (0..depth + 1) |level| {
            const entry = try unique.getOrPut(.{ .level = @intCast(level), .position = node >> @intCast(level) });
            if (!entry.found_existing) {
                if (level == 0) unique_payloads += 1 else unique_ancestors += 1;
            }
        }
    }
    const normalized = try a.alloc(usize, positions.len);
    defer a.free(normalized);
    for (positions, normalized) |position, *out| out.* = position >> @intCast(shift);
    var topology = try @import("../recursion/air/blake3_shared_opening_topology.zig").build(a, depth, normalized);
    defer topology.deinit();
    const shared_counts = topology.computedCounts();
    try std.testing.expectEqual(unique_payloads, shared_counts.payloads);
    try std.testing.expectEqual(unique_ancestors, shared_counts.ancestors);
    const actual = full.g * positions.len;
    const payload_g = payload.g * positions.len;
    const candidate = payload.g * unique_payloads + node_g * unique_ancestors;
    try std.testing.expect(candidate <= actual);
    total.actual += actual;
    total.payload += payload_g;
    total.ancestor += actual - payload_g;
    total.candidate += candidate;
    std.debug.print("BLAKE3_HASH_CENSUS kind={s} index={d} openings={d} depth={d} payload_g={d} ancestor_g={d} unique_payloads={d} unique_ancestors={d} shared_candidate_g={d}\n", .{ kind, index, positions.len, depth, payload_g, actual - payload_g, unique_payloads, unique_ancestors, candidate });
}
