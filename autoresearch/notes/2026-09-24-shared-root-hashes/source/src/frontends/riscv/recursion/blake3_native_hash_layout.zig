//! Sizing for native hash columns, not proof or capture admission.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("blake3_engine_protocol.zig");
const group = @import("air/blake3_merkle_group_witness.zig");
pub const Counts = @import("air/blake3_draw_hash_layout.zig").Counts;
pub const Layout = struct {
    transcript: Counts,
    paths: Counts,
    total: Counts,
    logs: [2]u32,
    pub fn init(a: std.mem.Allocator, transcript: Counts, capture: *const core.verifier.ProofCapture(suite.Hasher)) !Layout {
        if (capture.column_log_sizes.len != 4 or capture.trace_paths.len != 4 or capture.fri.layers.len == 0) return error.InvalidNativeHashLayout;
        var paths = Counts{ .g = 0, .xor = 0 };
        for (capture.column_log_sizes, capture.trace_paths) |columns, path| {
            try addGroup(a, &paths, 1, columns.len, path.path_depth, path.positions.len);
        }
        for (capture.fri.layers) |layer| {
            const width: u32 = if (layer.fold_step > 1) 4 else 1;
            if (layer.fold_width % width != 0) return error.InvalidNativeHashLayout;
            try addGroup(a, &paths, layer.fold_width / width, width * 4, layer.path_depth, layer.positions.len);
        }
        return fromCounts(transcript, paths);
    }
    fn fromCounts(transcript: Counts, paths: Counts) !Layout {
        const total = Counts{ .g = try std.math.add(usize, transcript.g, paths.g), .xor = try std.math.add(usize, transcript.xor, paths.xor) };
        const logs = [2]u32{ rowLog(total.g), rowLog(total.xor) };
        if (logs[0] > 24 or logs[1] > 24) return error.InvalidNativeHashLayout;
        return .{ .transcript = transcript, .paths = paths, .total = total, .logs = logs };
    }
    pub fn validateEmitted(self: Layout, transcript: Counts, paths: Counts) !void {
        if (!std.meta.eql(self, try fromCounts(transcript, paths))) return error.InvalidNativeHashLayout;
    }
};
fn rowLog(count: usize) u32 {
    return if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
}
fn addGroup(a: std.mem.Allocator, total: *Counts, leaves: u32, words: usize, depth: u32, openings: usize) !void {
    if (depth > 31 or words > std.math.maxInt(u32) or openings > std.math.maxInt(u32)) return error.InvalidNativeHashLayout;
    var statement = group.Statement{ .namespace = 2_000_000, .payload = .{ .circuit = 3_000_000, .first_wire = 0 }, .leaf_count = leaves, .words_per_leaf = @intCast(words), .index = 0, .depth = @intCast(depth), .root = @splat(0) };
    const counts = try group.requiredHashRows(a, statement);
    if (openings == 0) return;
    statement.shared_root = if (depth > 0 and openings > 1) .{ .first_namespace = statement.namespace, .query_index = 1, .queries = @intCast(openings) } else null;
    const rest = try group.requiredHashRows(a, statement);
    total.g = try std.math.add(usize, total.g, try std.math.add(usize, counts.g, try std.math.mul(usize, rest.g, openings - 1)));
    total.xor = try std.math.add(usize, total.xor, try std.math.add(usize, counts.xor, try std.math.mul(usize, rest.xor, openings - 1)));
}
