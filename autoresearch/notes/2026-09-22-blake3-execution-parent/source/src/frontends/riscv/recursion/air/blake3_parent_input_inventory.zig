//! Every arithmetic input has one matching scalar, secure-pack or public producer.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const scalar = @import("scalar_wire_source.zig");
const boundary = @import("blake3_boundary.zig");
const pack = @import("qm31_pack_wire.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
pub fn check(a: std.mem.Allocator, graphs: anytype, values: anytype, scalars: []const scalar.Row, boundaries: []const boundary.Row, packs: []const pack.Row) !usize {
    var seen: [graphs.len][]bool = undefined;
    for (graphs, &seen) |graph, *mask| {
        mask.* = try a.alloc(bool, graph.nodes.len);
        @memset(mask.*, false);
    }
    for (scalars) |row| try mark(graphs, values, seen, row[1].v, row[2].v, Q.fromBase(row[0]));
    for (boundaries) |row| try mark(graphs, values, seen, row[5].v, row[6].v, Q.fromM31Array(row[0..4].*));
    for (packs) |row| try mark(graphs, values, seen, row[10].v, row[11].v, Q.fromM31Array(row[0..4].*));
    var count: usize = 0;
    for (graphs, seen, 0..) |graph, mask, lane| {
        const uses = try lower.computeUseCountsInto(graph, try a.alloc(u32, graph.nodes.len));
        for (graph.nodes, mask, uses) |node, present, reads| {
            if (node.op == .input) {
                // Execution draws all universal challenges, including domains
                // unused by this statement. Zero-use secure inputs need no rows.
                if (!present and !(graphs.len == 3 and lane == 0 and reads == 0)) return error.MissingNativeParentInput;
                count += 1;
            }
        }
    }
    return count;
}
fn mark(graphs: anytype, values: anytype, seen: anytype, circuit: u32, node: u32, value: Q) !void {
    if (circuit < 1500 or circuit >= 1500 + 2 * graphs.len) return;
    if (circuit % 2 != 0) return error.InvalidNativeParentInput;
    const lane = (circuit - 1500) / 2;
    if (node >= graphs[lane].nodes.len or graphs[lane].nodes[node].op != .input or !values[lane][node].eql(value)) return error.InvalidNativeParentInput;
    if (seen[lane][node]) return error.DuplicateNativeParentInput;
    seen[lane][node] = true;
}
