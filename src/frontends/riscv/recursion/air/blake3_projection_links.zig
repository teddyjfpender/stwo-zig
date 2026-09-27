//! Shared parity-preserving projected index bytes from authenticated query bits.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const queries = @import("blake3_query_links.zig");
pub const route = @import("blake3_byte_route.zig");
pub const pack = @import("qm31_pack_wire.zig");
const packed_circuit: u32 = 5_000_004;
const index_circuit: u32 = 5_000_005;
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 11, 7 });
pub const Prepared = struct {
    bit_reads: [][31]u32,
    ports: [32]?[]route.Endpoint,
    packing: []pack.Row,
    fixed_packed: []pack.Row,
    routed: []route.Row,
    fixed_routed: []route.Row,
    columns: ?Columns = null,
    pub fn deinitColumns(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        self.columns = null;
    }
    pub fn appendPacking(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.packing.len != 0 or self.fixed_packed.len != 0) return error.InvalidProjectionLink;
            try columns.appendTo(11, b);
        } else try b.append(11, self.packing, self.fixed_packed);
    }
    pub fn appendRoutes(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.routed.len != 0 or self.fixed_routed.len != 0) return error.InvalidProjectionLink;
            try columns.appendTo(7, b);
        } else try b.append(7, self.routed, self.fixed_routed);
    }
};
/// All returned storage belongs to a; caller uses an arena for partial failures.
pub fn build(a: std.mem.Allocator, lifting: u32, logs: []const u32, raw: []const usize, links: []const queries.Query) !Prepared {
    return buildMode(false, a, a, lifting, logs, raw, links);
}
/// Metadata belongs to output; direct columns own separate backing allocations.
pub fn buildColumns(output: std.mem.Allocator, backing: std.mem.Allocator, lifting: u32, logs: []const u32, raw: []const usize, links: []const queries.Query) !Prepared {
    return buildMode(true, output, backing, lifting, logs, raw, links);
}
fn buildMode(comptime direct: bool, a: std.mem.Allocator, backing: std.mem.Allocator, lifting: u32, logs: []const u32, raw: []const usize, links: []const queries.Query) !Prepared {
    if (lifting == 0 or lifting > 31 or raw.len != links.len) return error.InvalidProjectionLink;
    var counts: [32]u32 = @splat(0);
    for (logs) |log| {
        if (log == 0 or log > lifting) return error.InvalidProjectionLink;
        counts[log] = try std.math.add(u32, counts[log], 1);
        if (counts[log] >= core.fields.m31.Modulus) return error.InvalidProjectionLink;
    }
    var count_rows: usize = 0;
    for (counts, 0..) |count, log| if (count != 0) {
        count_rows = try std.math.add(usize, count_rows, try std.math.mul(usize, raw.len, (log + 3) / 4));
    };
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(backing, .{ count_rows, count_rows });
    const bit_reads = try a.alloc([31]u32, raw.len);
    @memset(bit_reads, @splat(0));
    var ports: [32]?[]route.Endpoint = @splat(null);
    var packing: std.ArrayList(pack.Row) = .empty;
    var fixed_packed: std.ArrayList(pack.Row) = .empty;
    var routed: std.ArrayList(route.Row) = .empty;
    var fixed_routed: std.ArrayList(route.Row) = .empty;
    var wire: u32 = 0;
    for (counts, 0..) |count, log| {
        if (count == 0) continue;
        const outputs = try a.alloc(route.Endpoint, raw.len);
        ports[log] = outputs;
        for (raw, links, outputs, 0..) |position, query, *output, q| {
            if (position >= @as(u64, 1) << @intCast(lifting)) return error.InvalidProjectionLink;
            var previous: ?route.Endpoint = null;
            var accumulated: [4]M = @splat(M.zero());
            var start: usize = 0;
            while (start < log) : (start += 4) {
                if (wire >= core.fields.m31.Modulus) return error.InvalidProjectionLink;
                var nodes: [4]u32 = undefined;
                var bits: [4]M = undefined;
                var affine = route.AffineSchedule{ .sources = .{ previous, .{ .circuit = packed_circuit, .wire = wire } }, .destination = .{ .circuit = index_circuit, .wire = wire }, .uses = if (start + 4 >= log) count else 1 };
                if (previous != null) for (0..4) |i| {
                    affine.coefficients[i][i] = M.one();
                };
                for (0..4) |j| {
                    const bit = start + j;
                    const source = if (bit == 0 or bit >= log) 0 else lifting - log + bit;
                    nodes[j] = query.bits[source].deep;
                    bits[j] = M.fromCanonical(@intCast((position >> @intCast(source)) & 1));
                    bit_reads[q][source] = try std.math.add(u32, bit_reads[q][source], 1);
                    if (bit < log) affine.coefficients[bit / 8][4 + j] = M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(bit % 8)));
                }
                const ps = pack.Schedule{ .source_circuit = 1502, .source_nodes = nodes, .destination_circuit = packed_circuit, .destination_wire = wire };
                const packing_row = try pack.logicalRow(ps, Q.fromM31Array(bits));
                const packing_fixed = try pack.fixedRow(ps);
                if (direct) try columns.?.appendFixed(11, packing_row, packing_fixed) else {
                    try packing.append(a, packing_row);
                    try fixed_packed.append(a, packing_fixed);
                }
                const row = try route.logicalAffine(affine, .{ accumulated, bits });
                const fixed_row = try route.fixedAffine(affine);
                if (direct) try columns.?.appendFixed(7, row, fixed_row) else {
                    try routed.append(a, row);
                    try fixed_routed.append(a, fixed_row);
                }
                accumulated = row[8..12].*;
                previous = affine.destination;
                wire += 1;
            }
            output.* = previous.?;
            var actual: u32 = 0;
            for (accumulated, 0..) |byte, i| {
                if (byte.v > 255) return error.InvalidProjectionLink;
                actual |= byte.v << @as(u5, @intCast(8 * i));
            }
            const expected = ((position >> @intCast(lifting - log + 1)) << 1) | (position & 1);
            if (actual != expected) return error.InvalidProjectionLink;
        }
    }
    if (columns) |*owned| try owned.finish();
    // Do not publish an optional owner in an aggregate with later fallible
    // fields. Output metadata uses the caller arena on partial failure.
    const packing_rows = try packing.toOwnedSlice(a);
    const packing_tail = try fixed_packed.toOwnedSlice(a);
    const route_rows = try routed.toOwnedSlice(a);
    const route_tail = try fixed_routed.toOwnedSlice(a);
    return .{ .columns = columns, .bit_reads = bit_reads, .ports = ports, .packing = packing_rows, .fixed_packed = packing_tail, .routed = route_rows, .fixed_routed = route_tail };
}
