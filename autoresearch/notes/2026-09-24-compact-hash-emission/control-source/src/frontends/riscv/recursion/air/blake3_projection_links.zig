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
pub const Prepared = struct {
    bit_reads: [][31]u32,
    ports: [32]?[]route.Endpoint,
    packing: []pack.Row,
    fixed_packed: []pack.Row,
    routed: []route.Row,
    fixed_routed: []route.Row,
};
/// All returned storage belongs to a; caller uses an arena for partial failures.
pub fn build(a: std.mem.Allocator, lifting: u32, logs: []const u32, raw: []const usize, links: []const queries.Query) !Prepared {
    if (lifting == 0 or lifting > 31 or raw.len != links.len) return error.InvalidProjectionLink;
    var counts: [32]u32 = @splat(0);
    for (logs) |log| {
        if (log == 0 or log > lifting) return error.InvalidProjectionLink;
        counts[log] = try std.math.add(u32, counts[log], 1);
        if (counts[log] >= core.fields.m31.Modulus) return error.InvalidProjectionLink;
    }
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
                try packing.append(a, try pack.logicalRow(ps, Q.fromM31Array(bits)));
                try fixed_packed.append(a, try pack.fixedRow(ps));
                const row = try route.logicalAffine(affine, .{ accumulated, bits });
                try routed.append(a, row);
                try fixed_routed.append(a, try route.fixedAffine(affine));
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
    return .{ .bit_reads = bit_reads, .ports = ports, .packing = try packing.toOwnedSlice(a), .fixed_packed = try fixed_packed.toOwnedSlice(a), .routed = try routed.toOwnedSlice(a), .fixed_routed = try fixed_routed.toOwnedSlice(a) };
}
