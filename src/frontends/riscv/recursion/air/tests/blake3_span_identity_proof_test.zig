//! Real paired-identity proof over public canonical statement scalar sources.
//! This gate does not prove the production statement semantics or its ingress.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const pair = @import("../blake3_span_identity_pair.zig");
const graph = @import("../../statement_semantics_circuit_blake3.zig");
const identity = @import("../../span_identity_blake3.zig");
const pack = @import("../qm31_pack_wire.zig");
const encoding = @import("../blake3_field_bytes.zig");
const route = @import("../blake3_byte_route.zig");
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ pack, encoding, route });
const Data = struct {
    gs: []f.g.Row,
    xs: []f.xor.Row,
    bs: []f.boundary.Row,
    packing: []pack.Row,
    encoded: []encoding.Row,
    routed: []route.Row,
    fn logs(self: Data) [6]u32 {
        return .{ log(self.gs.len), log(self.xs.len), log(self.bs.len), log(self.packing.len), log(self.encoded.len), log(self.routed.len) };
    }
    fn log(n: usize) u32 {
        return @max(1, std.math.log2_int_ceil(usize, n));
    }
};
test "BLAKE3 paired Span identities prove and reject a substituted job claim" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fixture = @import("../../span_statement_blake3_test_fixture.zig");
    const context = try fixture.job(1);
    const words = try (try fixture.leaf(context, 0, context.complete.initial_state, context.complete.final_state)).canonicalWords();
    var circuit = try graph.build(a);
    defer circuit.deinit();
    var plan = try pair.buildParent(a, &circuit, .{ .scalar = 21, .packing = 22, .bytes = 23, .hash = 24 }, 25);
    defer plan.deinit();
    const claims = pair.Claims{ .statement = try identity.hash(&words, .statement), .job = try identity.hash(&words, .job) };
    const live = try assemble(a, &plan, &words, claims, true);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.gs, logs[0]), try f.padded(f.xor, a, live.xs, logs[1]), try f.padded(f.boundary, a, live.bs, logs[2]), try f.padded(pack, a, live.packing, logs[3]), try f.padded(encoding, a, live.encoded, logs[4]), try f.padded(route, a, live.routed, logs[5]) };
    const trusted = try preprocessing(a, try assemble(a, &plan, &words, claims, false));
    var wrong = claims;
    wrong.job.bytes[31] ^= 0x80;
    const false_pp = try preprocessing(a, try assemble(a, &plan, &words, wrong, false));
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, data: Data) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    const logs = data.logs();
    inline for (F.Airs, .{ data.gs, data.xs, data.bs, data.packing, data.encoded, data.routed }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn assemble(a: std.mem.Allocator, plan: *const pair.Plan, words: *const identity.StatementWords, claims: pair.Claims, live: bool) !Data {
    var prepared = if (live) try plan.prepare(a, words, claims) else try plan.trusted(a, claims);
    defer prepared.deinit();
    var scalars: [525]f.boundary.Row = undefined;
    for (&scalars, words, plan.statement.inputs.source_uses, 0..) |*row, word, uses, i| {
        const node = plan.statement.inputs.packing[i / 4].source_nodes[i % 4];
        row.* = try f.boundary.logicalCoordinates(21, node, f.M31.fromCanonical(uses), .{ word, f.M31.zero(), f.M31.zero(), f.M31.zero() });
    }
    const statement = &prepared.statement.hash;
    return .{
        .gs = try std.mem.concat(a, f.g.Row, &.{ statement.hash_rows.g_rows, prepared.job.hash_rows.g_rows }),
        .xs = try std.mem.concat(a, f.xor.Row, &.{ statement.hash_rows.xor_rows, prepared.job.hash_rows.xor_rows }),
        .bs = try std.mem.concat(a, f.boundary.Row, &.{ statement.hash_rows.boundary_rows, prepared.job.hash_rows.boundary_rows, &scalars }),
        .packing = try a.dupe(pack.Row, &prepared.statement.inputs.packing),
        .encoded = try a.dupe(encoding.Row, &prepared.statement.inputs.encoding),
        .routed = try std.mem.concat(a, route.Row, &.{ statement.route_rows, prepared.job.route_rows }),
    };
}
