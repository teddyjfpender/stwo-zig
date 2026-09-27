//! Private identity preimages routed into the full BLAKE3 hash witness.
const std = @import("std");
const identity = @import("../span_identity_blake3.zig");
const graph = @import("blake3_hash_plan.zig");
const hash = @import("blake3_hash_witness.zig");
const routing = @import("blake3_span_identity_route.zig");
const route = @import("blake3_byte_route.zig");
const boundary = @import("blake3_boundary.zig");
pub const Prepared = struct {
    hash_rows: hash.Rows,
    route_rows: []route.Row,
    digest: ?[32]u8,
    pub fn deinit(self: *Prepared) void {
        self.hash_rows.allocator.free(self.route_rows);
        self.hash_rows.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, purpose: identity.Purpose, caller: routing.Caller, circuit: u32, words: *const identity.StatementWords, claim: identity.Digest) !Prepared {
    return build(a, purpose, caller, circuit, words, claim);
}
/// Message-free verifier metadata; only the claimed full digest is public here.
pub fn trusted(a: std.mem.Allocator, purpose: identity.Purpose, caller: routing.Caller, circuit: u32, claim: identity.Digest) !Prepared {
    return build(a, purpose, caller, circuit, null, claim);
}
fn build(a: std.mem.Allocator, purpose: identity.Purpose, caller: routing.Caller, circuit: u32, words: ?*const identity.StatementWords, claim: identity.Digest) !Prepared {
    var plan = try routing.build(a, purpose, caller, circuit);
    defer plan.deinit();
    var shape = try graph.build(a, identity.byteCount(purpose));
    defer shape.deinit();
    var digest: ?[32]u8 = null;
    var rows = if (words) |values| blk: {
        var storage: [identity.MAX_BYTE_COUNT]u8 = undefined;
        const bytes = try identity.encode(values, purpose, &storage);
        const prepared = try hash.prepare(a, circuit, bytes, claim.bytes);
        digest = prepared.digest;
        break :blk prepared.rows;
    } else try hash.trustedShapeRows(a, circuit, identity.byteCount(purpose), claim.bytes);
    errdefer rows.deinit();
    const retained = try a.alloc(boundary.Row, rows.boundary_rows.len - plan.schedules.len);
    var at: usize = 0;
    for (shape.sources, rows.boundary_rows[0..shape.sources.len]) |source, row| if (source.value == .constant) {
        retained[at] = row;
        at += 1;
    };
    @memcpy(retained[at..], rows.boundary_rows[shape.sources.len..]);
    a.free(rows.boundary_rows);
    rows.boundary_rows = retained;
    const routed = try a.alloc(route.Row, plan.schedules.len);
    errdefer a.free(routed);
    for (routed, plan.schedules) |*row, schedule| {
        if (words) |values| {
            var source: [2]u32 = @splat(0);
            if (schedule.sources[0]) |endpoint| source[0] = values[endpoint.wire - caller.first_wire].toU32();
            row.* = try route.logicalRow(schedule, source);
        } else row.* = try route.fixedRow(schedule);
    }
    return .{ .hash_rows = rows, .route_rows = routed, .digest = digest };
}
