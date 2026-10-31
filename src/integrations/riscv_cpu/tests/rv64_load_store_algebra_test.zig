const std = @import("std");
const core = @import("stwo_core");
const air = @import("stwo_riscv_frontend").rv64_air;
const E = air.evaluation;
const R = air.memory.load_store_v1;
const L = R.layout;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const C = @import("../rv64_load_store.zig");
const KINDS = [_]L.Kind{ .ls, .owner, .selection };
fn publicRows() R.types.OwnerRows {
    var rows: R.types.OwnerRows = undefined;
    for (&rows, 0..) |*row, i| for (row, 0..) |*v, c| {
        v.* = M.fromCanonical(@intCast(1 + 17 * i + c));
    };
    return rows;
}
test "closed LS every residual is cubic over arbitrary QM31 coordinates" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = C.draw(&channel);
    const pubrows = publicRows();
    const claims = R.types.Claims{ .ram = channel.drawSecureFelt(), .owner = channel.drawSecureFelt(), .range16 = channel.drawSecureFelt(), .range8 = channel.drawSecureFelt(), .selection = channel.drawSecureFelt() };
    for (KINDS) |kind| {
        const widths = L.widths(kind);
        var constant: [5][116]Q = undefined;
        var slope: [5][116]Q = undefined;
        for (&constant, &slope) |*a, *b| for (a, b) |*x, *y| {
            x.* = channel.drawSecureFelt();
            y.* = channel.drawSecureFelt();
        };
        var residuals: [5][280]Q = undefined;
        for (0..5) |x| {
            var data: [5][116]Q = undefined;
            for (&data, constant, slope) |*row, a, b| for (row, a, b) |*v, c, s| {
                v.* = c.add(s.mulM31(M.fromCanonical(@intCast(x))));
            };
            var sink = E.Sink{ .values = &residuals[x] };
            R.authority.emitFor(Q, kind, data[0][0..widths[0]], data[1][0..widths[1]], data[2][0..widths[1]], data[3][0..widths[2]], data[4][0..widths[2]], 4, &pubrows, claims, ch, &sink);
            try std.testing.expectEqual(L.constraints(kind), sink.count);
        }
        var has_cubic = false;
        for (0..L.constraints(kind)) |r| {
            const fourth = residuals[0][r].sub(residuals[1][r].mulM31(M.fromCanonical(4))).add(residuals[2][r].mulM31(M.fromCanonical(6))).sub(residuals[3][r].mulM31(M.fromCanonical(4))).add(residuals[4][r]);
            try std.testing.expect(fourth.isZero());
            const third = residuals[3][r].sub(residuals[2][r].mulM31(M.fromCanonical(3))).add(residuals[1][r].mulM31(M.fromCanonical(3))).sub(residuals[0][r]);
            has_cubic = has_cubic or !third.isZero();
        }
        if (kind == .ls or kind == .selection) try std.testing.expect(has_cubic);
    }
}
test "closed LS packed base lanes equal QM31 authority including secure lookups" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = C.draw(&channel);
    const pubrows = publicRows();
    const claims = R.types.Claims{ .ram = channel.drawSecureFelt(), .owner = channel.drawSecureFelt(), .range16 = channel.drawSecureFelt(), .range8 = channel.drawSecureFelt(), .selection = channel.drawSecureFelt() };
    const Base = E.PackedBase;
    for (KINDS) |kind| {
        const widths = L.widths(kind);
        var scalar: [5][116][16]M = undefined;
        var simd: [5][116]Base = undefined;
        for (&scalar, &simd) |*a, *b| for (a, b) |*lanes, *v| {
            for (lanes) |*lane| lane.* = channel.drawSecureFelt().toM31Array()[0];
            v.* = Base.fromLanes(lanes.*);
        };
        var packed_results: [280]E.PackedSecure = undefined;
        var packed_sink = E.SinkFor(Base){ .values = &packed_results };
        R.authority.emitFor(Base, kind, simd[0][0..widths[0]], simd[1][0..widths[1]], simd[2][0..widths[1]], simd[3][0..widths[2]], simd[4][0..widths[2]], 4, &pubrows, claims, ch, &packed_sink);
        try std.testing.expectEqual(L.constraints(kind), packed_sink.count);
        for (0..16) |lane| {
            var data: [5][116]Q = undefined;
            for (&data, scalar) |*a, b| for (a, b) |*v, lanes| {
                v.* = Q.fromBase(lanes[lane]);
            };
            var residuals: [280]Q = undefined;
            var sink = E.Sink{ .values = &residuals };
            R.authority.emitFor(Q, kind, data[0][0..widths[0]], data[1][0..widths[1]], data[2][0..widths[1]], data[3][0..widths[2]], data[4][0..widths[2]], 4, &pubrows, claims, ch, &sink);
            for (residuals[0..sink.count], packed_results[0..sink.count]) |expected, actual| try std.testing.expect(expected.eql(actual.lane(lane)));
        }
    }
}
