const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.memory.load_store_v1;
const R = front.rv64_air.memory.closed_ram;
const E = front.rv64_air.evaluation;
const P = @import("../rv64_load_store_public.zig");
const Data = @import("../rv64_load_store_data.zig");
const F = @import("../rv64_load_store_fixture.zig");
const Q = E.Q;
pub fn challenges() X.types.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var result: X.types.Challenges = undefined;
    result.ram.offset = channel.drawSecureFelt();
    for (&result.ram.coefficients) |*v| v.* = channel.drawSecureFelt();
    result.owner.offset = channel.drawSecureFelt();
    for (&result.owner.coefficients) |*v| v.* = channel.drawSecureFelt();
    result.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    result.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    result.selection.offset = channel.drawSecureFelt();
    for (&result.selection.coefficients) |*v| v.* = channel.drawSecureFelt();
    return result;
}
pub fn audit(trace: *const X.trace.Trace, claim: X.types.Claims, ch: X.types.Challenges) !void {
    const widths = X.layout.widths(trace.kind);
    for (0..trace.size()) |row| {
        const pos = R.trace.physical(row, trace.log_size);
        const prior = R.trace.physical((row + trace.size() - 1) % trace.size(), trace.log_size);
        var f: [66]Q = undefined;
        var m: [79]Q = undefined;
        var pm: [79]Q = undefined;
        var i: [116]Q = undefined;
        var pi: [116]Q = undefined;
        for (0..widths[0]) |c| f[c] = Q.fromBase(trace.fixed[c * trace.size() + pos]);
        for (0..widths[1]) |c| {
            m[c] = Q.fromBase(trace.main[c * trace.size() + pos]);
            pm[c] = Q.fromBase(trace.main[c * trace.size() + prior]);
        }
        for (0..widths[2]) |c| {
            i[c] = Q.fromBase(trace.interaction[c * trace.size() + pos]);
            pi[c] = Q.fromBase(trace.interaction[c * trace.size() + prior]);
        }
        var values: [280]Q = undefined;
        var sink = E.Sink{ .values = &values };
        X.authority.emitFor(Q, trace.kind, f[0..widths[0]], m[0..widths[1]], pm[0..widths[1]], i[0..widths[2]], pi[0..widths[2]], trace.rows, if (trace.public_rows) |*p| p else null, claim, ch, &sink);
        try std.testing.expectEqual(X.layout.constraints(trace.kind), sink.count);
        for (values[0..sink.count], 0..) |value, residual| if (!value.isZero()) {
            std.debug.print("LS {s} row{} residual{}\n", .{ @tagName(trace.kind), row, residual });
            return error.NonzeroLoadStoreResidual;
        };
    }
}
test "LS all legal widths offsets signed negatives wrap addresses and actual RAM ownership" {
    const data = Data.fixture();
    var fixture = try F.Fixture.init(std.testing.allocator, data.expected());
    defer fixture.deinit();
    const ch = challenges();
    const claims = try fixture.generate(ch);
    try audit(&fixture.ls[0], claims[0], ch);
    try audit(&fixture.ls[1], claims[1], ch);
    try audit(&fixture.owner, claims[4], ch);
    try audit(&fixture.selection, claims[7], ch);
    var sums: [5]Q = @splat(Q.zero());
    for (claims) |claim| for (claim.values(), &sums) |v, *sum| {
        sum.* = sum.add(v);
    };
    for (sums) |sum| try std.testing.expect(sum.isZero());
    try std.testing.expectEqual(@as(usize, 49), data.operations.len);
}

test "LS actual closed eight-component q70 proof binds CPU-style operands and RAM" {
    const C = @import("../rv64_load_store.zig");
    const data = Data.fixture();
    var encoded = try C.produce(std.testing.allocator, data.expected(), .none);
    defer encoded.deinit(std.testing.allocator);
    try C.verify(std.testing.allocator, data.expected(), encoded);
}
