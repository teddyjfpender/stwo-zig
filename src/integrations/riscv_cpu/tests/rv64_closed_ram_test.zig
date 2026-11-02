const std = @import("std");
const core = @import("stwo_core");
const R = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram;
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const F = @import("../rv64_closed_ram_fixture.zig");
const P = @import("../rv64_closed_ram_public.zig");
const Q = core.fields.qm31.QM31;
pub fn challenges() R.types.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: R.types.Challenges = undefined;
    ch.ram.offset = channel.drawSecureFelt();
    for (&ch.ram.coefficients) |*c| c.* = channel.drawSecureFelt();
    ch.owner.offset = channel.drawSecureFelt();
    for (&ch.owner.coefficients) |*c| c.* = channel.drawSecureFelt();
    ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    ch.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    return ch;
}
pub fn audit(trace: *const R.trace.Trace, claim: R.types.Claims, ch: R.types.Challenges) !void {
    const widths = R.layout.widths(trace.kind);
    for (0..trace.size()) |row| {
        const pos = R.trace.physical(row, trace.log_size);
        const prior = R.trace.physical((row + trace.size() - 1) % trace.size(), trace.log_size);
        var fixed: [34]Q = undefined;
        var main: [28]Q = undefined;
        var pm: [28]Q = undefined;
        var inter: [68]Q = undefined;
        var pi: [68]Q = undefined;
        for (0..widths[0]) |c| fixed[c] = Q.fromBase(trace.fixed[c * trace.size() + pos]);
        for (0..widths[1]) |c| {
            main[c] = Q.fromBase(trace.main[c * trace.size() + pos]);
            pm[c] = Q.fromBase(trace.main[c * trace.size() + prior]);
        }
        for (0..widths[2]) |c| {
            inter[c] = Q.fromBase(trace.interaction[c * trace.size() + pos]);
            pi[c] = Q.fromBase(trace.interaction[c * trace.size() + prior]);
        }
        var values: [72]Q = undefined;
        var sink = E.Sink{ .values = &values };
        R.equations.emitFor(Q, trace.kind, fixed[0..widths[0]], main[0..widths[1]], pm[0..widths[1]], inter[0..widths[2]], pi[0..widths[2]], trace.rows, if (trace.public_rows) |*p| p else null, claim, ch, &sink);
        try std.testing.expectEqual(R.layout.constraints(trace.kind), sink.count);
        for (values[0..sink.count], 0..) |value, ordinal| if (!value.isZero()) {
            std.debug.print("RAM kind={s} row={} residual={}\n", .{ @tagName(trace.kind), row, ordinal });
            return error.NonzeroClosedRamResidual;
        };
    }
}
test "closed RAM native rows close four physical relations across unequal heights" {
    var fixture = try F.Fixture.init(std.testing.allocator, P.fixture());
    defer fixture.deinit();
    const ch = challenges();
    const claims = try fixture.generate(ch);
    var sums: [4]Q = @splat(Q.zero());
    for (&fixture.traces, claims) |*trace, claim| {
        try audit(trace, claim, ch);
        for (claim.values(), &sums) |value, *sum| sum.* = sum.add(value);
    }
    for (sums) |sum| try std.testing.expect(sum.isZero());
}

test "closed RAM q70 P26 proof binds independent image operations and terminal" {
    const C = @import("../rv64_closed_ram.zig");
    var encoded = try C.produce(std.testing.allocator, P.fixture(), .none);
    defer encoded.deinit(std.testing.allocator);
    try C.verify(std.testing.allocator, P.fixture(), encoded);
}
