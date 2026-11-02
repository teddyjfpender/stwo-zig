//! Debug arithmetic-provider rows, using their sole AIR authorities and actual
//! post-commit challenges. Original main snapshots are explicitly caller-owned.
const rv = @import("stwo_riscv_frontend").rv64_air;
const E = rv.evaluation;
const Q = E.Q;
const M = @import("stwo_core").fields.m31.M31;
const D = rv.arithmetic.division;
const U = rv.arithmetic.multiplication;
pub const Failure = struct { family: enum { division, multiplication }, row: usize, residual: usize, value: Q };
pub fn division(trace: *const D.trace.Trace, original: []const M, ch: D.provider.Challenges, claim: Q) !?Failure {
    const n = @as(usize, 1) << @intCast(trace.log_size);
    const L = D.layout;
    if (original.len != n * L.MAIN or trace.interaction.len != n * L.INTERACTION or trace.fixed.len != n * L.FIXED) return error.InvalidArithmeticDiagnosticShape;
    var main: L.Physical = undefined;
    var current: [L.INTERACTION]Q = undefined;
    var previous: [L.INTERACTION]Q = undefined;
    var fixed: [L.FIXED]Q = undefined;
    var residuals: [L.CONSTRAINTS]Q = undefined;
    for (0..n) |row| {
        const r = rv.witness.physical(row, trace.log_size);
        const prior = rv.witness.physical((row + n - 1) % n, trace.log_size);
        for (&main, 0..) |*v, col| v.* = Q.fromBase(original[col * n + r]);
        for (&fixed, 0..) |*v, col| v.* = Q.fromBase(trace.fixed[col * n + r]);
        for (&current, &previous, 0..) |*v, *p, col| {
            v.* = Q.fromBase(trace.interaction[col * n + r]);
            p.* = Q.fromBase(trace.interaction[col * n + prior]);
        }
        var sink = E.Sink{ .values = &residuals };
        D.provider.evaluate(fixed, &main, &current, &previous, Q.fromBase(original[L.COUNT * n + prior]), trace.count, ch, claim, &sink);
        if (sink.count != L.CONSTRAINTS) return error.InvalidArithmeticDiagnosticShape;
        for (residuals, 0..) |value, index| if (!value.isZero()) return .{ .family = .division, .row = row, .residual = index, .value = value };
    }
    return null;
}
pub fn multiplication(trace: *const U.trace.Trace, original: []const M, ch: U.provider.Challenges, byte_alpha: Q, claim: Q) !?Failure {
    const n = @as(usize, 1) << @intCast(trace.log_size);
    const L = U.layout;
    if (original.len != n * L.MAIN or trace.interaction.len != n * L.INTERACTION or trace.fixed.len != n * L.FIXED) return error.InvalidArithmeticDiagnosticShape;
    var main: U.provider.Values = undefined;
    var current: [L.INTERACTION]Q = undefined;
    var previous: [L.INTERACTION]Q = undefined;
    var fixed: [L.FIXED]Q = undefined;
    var residuals: [L.CONSTRAINTS]Q = undefined;
    const alpha = rv.range.cpu.PreparedAlpha.init(byte_alpha);
    for (0..n) |row| {
        const r = rv.witness.physical(row, trace.log_size);
        const prior = rv.witness.physical((row + n - 1) % n, trace.log_size);
        for (&main, 0..) |*v, col| v.* = Q.fromBase(original[col * n + r]);
        for (&fixed, 0..) |*v, col| v.* = Q.fromBase(trace.fixed[col * n + r]);
        for (&current, &previous, 0..) |*v, *p, col| {
            v.* = Q.fromBase(trace.interaction[col * n + r]);
            p.* = Q.fromBase(trace.interaction[col * n + prior]);
        }
        var sink = E.Sink{ .values = &residuals };
        U.provider.evaluate(fixed, &main, &current, &previous, Q.fromBase(original[L.COUNT * n + prior]), @intCast(trace.count), ch, &alpha, claim, &sink);
        if (sink.count != L.CONSTRAINTS) return error.InvalidArithmeticDiagnosticShape;
        for (residuals, 0..) |value, index| if (!value.isZero()) return .{ .family = .multiplication, .row = row, .residual = index, .value = value };
    }
    return null;
}
