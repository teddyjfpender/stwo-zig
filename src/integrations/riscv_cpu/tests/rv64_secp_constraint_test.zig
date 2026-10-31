const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = rv.crypto.secp256k1;
const L = S.layout;
const P = S.program;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const F = @import("../delegations/secp256k1/fixture.zig");
const physical = rv.witness.physical;
const Snapshot = struct {
    fixed: [L.FIXED]Q,
    main: [319]Q,
    current: [96]Q,
    previous_active: Q,
    previous_id: Q,
    previous_final: Q,
    fn load(trace: *const S.trace.Trace, logical: usize) Snapshot {
        const n = trace.size();
        const r = physical(logical, trace.log_size);
        const prior = physical((logical + n - 1) % n, trace.log_size);
        var out: Snapshot = undefined;
        for (&out.fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
        for (out.main[0..L.main(trace.kind)], 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + r]);
        for (out.current[0..L.batches(trace.kind)], 0..) |*v, b| v.* = secure(trace.interaction, n, r, 4 * b);
        out.previous_active = Q.fromBase(trace.main[prior]);
        out.previous_id = Q.fromBase(trace.main[L.base(trace.kind) * n + prior]);
        out.previous_final = secure(trace.interaction, n, prior, L.interaction(trace.kind) - 4);
        return out;
    }
    fn evaluate(self: *const Snapshot, kind: L.Kind, program: *const P.Program, public: S.equations.Public, ch: S.equations.Challenges, claim: Q, out: *[522]Q) void {
        var sink = rv.evaluation.Sink{ .values = out };
        S.equations.emit(kind, program, .{ .fixed = &self.fixed, .main = self.main[0..L.main(kind)], .previous_active = self.previous_active, .previous_id = self.previous_id }, self.current[0..L.batches(kind)], self.previous_final, claim, ch, public, &sink);
        std.debug.assert(sink.count == L.constraints(kind));
    }
};
fn secure(data: []const M, n: usize, r: usize, c: usize) Q {
    return Q.fromM31(data[c * n + r], data[(c + 1) * n + r], data[(c + 2) * n + r], data[(c + 3) * n + r]);
}
fn dense(i: usize) Q {
    return Q.fromU32Unchecked(@intCast(17 * i + 3), @intCast(19 * i + 5), @intCast(23 * i + 7), @intCast(29 * i + 11));
}
fn challenges() S.equations.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x53434f4e, 37 });
    return S.equations.Challenges.draw(&channel);
}
test "projective all arbitrary QM31 residuals have degree at most four" {
    const ch = challenges();
    for ([_]L.Kind{ .product, .linear }) |kind| {
        var differences: [6][522]Q = undefined;
        for (0..6) |sample| {
            const x = Q.fromBase(M.fromCanonical(@intCast(sample)));
            var row: Snapshot = undefined;
            for (&row.fixed, 0..) |*v, i| v.* = dense(i + 1).add(x.mul(dense(i + 503)));
            for (&row.main, 0..) |*v, i| v.* = dense(i + 1001).add(x.mul(dense(i + 2003)));
            for (&row.current, 0..) |*v, i| v.* = dense(i + 4001).add(x.mul(dense(i + 6007)));
            row.previous_active = dense(8001).add(x.mul(dense(8003)));
            row.previous_id = dense(8011).add(x.mul(dense(8017)));
            row.previous_final = dense(9001).add(x.mul(dense(9007)));
            row.evaluate(kind, &P.add, .{ .calls = 3, .first_id = 7 }, ch, dense(10001), &differences[sample]);
        }
        for (0..5) |order| for (0..5 - order) |sample| for (0..L.constraints(kind)) |i| {
            differences[sample][i] = differences[sample + 1][i].sub(differences[sample][i]);
        };
        for (differences[0][0..L.constraints(kind)]) |v| try std.testing.expect(v.isZero());
    }
}
test "projective public count, IDs, incomplete tail and claim are AIR authority" {
    const a = std.testing.allocator;
    const in = try F.fixtureInputs(a, 3);
    defer a.free(in);
    var trace = try S.trace.Trace.init(a, .product, &P.add, in, 11);
    defer trace.deinit();
    const ch = challenges();
    const claim = try trace.generateInteraction(ch);
    var residuals: [522]Q = undefined;
    const terminal = 3 * P.add.rows(true);
    var row = Snapshot.load(&trace, terminal);
    row.evaluate(.product, &P.add, .{ .calls = 2, .first_id = 11 }, ch, claim, &residuals);
    try std.testing.expect(!residuals[L.mul.constraint_count + 5].isZero());
    row = Snapshot.load(&trace, 1);
    row.main[L.base(.product)] = row.main[L.base(.product)].add(Q.one());
    row.evaluate(.product, &P.add, .{ .calls = 3, .first_id = 11 }, ch, claim, &residuals);
    try std.testing.expect(!residuals[L.mul.constraint_count + 3].isZero());
    row = Snapshot.load(&trace, 0);
    row.evaluate(.product, &P.add, .{ .calls = 3, .first_id = 11 }, ch, claim.add(Q.one()), &residuals);
    try std.testing.expect(!residuals[L.direct(.product)].isZero());
    const partial = trace.size() / P.add.rows(true) * P.add.rows(true);
    row = Snapshot.load(&trace, @min(partial, trace.size() - 1));
    row.fixed[L.COMPLETE] = Q.zero();
    row.main[0] = Q.one();
    row.evaluate(.product, &P.add, .{ .calls = 3, .first_id = 11 }, ch, claim, &residuals);
    try std.testing.expect(!residuals[L.mul.constraint_count].isZero());
}
test "projective locally valid alternate arithmetic cannot forge the typed wire closure" {
    const a = std.testing.allocator;
    const in = try F.fixtureInputs(a, 1);
    defer a.free(in);
    var batch = try S.batch.Batch.init(a, &P.add, in, 1);
    defer batch.deinit();
    const product = &batch.product;
    const n = product.size();
    const r = physical(0, product.log_size);
    const original = try P.execute(&P.add, in[0].coordinates[0..6]);
    const op = P.add.operation(true, 0);
    const wrong = try P.field.create(P.bytes(123), P.bytes(P.resolve(op.rhs, &original)), P.field.base_modulus);
    const altered = L.mul.rowFromWitness(&wrong);
    for (altered, 0..) |v, c| product.main[c * n + r] = v;
    S.trace.captureLookupBytes(.product, product.lookup_bytes[0..L.byteCount(.product)], &altered);
    product.byte_counts = @splat(0);
    for (0..n) |row| for (0..L.byteCount(.product)) |i| {
        product.byte_counts[product.main[S.trace.byteColumn(.product, i) * n + row].v] += 1;
    };
    var counts: [256]u64 = undefined;
    for (&counts, product.byte_counts, batch.linear.byte_counts) |*v, x, y| v.* = x + y;
    var bytes = try rv.range.provider.Trace.init(a, &counts);
    defer bytes.deinit();
    const ch = challenges();
    const pc = try product.generateInteraction(ch);
    const lc = try batch.linear.generateInteraction(ch);
    const bc = try bytes.generateInteraction(ch.bytes);
    var snapshot = Snapshot.load(product, 0);
    var residuals: [522]Q = undefined;
    snapshot.evaluate(.product, &P.add, .{ .calls = 1 }, ch, pc, &residuals);
    for (residuals[0..L.constraints(.product)]) |v| try std.testing.expect(v.isZero());
    try std.testing.expect(!pc.add(lc).add(bc).eql(try F.expectedWireClaim(&P.add, in, 1, ch.wire)));
}
fn allocationRun(a: std.mem.Allocator) !void {
    const input = S.trace.Input{ .coordinates = .{ 1, 2, 3, 4, 5, 6 } };
    var batch = try S.batch.Batch.init(a, &P.add, &.{input}, 1);
    defer batch.deinit();
}
test "projective construction cleans every allocation and failed inverse publishes nothing" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRun, .{});
    const in = try F.fixtureInputs(std.testing.allocator, 1);
    defer std.testing.allocator.free(in);
    var trace = try S.trace.Trace.init(std.testing.allocator, .product, &P.add, in, 1);
    defer trace.deinit();
    var ch = challenges();
    ch.bytes = Q.zero();
    try std.testing.expectError(error.DivisionByZero, trace.generateInteraction(ch));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
}
test "projective combined characteristic admission includes every padded BYTE request" {
    const item = L.RosterItem{ .kind = .product, .program = &P.add, .calls = 0, .first_id = 1, .log = 22 };
    _ = try L.admitRoster(&.{item}, &.{});
    try std.testing.expectError(error.SecpLookupMassExceeded, L.admitRoster(&.{ item, item }, &.{}));
    try std.testing.expectError(error.SecpLookupMassExceeded, L.admitRoster(&.{}, &.{core.fields.m31.Modulus}));
}
