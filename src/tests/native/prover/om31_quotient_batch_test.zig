//! Bounded cross-row inverse profile using the actual core quadratic authority.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const Q = core.pcs.ForField(O).quotients;
const Inner = O.InnerField;
const a = std.testing.allocator;
test "OM31 actual quotient denominator row versus batch-major inversion profile" {
    const bench = std.process.hasEnvVarConstant("STWO_ZIG_BENCH_WIDE_QUOTIENT");
    const log: u32 = if (bench) 16 else 9;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    var batches: [8]Q.ColumnSampleBatch = undefined;
    for (&batches) |*b| b.* = .{ .point = try core.circle.randomSecureFieldPointFor(O, &channel), .cols_vals_randpows = &.{} };
    var workspace = try Q.RowQuotientWorkspace.init(a, &batches);
    defer workspace.deinit(a);
    const points = try a.alloc(core.circle.CirclePointM31, 1024);
    defer a.free(points);
    const d = try a.alloc(Inner, 8 * 1024);
    defer a.free(d);
    const inv = try a.alloc(Inner, 8 * 1024);
    defer a.free(inv);
    var timer = try std.time.Timer.start();
    var scalar = Inner.zero();
    for (0..domain.size()) |row| {
        try workspace.beginRow(domain.at(core.utils.bitReverseIndex(row, log)));
        for (workspace.denominator_inverses) |x| scalar = scalar.add(x);
    }
    const scalar_ns = timer.lap();
    var batched = Inner.zero();
    var first: usize = 0;
    while (first < domain.size()) : (first += 1024) {
        const n: usize = @min(@as(usize, 1024), domain.size() - first);
        for (points[0..n], 0..) |*p, r| p.* = domain.at(core.utils.bitReverseIndex(first + r, log));
        try workspace.prepareDenominatorInversesForRowsBatchMajor(points[0..n], d[0 .. 8 * n], inv[0 .. 8 * n]);
        for (inv[0 .. 8 * n]) |x| batched = batched.add(x);
    }
    const batched_ns = timer.read();
    if (!scalar.eql(batched)) std.debug.print("INVERSE_MISMATCH scalar={any} batch={any}\n", .{ scalar.toM31Array(), batched.toM31Array() });
    try std.testing.expect(scalar.eql(batched));
    if (bench) std.debug.print("OM31_QUOTIENT_INVERSE rows={d} batches=8 scalar_ns={d} batched_ns={d} scratch_bytes={d}\n", .{ domain.size(), scalar_ns, batched_ns, 1024 * (@sizeOf(core.circle.CirclePointM31) + 16 * @sizeOf(Inner)) });
}
