const std = @import("std");
const air = @import("terminal_air.zig");
const Cell = @import("cell_air.zig");
const E = @import("../evaluation.zig");
const Q = E.Q;
fn sample(n: u32) Q {
    return Q.fromU32Unchecked(n + 1, n + 3, n + 7, n + 11);
}
test "RV64 terminal certificate: final private upper five bytes are masked over the full extension field" {
    const spec = air.Spec{ .geometry = .chunk512, .halt_flag = 0xc00000, .output = @splat(29) };
    var main: air.SecureRow = @splat(Q.zero());
    main[Cell.BASE + 2] = E.q(192);
    var selectors: [7]Q = @splat(Q.zero());
    selectors[6] = Q.one();
    for (0..8) |i| main[Cell.AFTER + i] = if (i < 3) E.q(29) else sample(@intCast(i + 17));
    var residuals: [17]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    air.evaluateBinding(spec, &selectors, &main, &sink);
    try std.testing.expectEqual(@as(usize, 17), sink.count);
    for (residuals) |value| try std.testing.expect(value.isZero());
    main[Cell.AFTER + 2] = main[Cell.AFTER + 2].add(Q.one());
    sink = .{ .values = &residuals };
    air.evaluateBinding(spec, &selectors, &main, &sink);
    try std.testing.expect(!residuals[11].isZero());
}
test "RV64 terminal certificate: public byte binding is quadratic at arbitrary QM31 coordinates" {
    const spec = air.Spec{ .geometry = .page4096, .halt_flag = 0xc00000, .output = @splat(37) };
    var evaluations: [4][17]Q = undefined;
    for (0..4) |step| {
        const t = E.q(@intCast(step));
        var main: air.SecureRow = undefined;
        var selectors: [7]Q = undefined;
        for (&main, 0..) |*field, i| field.* = sample(@intCast(101 + i)).add(t.mul(sample(@intCast(211 + i))));
        for (&selectors, 0..) |*field, i| field.* = sample(@intCast(307 + i)).add(t.mul(sample(@intCast(419 + i))));
        var sink = E.Sink{ .values = &evaluations[step] };
        air.evaluateBinding(spec, &selectors, &main, &sink);
    }
    for (0..3) |level| for (0..3 - level) |row| for (0..17) |column| {
        evaluations[row][column] = evaluations[row + 1][column].sub(evaluations[row][column]);
    };
    for (evaluations[0]) |value| try std.testing.expect(value.isZero());
}
