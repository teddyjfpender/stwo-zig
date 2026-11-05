const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = core.fri.ForField(O);
const a = std.testing.allocator;
extern "c" fn rv64_test_fri_pairs([*]const [8]u32, [*]const u32, *const [8]u32, u32, ?[*]const [8]u32, [*][8]u32) void;
fn words(x: O) [8]u32 {
    var out: [8]u32 = undefined;
    for (x.toM31Array(), &out) |v, *w| w.* = v.v;
    return out;
}
fn random(rng: std.Random) O {
    var out: [8]M = undefined;
    for (&out) |*v| v.* = M.fromCanonical(rng.uintLessThan(u32, core.fields.m31.Modulus));
    return O.fromM31Array(out);
}
test "OM31 CUDA PCS FRI formula agrees with native canonical line and circle folds" {
    var generator = std.Random.DefaultPrng.init(0x5090_128);
    const rng = generator.random();
    for (1..11) |log_| {
        const log: u32 = @intCast(log_);
        const n = @as(usize, 1) << @intCast(log);
        const src = try a.alloc(O, n);
        defer a.free(src);
        const src_words = try a.alloc([8]u32, n);
        defer a.free(src_words);
        for (src, src_words) |*v, *w| {
            v.* = random(rng);
            w.* = words(v.*);
        }
        const inverses = try a.alloc(u32, n / 2);
        defer a.free(inverses);
        const got = try a.alloc([8]u32, n / 2);
        defer a.free(got);
        for (0..3) |mode| {
            const alpha = switch (mode) {
                0 => O.zero(),
                1 => O.one(),
                else => random(rng),
            };
            const aw = words(alpha);
            const circle = core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
            const line = core.poly.line.LineDomain.fromCircleDomain(circle);
            for (inverses, 0..) |*inv, i| inv.* = (try line.at(core.utils.bitReverseIndex(i, log - 1)).inv()).v;
            var workspace = try F.FoldLineWorkspace.init(a, n / 2);
            defer workspace.deinit(a);
            const expected = try F.foldLineSingleStep(a, src, line, alpha, &workspace);
            defer a.free(expected.values);
            rv64_test_fri_pairs(src_words.ptr, inverses.ptr, &aw, @intCast(n), null, got.ptr);
            for (got, expected.values) |actual, value| try std.testing.expectEqualSlices(u32, &words(value), &actual);
            const circle_domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
            const prior = try a.alloc(O, n / 2);
            defer a.free(prior);
            const prior_words = try a.alloc([8]u32, n / 2);
            defer a.free(prior_words);
            for (prior, prior_words, inverses, 0..) |*v, *w, *inv, i| {
                v.* = random(rng);
                w.* = words(v.*);
                inv.* = (try circle_domain.half_coset.at(core.utils.bitReverseIndex(i, log - 1)).y.inv()).v;
            }
            rv64_test_fri_pairs(src_words.ptr, inverses.ptr, &aw, @intCast(n), prior_words.ptr, got.ptr);
            try F.foldCircleIntoLine(prior, src, circle_domain, alpha);
            for (got, prior) |actual, value| try std.testing.expectEqualSlices(u32, &words(value), &actual);
        }
    }
}
