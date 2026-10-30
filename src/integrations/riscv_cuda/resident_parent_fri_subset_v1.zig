//! Exact allocation-free subset folds for GPU sparse FRI reconstruction.
//! Uses the original circle/line domains and the core's canonical butterfly.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const MAX_WIDTH: usize = 32;
pub fn fold(is_circle: bool, domain_log: u32, fold_log: u32, subset_start: u32, input: []const Q, alpha: Q) !Q {
    if (domain_log == 0 or domain_log > 30 or fold_log == 0 or fold_log > 5 or
        fold_log > domain_log or input.len != @as(usize, 1) << @intCast(fold_log) or
        subset_start >= @as(u32, 1) << @intCast(domain_log) or subset_start & ((@as(u32, 1) << @intCast(fold_log)) - 1) != 0)
        return error.InvalidResidentFriSubset;
    for (input) |value| for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.InvalidResidentFriSubset;
    for (alpha.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.InvalidResidentFriSubset;
    const natural = core.utils.bitReverseIndex(subset_start, domain_log);
    var scratch: [MAX_WIDTH]Q = undefined;
    @memcpy(scratch[0..input.len], input);
    var length = input.len;
    var current_alpha = alpha;
    var line_domain: core.poly.line.LineDomain = undefined;
    if (is_circle) {
        const source = core.poly.circle.CanonicCoset.new(domain_log).circleDomain();
        const subset = core.poly.circle.CircleDomain.new(core.circle.Coset.new(source.indexAt(natural), fold_log - 1));
        const next = length / 2;
        for (0..next) |j| {
            const point = subset.half_coset.at(core.utils.bitReverseIndex(j, fold_log - 1));
            scratch[j] = core.fri.foldPairWithInverse(scratch[2 * j], scratch[2 * j + 1], try point.y.inv(), current_alpha);
        }
        length = next;
        current_alpha = current_alpha.square();
        line_domain = core.poly.line.LineDomain.fromCircleDomain(subset);
    } else {
        const source = core.poly.line.LineDomain.fromCircleDomain(core.poly.circle.CanonicCoset.new(domain_log + 1).circleDomain());
        line_domain = try core.poly.line.LineDomain.init(core.circle.Coset.new(source.coset().indexAt(natural), fold_log));
    }
    while (length > 1) {
        const next = length / 2;
        const log: u32 = @intCast(std.math.log2_int(usize, next));
        for (0..next) |j| {
            const x = line_domain.at(core.utils.bitReverseIndex(j, log));
            scratch[j] = core.fri.foldPairWithInverse(scratch[2 * j], scratch[2 * j + 1], try x.inv(), current_alpha);
        }
        line_domain = line_domain.double();
        current_alpha = current_alpha.square();
        length = next;
    }
    return scratch[0];
}

test "resident FRI subset geometry matches original sparse folds across widths and domains" {
    const a = std.testing.allocator;
    var random = std.Random.DefaultPrng.init(0x76854589);
    const rng = random.random();
    var cases: usize = 0;
    for ([_]bool{ true, false }) |is_circle| for (1..14) |log_usize| {
        const domain_log: u32 = @intCast(log_usize);
        for (1..@min(6, log_usize + 1)) |step_usize| {
            const step: u32 = @intCast(step_usize);
            const width: usize = @as(usize, 1) << @intCast(step);
            for (0..4) |_| {
                var values: [MAX_WIDTH]Q = undefined;
                for (values[0..width]) |*value| value.* = randomQ(rng);
                const alpha = randomQ(rng);
                const position: u32 = (rng.int(u32) & ((@as(u32, 1) << @intCast(domain_log)) - 1)) & ~(@as(u32, @intCast(width)) - 1);
                const initial = core.utils.bitReverseIndex(position, domain_log);
                var subsets = [_][]Q{values[0..width]};
                var initials = [_]usize{initial};
                const sparse = try core.fri.SparseEvaluation.initOwned(&subsets, &initials);
                const expected = if (is_circle)
                    try sparse.foldCircleSubsets(a, alpha, core.poly.circle.CanonicCoset.new(domain_log).circleDomain(), step)
                else
                    try sparse.foldLineSubsetsN(a, alpha, core.poly.line.LineDomain.fromCircleDomain(core.poly.circle.CanonicCoset.new(domain_log + 1).circleDomain()), step);
                defer a.free(expected);
                try std.testing.expectEqualDeep(expected[0], try fold(is_circle, domain_log, step, position, values[0..width], alpha));
                cases += 1;
            }
        }
    };
    try std.testing.expect(cases > 400);
}
fn randomQ(rng: std.Random) Q {
    var words: [4]M = undefined;
    for (&words) |*word| word.* = M.fromCanonical(rng.uintLessThan(u32, core.fields.m31.Modulus));
    return Q.fromM31Array(words);
}
pub fn exported(circle: u32, log: u32, step: u32, first: u32, values: [*]const u32, alpha_words: *const [4]u32, output: *[4]u32) callconv(.c) u32 {
    if (circle > 1 or step == 0 or step > 5) return 1;
    const count = @as(usize, 1) << @intCast(step);
    var input: [MAX_WIDTH]Q = undefined;
    for (input[0..count], 0..) |*value, i| value.* = Q.fromM31Array(.{
        M.fromU32Unchecked(values[4 * i]),     M.fromU32Unchecked(values[4 * i + 1]),
        M.fromU32Unchecked(values[4 * i + 2]), M.fromU32Unchecked(values[4 * i + 3]),
    });
    const alpha = Q.fromM31Array(.{ M.fromU32Unchecked(alpha_words[0]), M.fromU32Unchecked(alpha_words[1]), M.fromU32Unchecked(alpha_words[2]), M.fromU32Unchecked(alpha_words[3]) });
    const result = fold(circle != 0, log, step, first, input[0..count], alpha) catch return 1;
    for (output, result.toM31Array()) |*word, value| word.* = value.v;
    return 0;
}
