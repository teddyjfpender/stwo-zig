//! Focused Metal FRI layer and terminal-degree parity.

const std = @import("std");
const core = @import("stwo_core");
const MetalBackend = @import("../commit_backend.zig").MetalCommitBackend;
const parity = @import("../fri_fold_parity.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

test "metal: FRI parity reports the first circle coordinate mutation" {
    const source_log: u32 = 5;
    const source_count: usize = @as(usize, 1) << @intCast(source_log);
    const destination_count = source_count / 2;
    const domain = core.poly.circle.CanonicCoset.new(source_log).circleDomain();
    var storage: [4][source_count]M31 = undefined;
    for (&storage, 0..) |*column, coordinate| {
        for (column, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast(
                3 + coordinate * 101 + row * 17,
            ));
        }
    }
    const source = [4][]const M31{
        storage[0][0..source_count],
        storage[1][0..source_count],
        storage[2][0..source_count],
        storage[3][0..source_count],
    };
    var inverses: [destination_count]M31 = undefined;
    for (&inverses, 0..) |*inverse, row| {
        const point = domain.at(core.utils.bitReverseIndex(
            row * 2,
            domain.logSize(),
        ));
        inverse.* = try point.y.inv();
    }
    const alpha = QM31.fromU32Unchecked(7, 11, 13, 17);
    var actual: [destination_count]QM31 = undefined;
    for (&actual, inverses, 0..) |*value, inverse, row| {
        const left_index = row * 2;
        const right_index = left_index + 1;
        const left = QM31.fromM31Array(.{
            source[0][left_index],
            source[1][left_index],
            source[2][left_index],
            source[3][left_index],
        });
        const right = QM31.fromM31Array(.{
            source[0][right_index],
            source[1][right_index],
            source[2][right_index],
            source[3][right_index],
        });
        value.* = left.add(right).add(alpha.mul(
            left.sub(right).mulM31(inverse),
        ));
    }

    const valid = try parity.validateCircle(
        source,
        domain,
        &inverses,
        alpha,
        &actual,
    );
    try std.testing.expectEqual(parity.Kind.circle_to_line, valid.kind);
    try std.testing.expect(valid.terminal_coefficient_one == null);

    actual[7] = actual[7].add(QM31.fromM31(
        M31.zero(),
        M31.zero(),
        M31.one(),
        M31.zero(),
    ));
    const mismatch = (try parity.firstCircleMismatch(
        source,
        &inverses,
        alpha,
        &actual,
    )).?;
    try std.testing.expectEqual(@as(usize, 7), mismatch.row);
    try std.testing.expectEqual(@as(usize, 2), mismatch.coordinate);
    try std.testing.expectEqual(mismatch.expected + 1, mismatch.actual);
}

test "metal: complete line FRI chain matches CPU and has zero terminal coefficient one" {
    const allocator = std.testing.allocator;
    try MetalBackend.warmup();

    const source_log: u32 = 12;
    const source_count: usize = @as(usize, 1) << @intCast(source_log);
    const domain = try core.poly.line.LineDomain.init(
        core.circle.Coset.halfOdds(source_log),
    );
    const ordered_coefficients = try allocator.alloc(QM31, source_count);
    @memset(ordered_coefficients, QM31.zero());
    ordered_coefficients[0] = QM31.fromU32Unchecked(3, 5, 7, 11);
    ordered_coefficients[1] = QM31.fromU32Unchecked(13, 17, 19, 23);
    var polynomial = core.poly.line.LinePoly.fromOrderedCoefficients(
        ordered_coefficients,
    );
    defer polynomial.deinit(allocator);

    const bit_reversed_evaluation = try allocator.alloc(QM31, source_count);
    defer allocator.free(bit_reversed_evaluation);
    for (bit_reversed_evaluation, 0..) |*value, natural_index| {
        value.* = try polynomial.evalAtPoint(
            allocator,
            QM31.fromBase(domain.at(natural_index)),
        );
    }
    core.utils.bitReverse(QM31, bit_reversed_evaluation);

    var metal = try MetalBackend.allocateLineEvaluation(domain);
    @memcpy(@constCast(metal.values), bit_reversed_evaluation);
    defer metal.deinit(allocator);
    var group: u32 = 0;
    while (metal.len() > 2) : (group += 1) {
        const remaining_folds = std.math.log2_int(usize, metal.len()) - 1;
        const fold_count: u32 = @intCast(@min(remaining_folds, 4));
        const alpha = QM31.fromU32Unchecked(
            29 + group,
            31 + group,
            37 + group,
            41 + group,
        );
        var cpu_workspace = try core.fri.FoldLineWorkspace.init(
            allocator,
            metal.len() / 2,
        );
        defer cpu_workspace.deinit(allocator);
        const cpu = try core.fri.foldLineNWithWorkspace(
            allocator,
            metal.values,
            metal.domain(),
            alpha,
            &cpu_workspace,
            fold_count,
        );
        defer allocator.free(cpu.values);

        var metal_workspace = try core.fri.FoldLineWorkspace.init(
            allocator,
            metal.len() / 2,
        );
        defer metal_workspace.deinit(allocator);
        var next = try MetalBackend.foldLineEvaluationN(
            allocator,
            metal,
            alpha,
            &metal_workspace,
            fold_count,
        );
        errdefer next.deinit(allocator);
        try expectEqualQm31Slices(cpu.values, next.values);
        metal.deinit(allocator);
        metal = next;
    }

    const coefficient_one = try parity.terminalCoefficientOne(
        metal.values,
        metal.domain(),
    );
    try std.testing.expect(coefficient_one.isZero());
}

fn expectEqualQm31Slices(expected: []const QM31, actual: []const QM31) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));
}
