const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const cosets = @import("../coset_evaluation.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Polynomial = engine.poly.circle.CircleCoefficients;
const Poly = engine.air.component_prover.Poly;
const a = std.testing.allocator;

test "RV64 coset scratch: arbitrary degree-bounded polynomials and predecessor samples equal full LDE" {
    var prng = std.Random.DefaultPrng.init(0x434f534554345256);
    const rng = prng.random();
    for (2..10) |native| {
        const log: u32 = @intCast(native);
        const size = @as(usize, 1) << @intCast(log);
        var coefficients: [3][]M = undefined;
        var initialized: usize = 0;
        defer for (coefficients[0..initialized]) |column| a.free(column);
        var sources: [3]Poly = undefined;
        for (&coefficients, &sources, 0..) |*column, *source, i| {
            column.* = try a.alloc(M, if (i == 0) size else if (i == 1) size / 2 else 1);
            initialized += 1;
            for (column.*) |*value| value.* = M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus);
            source.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try Polynomial.initBorrowed(column.*) };
        }
        const domain = core.poly.circle.canonic.CanonicCoset.new(log + 2).circleDomain();
        var reference: [3][]const M = undefined;
        var reference_count: usize = 0;
        defer for (reference[0..reference_count]) |column| a.free(column);
        for (sources, &reference) |source, *column| {
            column.* = (try source.coefficients.?.evaluate(a, domain)).values;
            reference_count += 1;
        }
        var evaluation = try cosets.Evaluation.init(a, &sources, log, &.{ true, false, true });
        defer evaluation.deinit();
        try std.testing.expectEqual(5 * size, evaluation.scratch.len);
        try std.testing.expectEqual(@as(usize, 0), evaluation.previous_values[1].len);
        const original_scratch = evaluation.scratch.ptr;
        const trace_step = core.poly.circle.canonic.CanonicCoset.new(log).step();
        for (0..cosets.PARTS) |part| {
            try evaluation.evaluatePart(part);
            try std.testing.expectEqual(original_scratch, evaluation.scratch.ptr);
            const local_domain = try evaluation.domain(part);
            const inverse = try evaluation.denominatorInverse(part);
            for (0..size) |row| {
                const global = evaluation.globalRow(part, row);
                const previous = core.utils.previousBitReversedCircleDomainIndex(global, log, log + 2);
                try std.testing.expectEqual(part ^ 1, previous / size);
                const local = local_domain.at(core.utils.bitReverseIndex(row, log));
                const point = domain.at(core.utils.bitReverseIndex(global, log + 2));
                try std.testing.expect(local.eql(point));
                const previous_point = domain.at(core.utils.bitReverseIndex(previous, log + 2));
                try std.testing.expect(point.sub(trace_step).eql(previous_point));
                const expected_inverse = try core.constraints.cosetVanishing(M, core.poly.circle.canonic.CanonicCoset.new(log).coset(), point).inv();
                try std.testing.expect(inverse.eql(expected_inverse));
                for (evaluation.current_values, reference, sources) |actual, expected, source| {
                    try std.testing.expect(actual[row].eql(expected[global]));
                    try std.testing.expect(Q.fromBase(actual[row]).eql(source.coefficients.?.evalAtPoint(.{ .x = Q.fromBase(point.x), .y = Q.fromBase(point.y) })));
                }
                for ([_]usize{ 0, 2 }) |column| {
                    try std.testing.expect(evaluation.previous_values[column][evaluation.previousRow(part, row)].eql(reference[column][previous]));
                }
                // A quartic residual with a preceding-row factor must retain
                // the exact full-domain quotient position and denominator.
                const x = evaluation.current_values[0][row];
                const y = evaluation.current_values[1][row];
                const z = evaluation.previous_values[2][evaluation.previousRow(part, row)];
                const partitioned = x.square().square().add(y.mul(z.square())).mul(inverse);
                const full = reference[0][global].square().square().add(reference[1][global].mul(reference[2][previous].square())).mul(expected_inverse);
                try std.testing.expect(partitioned.eql(full));
            }
        }
        try std.testing.expectEqual(@as(usize, 4 * sources.len), evaluation.test_transformed_columns);
        try std.testing.expectError(error.InvalidCosetPartition, evaluation.evaluatePart(4));
    }
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const coefficients: [8]M = .{M.one()} ** 8;
    const sources = [_]Poly{.{ .log_size = 4, .values = &.{}, .coefficients = try Polynomial.initBorrowed(&coefficients) }};
    var evaluation = try cosets.Evaluation.init(allocator, &sources, 3, &.{true});
    defer evaluation.deinit();
    for (0..cosets.PARTS) |part| try evaluation.evaluatePart(part);
}
test "RV64 coset scratch: every initialization and per-coset FFT failure releases owned storage" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    const values: [8]M = .{M.zero()} ** 8;
    const missing = [_]Poly{.{ .log_size = 3, .values = &values }};
    try std.testing.expectError(error.MissingRv64CosetCoefficients, cosets.Evaluation.init(a, &missing, 3, &.{false}));
}

test "RV64 coset column FFT waves equal serial values and drain before reuse" {
    const log = 12;
    const size = 1 << log;
    const columns = 11;
    const coefficients = try a.alloc(M, columns * size);
    defer a.free(coefficients);
    var sources: [columns]Poly = undefined;
    var previous: [columns]bool = undefined;
    for (&sources, &previous, 0..) |*source, *shifted, c| {
        const values = coefficients[c * size ..][0..size];
        for (values, 0..) |*value, row| value.* = M.fromU64((c + 7) * (row * row + 13));
        source.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try Polynomial.initBorrowed(values) };
        shifted.* = c % 3 == 0;
    }
    var serial = try cosets.Evaluation.init(a, &sources, log, &previous);
    defer serial.deinit();
    var pooled = try cosets.Evaluation.init(a, &sources, log, &previous);
    defer pooled.deinit();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .backing_allocator = a });
    defer pool.deinit();
    for (0..2) |_| for (0..cosets.PARTS) |part| {
        try serial.evaluatePart(part);
        try pooled.evaluatePartWithPool(part, &pool);
        for (serial.current_values, pooled.current_values, serial.previous_values, pooled.previous_values) |want, actual, prior_want, prior_actual| {
            try std.testing.expectEqualSlices(M, want, actual);
            try std.testing.expectEqualSlices(M, prior_want, prior_actual);
        }
    };
    var competing = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    defer competing.deinit();
    try std.testing.expectError(error.WorkerBudgetUnavailable, pooled.evaluatePartWithPool(0, &pool));
}

test "paired cosets swap exact predecessor buffers and tolerate arbitrary requests with every mask pattern" {
    const log = 6;
    const size = 1 << log;
    var coefficients: [3][size]M = undefined;
    var sources: [3]Poly = undefined;
    for (&coefficients, &sources, 0..) |*column, *source, c| {
        for (column, 0..) |*v, i| v.* = M.fromCanonical(@intCast(11 + 29 * c + 7 * i + i * i));
        source.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try Polynomial.initBorrowed(column) };
    }
    const domain = core.poly.circle.canonic.CanonicCoset.new(log + 2).circleDomain();
    var reference: [3][]const M = undefined;
    var filled: usize = 0;
    defer for (reference[0..filled]) |column| a.free(column);
    for (sources, &reference) |source, *column| {
        column.* = (try source.coefficients.?.evaluate(a, domain)).values;
        filled += 1;
    }
    for ([_][3]bool{ .{ false, false, false }, .{ true, true, true }, .{ true, false, true } }) |mask| {
        var evaluation = try cosets.Evaluation.init(a, &sources, log, &mask);
        defer evaluation.deinit();
        const original_scratch = evaluation.scratch.ptr;
        try evaluation.evaluatePart(0);
        const before = evaluation.test_transformed_columns;
        const current: [3][]const M = evaluation.current_values[0..3].*;
        const previous: [3][]const M = evaluation.previous_values[0..3].*;
        try evaluation.evaluatePart(1);
        for (mask, 0..) |marked, c| {
            if (marked) {
                try std.testing.expect(evaluation.current_values[c].ptr == previous[c].ptr);
                try std.testing.expect(evaluation.previous_values[c].ptr == current[c].ptr);
            } else try std.testing.expect(evaluation.current_values[c].ptr == current[c].ptr);
        }
        var expected_new: usize = 0;
        for (mask) |marked| expected_new += @intFromBool(!marked);
        try std.testing.expectEqual(before + expected_new, evaluation.test_transformed_columns);
        for ([_]usize{ 2, 3, 3, 2, 0, 3, 1, 0 }) |part| {
            try evaluation.evaluatePart(part);
            try std.testing.expect(evaluation.scratch.ptr == original_scratch);
            for (0..size) |row| {
                const global = evaluation.globalRow(part, row);
                const prior = core.utils.previousBitReversedCircleDomainIndex(global, log, log + 2);
                for (mask, reference, 0..) |marked, want, c| {
                    try std.testing.expect(evaluation.current_values[c][row].eql(want[global]));
                    if (marked) try std.testing.expect(evaluation.previous_values[c][evaluation.previousRow(part, row)].eql(want[prior]));
                }
            }
        }
    }
}

test "failed unshifted FFT after partner swap invalidates cache and retry reinitializes every view" {
    var coefficients: [2][8]M = undefined;
    var sources: [2]Poly = undefined;
    for (&coefficients, &sources, 0..) |*column, *source, c| {
        for (column, 0..) |*v, i| v.* = M.fromCanonical(@intCast(13 + c * 23 + i * i));
        source.* = .{ .log_size = 4, .values = &.{}, .coefficients = try Polynomial.initBorrowed(column) };
    }
    var fail = std.testing.FailingAllocator.init(a, .{});
    var evaluation = try cosets.Evaluation.init(fail.allocator(), &sources, 3, &.{ true, false });
    defer evaluation.deinit();
    try evaluation.evaluatePart(0);
    fail.fail_index = fail.alloc_index;
    try std.testing.expectError(error.OutOfMemory, evaluation.evaluatePart(1));
    try std.testing.expect(evaluation.cached_part == null);
    fail.fail_index = std.math.maxInt(usize);
    try evaluation.evaluatePart(1);
    var independent = try cosets.Evaluation.init(a, &sources, 3, &.{ true, false });
    defer independent.deinit();
    try independent.evaluatePart(1);
    for (evaluation.current_values, independent.current_values, evaluation.previous_values, independent.previous_values) |actual, want, previous, prior_want| {
        try std.testing.expectEqualSlices(M, want, actual);
        try std.testing.expectEqualSlices(M, prior_want, previous);
    }
}
