const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const P = K.parallel;
const G = P.testing.Gather;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
const L = K.layout;

test "Keccak native tiles preserve all full-domain halo reads including partial tiles" {
    const log = 6;
    const n = 1 << log;
    const columns = L.FIXED + L.MAIN + L.INTERACTION;
    const coefficients = try a.alloc([8]M, columns);
    defer a.free(coefficients);
    const polys = try a.alloc(engine.air.component_prover.Poly, columns);
    defer a.free(polys);
    const previous = try a.alloc(bool, columns);
    defer a.free(previous);
    const full = try a.alloc([]const M, columns);
    defer a.free(full);
    var filled: usize = 0;
    defer for (full[0..filled]) |column| a.free(column);
    const domain = core.poly.circle.canonic.CanonicCoset.new(log + 2).circleDomain();
    for (polys, coefficients, previous, 0..) |*poly, *c, *masked, i| {
        for (c, 0..) |*v, j| v.* = M.fromU64(17 + i * 53 + j * 179 + i * j);
        poly.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(c) };
        masked.* = (i >= L.FIXED and i < L.FIXED + L.STATE) or (i >= L.FIXED + L.ACTIVE_A and i < L.FIXED + L.MAIN) or i >= columns - 4;
        full[i] = (try poly.coefficients.?.evaluate(a, domain)).values;
        filled += 1;
    }
    var evaluation = try P.testing.Evaluation.init(a, polys, log, previous);
    defer evaluation.deinit();
    const tile = try a.alloc(G.Row, G.ROWS);
    defer a.free(tile);
    const scratch = try a.create(K.component.Scratch);
    defer a.destroy(scratch);
    for (0..4) |part| {
        try evaluation.evaluatePart(part);
        // Start at odd offsets; widths 1, 7 and 16 exercise final partial rows.
        for ([_]usize{ 1, 7, 16 }) |width| {
            var start: usize = 1;
            while (start < n) {
                const count = @min(width, n - start);
                G.fill(&evaluation, part, start, tile[0..count]);
                for (tile[0..count], 0..) |*row, r| {
                    const global = part * n + start + r;
                    const prior = core.utils.previousBitReversedCircleDomainIndex(global, log, log + 2);
                    const actual_previous = row.promote(scratch);
                    for (scratch.fixed, full[0..L.FIXED]) |v, column| try std.testing.expect(v.eql(Q.fromBase(column[global])));
                    for (scratch.main, full[L.FIXED..][0..L.MAIN]) |v, column| try std.testing.expect(v.eql(Q.fromBase(column[global])));
                    for (L.MASK_OFFSETS[1..], 0..) |offset, j| {
                        const shifted = core.utils.offsetBitReversedCircleDomainIndex(global, log, log + 2, offset);
                        for (scratch.shifted[j], full[L.FIXED..][0..L.STATE]) |v, column| try std.testing.expect(v.eql(Q.fromBase(column[shifted])));
                    }
                    for (scratch.previous_header, full[L.FIXED + L.ACTIVE_A ..][0..3]) |v, column| try std.testing.expect(v.eql(Q.fromBase(column[prior])));
                    const fm = L.FIXED + L.MAIN;
                    for (scratch.interaction, 0..) |v, b| try std.testing.expect(v.eql(secure(full[fm + 4 * b ..], global)));
                    try std.testing.expect(actual_previous.eql(secure(full[columns - 4 ..], prior)));
                }
                start += count;
            }
        }
    }
}
fn secure(columns: []const []const M, row: usize) Q {
    return Q.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

test "Keccak tiled native quotient retains exact serialized proof and point verification at 1/3/8/16 workers" {
    const fixture = @import("rv64_keccak_proof_test.zig");
    var reference: ?[32]u8 = null;
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = P.MIN_STACK, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        if (reference == null) {
            var untiled = P.testing.Binding.init(false);
            defer untiled.deinit();
            reference = try fixture.gather_testing.digest(a, 10);
        }
        var tiled = P.testing.Binding.init(true);
        defer tiled.deinit();
        const digest = try fixture.gather_testing.digest(a, 10);
        try std.testing.expectEqualSlices(u8, &reference.?, &digest);
    }
}

test "Keccak native tile quotient matches untiled arbitrary polynomial oracle at all worker budgets" {
    const log = 10;
    const n = 1 << log;
    const columns = L.FIXED + L.MAIN + L.INTERACTION;
    const coefficients = try a.alloc([8]M, columns);
    defer a.free(coefficients);
    const polys = try a.alloc(engine.air.component_prover.Poly, columns);
    defer a.free(polys);
    const previous = try a.alloc(bool, columns);
    defer a.free(previous);
    for (polys, coefficients, previous, 0..) |*poly, *c, *masked, i| {
        for (c, 0..) |*v, j| v.* = M.fromU64(71 + i * 31 + j * 127 + i * j);
        poly.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(c) };
        masked.* = (i >= L.FIXED and i < L.FIXED + L.STATE) or (i >= L.FIXED + L.ACTIVE_A and i < L.FIXED + L.MAIN) or i >= columns - 4;
    }
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b54494c, 19 });
    const component = K.component.Component{ .kind = .permutation, .log_size = log, .calls = 1, .challenges = K.equations.Challenges.draw(&channel), .claim = channel.drawSecureFelt() };
    var evaluation = try P.testing.Evaluation.init(a, polys, log, previous);
    defer evaluation.deinit();
    const alpha = channel.drawSecureFelt();
    var oracle = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, L.CONSTRAINTS);
    defer oracle.deinit();
    var candidate = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, L.CONSTRAINTS);
    defer candidate.deinit();
    const old = try oracle.columns(a, &.{.{ .log_size = log + 2, .n_cols = L.CONSTRAINTS }});
    defer a.free(old);
    const actual = try candidate.columns(a, &.{.{ .log_size = log + 2, .n_cols = L.CONSTRAINTS }});
    defer a.free(actual);
    // Each budget adds one pass to both accumulators, checking additive output
    // and scratch reuse as well as individual worker waves and halo reads.
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = P.MIN_STACK, .backing_allocator = a });
        defer pool.deinit();
        for (0..4) |part| {
            try evaluation.evaluatePart(part);
            const inverse = try evaluation.denominatorInverse(part);
            try P.testing.evaluateUntiled(&component, &evaluation, part, &old[0], inverse, null);
            try P.evaluatePart(&component, &evaluation, part, &actual[0], inverse, &pool);
            for (0..4 * n) |row| try std.testing.expect(old[0].col.at(row).eql(actual[0].col.at(row)));
        }
        const before = actual[0].col.at(0);
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        evaluation.allocator = failing.allocator();
        const allocation_result = P.evaluatePart(&component, &evaluation, 0, &actual[0], M.one(), &pool);
        evaluation.allocator = a;
        try std.testing.expectError(error.OutOfMemory, allocation_result);
        try std.testing.expect(before.eql(actual[0].col.at(0)));
        if (workers > 1) {
            var reservation = try pool.acquire(try engine.work_pool.WorkerBudget.init(workers));
            const reserved_result = P.evaluatePart(&component, &evaluation, 0, &actual[0], M.one(), &pool);
            reservation.deinit();
            try std.testing.expectError(error.WorkerBudgetUnavailable, reserved_result);
            try std.testing.expect(before.eql(actual[0].col.at(0)));
        }
    }
    const saved = evaluation.previous_values[L.FIXED];
    evaluation.previous_values[L.FIXED] = &.{};
    const malformed = P.evaluatePart(&component, &evaluation, 0, &actual[0], M.one(), null);
    evaluation.previous_values[L.FIXED] = saved;
    try std.testing.expectError(error.InvalidKeccakCosetShape, malformed);
}
