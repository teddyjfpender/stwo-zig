const std = @import("std");
const engine = @import("stwo_prover_engine");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const A = @import("alu.zig");
const P = @import("alu_lookup.zig");
const S = @import("alu_source.zig");
const U = @import("u16_source.zig");
const O = @import("operations.zig");
const physical = @import("../witness.zig").physical;
const Q = E.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const N = 32;
fn facts() [10]S.Fact {
    var result: [10]S.Fact = undefined;
    for (std.enums.values(O.Alu), 0..) |op, i| {
        const x: u64 = if (i % 2 == 0) 0x80000000ffffffff else 0x7fffffffffffffff;
        const y: u64 = if (i % 3 == 0) 1 else 0xffff000012345678;
        result[i] = .{ .op = op, .a = x, .b = y, .c = A.nativeResult(op, x, y) };
    }
    return result;
}
test "ALU physical native waves equal serial and cancelled submissions preserve borrowed main" {
    const values = facts();
    const log = 14;
    var serial = try S.Source.init(a, &values, log);
    defer serial.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const available = pool.availableWorkers();
    const weights: [10]u32 = .{ 70000, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    var weighted = try S.Source.initWeighted(a, &values, &weights, log);
    defer weighted.deinit();
    var weighted_serial = try S.Source.initWeighted(a, &values, &weights, 5);
    defer weighted_serial.deinit();
    // Logical row metadata is independent of native worker partitioning.
    for (weighted_serial.metadata[0..values.len], weighted.metadata[0..values.len]) |x, y| try std.testing.expect(std.meta.eql(x, y));
    var parallel = try S.Source.init(a, &values, log);
    defer parallel.deinit();
    try std.testing.expectEqualSlices(M, serial.main, parallel.main);
    try std.testing.expectEqualSlices(u64, serial.range16_counts, parallel.range16_counts);
    for (serial.metadata, parallel.metadata) |x, y| try std.testing.expect(std.meta.eql(x, y));
    const borrowed = try a.alloc(M, P.MAIN * (@as(usize, 1) << log));
    defer a.free(borrowed);
    @memset(borrowed, M.fromCanonical(23));
    for ([_]usize{ 0, 1 }) |failure| {
        S.testing.fail_after_helpers = failure;
        defer S.testing.fail_after_helpers = null;
        try std.testing.expectError(error.InjectedAluNativeSubmissionFailure, S.Source.initWithMainBuffers(a, &values, log, .{ .main = borrowed }));
        for (borrowed) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
        try std.testing.expectEqual(available, pool.availableWorkers());
        try std.testing.expectError(error.InjectedAluNativeSubmissionFailure, S.Source.initWeightedWithMainBuffers(a, &values, &weights, log, .{ .main = borrowed }));
        for (borrowed) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
        try std.testing.expectEqual(available, pool.availableWorkers());
    }
    var recovered = try S.Source.initWithMainBuffers(a, &values, log, .{ .main = borrowed });
    defer recovered.deinit();
    try std.testing.expectEqualSlices(M, serial.main, recovered.main);
}
fn ch() P.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x414c5553, 1 });
    var result = P.Challenges{ .range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() }, .function = .{ .offset = channel.drawSecureFelt(), .coefficients = undefined } };
    for (&result.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    return result;
}
fn store(data: []M, row: usize, start: usize, v: Q) void {
    for (v.toM31Array(), 0..) |value, c| data[(start + c) * N + row] = value;
}
fn reference(main: []const M, challenge: P.Challenges) !struct { data: []M, claims: P.Claims } {
    const data = try a.alloc(M, P.INTERACTION * N);
    errdefer a.free(data);
    var sum = Q.zero();
    var function = Q.zero();
    for (0..N) |i| {
        const pos = physical(i, 5);
        var values: [P.MAIN]Q = undefined;
        for (&values, 0..) |*v, c| v.* = Q.fromBase(main[c * N + pos]);
        const row = P.rowFromColumnsFor(Q, &values);
        for (0..10) |j| {
            const x = try challenge.range16.denominatorFor(Q, A.rangeValueFor(Q, &row, 2 * j)).inv();
            const y = try challenge.range16.denominatorFor(Q, A.rangeValueFor(Q, &row, 2 * j + 1)).inv();
            store(data, pos, 4 * j, x.mul(y));
            sum = sum.add(x).add(y);
        }
        store(data, pos, 40, sum);
        const inverse = try challenge.function.denominatorFor(Q, row.payload).inv();
        store(data, pos, 44, inverse);
        function = function.sub(inverse.mul(values[A.LOCAL_MAIN]));
        store(data, pos, 48, function);
    }
    for ([_]usize{ 40, 48 }, [_]Q{ sum, function }) |offset, value| {
        for (value.toM31Array(), 0..) |v, c| for (0..N) |i| {
            data[(offset + c) * N + i] = data[(offset + c) * N + i].sub(v);
        };
    }
    return .{ .data = data, .claims = .{ .range16 = sum, .function = function } };
}
test "ALUSource canonical native row cache equals Q authority all10 operations and count-independent geometry" {
    const values = facts();
    var source = try S.Source.init(a, &values, 5);
    defer source.deinit();
    var empty = try S.Source.init(a, &.{}, 5);
    defer empty.deinit();
    try std.testing.expectEqualSlices(M, source.fixed, empty.fixed);
    try std.testing.expectEqual(@as(usize, 70), @sizeOf(S.Metadata));
    for (0..N) |i| {
        var row = if (i < values.len) try A.witness(values[i].op, values[i].a, values[i].b) else try A.witness(.add, 0, 0);
        if (i >= values.len) {
            row.active = Q.zero();
            row.selectors[0] = Q.zero();
        }
        const expected = P.rowToColumnsFor(Q, row);
        const pos = physical(i, 5);
        for (expected, 0..) |v, c| try std.testing.expect(v.eql(Q.fromBase(source.main[c * N + pos])));
        for (0..20) |j| try std.testing.expectEqual((try A.rangeValueFor(Q, &row, j).tryIntoM31()).v, @as(u32, source.metadata[i].range_indices[j]));
    }
    var total: u64 = 0;
    for (source.range16_counts) |value| total += value;
    try std.testing.expectEqual(@as(u64, 20 * N), total);
    try std.testing.expectError(error.InvalidAluGeometry, S.massForLog(27));
}
test "ALUSource shared U16 dictionary and released owned borrowed main preserve all52 columns and80 residuals" {
    const values = facts();
    var source = try S.Source.init(a, &values, 5);
    defer source.deinit();
    const main = try a.dupe(M, source.main);
    defer a.free(main);
    const buffer = try a.alloc(M, P.MAIN * N);
    defer a.free(buffer);
    var borrowed = try S.Source.initWithMainBuffers(a, &values, 5, .{ .main = buffer });
    defer borrowed.deinit();
    try std.testing.expectEqualSlices(M, source.main, borrowed.main);
    var setup = try U.Setup.init(a);
    defer setup.deinit();
    var range = try U.Source.init(a, &setup, source.range16_counts);
    defer range.deinit();
    const challenge = ch();
    const negative = try range.generate(challenge.range16);
    const expected = try reference(main, challenge);
    defer a.free(expected.data);
    const owned = try source.takeMainForCommit();
    a.free(owned);
    try std.testing.expectError(error.BorrowedAluMain, borrowed.takeMainForCommit());
    borrowed.releaseMain();
    @memset(buffer, M.fromCanonical(123));
    const actual = try source.generate(challenge, range.dictionary);
    const other = try borrowed.generate(challenge, range.dictionary);
    try std.testing.expect(actual.range16.eql(expected.claims.range16) and actual.function.eql(expected.claims.function));
    try std.testing.expect(actual.range16.add(negative).isZero());
    try std.testing.expect(actual.range16.eql(other.range16) and actual.function.eql(other.function));
    try std.testing.expectEqualSlices(M, expected.data, source.interaction);
    try std.testing.expectEqualSlices(M, source.interaction, borrowed.interaction);
    for (0..N) |i| {
        const pos = physical(i, 5);
        const before = physical((i + N - 1) % N, 5);
        var row: [P.MAIN]Q = undefined;
        var current: [P.INTERACTION]Q = undefined;
        var previous: [P.INTERACTION]Q = undefined;
        for (&row, 0..) |*v, c| v.* = Q.fromBase(main[c * N + pos]);
        for (&current, &previous, 0..) |*v, *p, c| {
            v.* = Q.fromBase(source.interaction[c * N + pos]);
            p.* = Q.fromBase(source.interaction[c * N + before]);
        }
        var residuals: [P.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        P.emitFor(Q, &row, &current, &previous, Q.fromBase(source.fixed[pos]), Q.fromBase(source.fixed[N + pos]), actual, challenge, &sink);
        try std.testing.expectEqual(P.CONSTRAINTS, sink.count);
        for (residuals) |v| try std.testing.expect(v.isZero());
    }
    try std.testing.expectEqual(@as(usize, 0), source.metadata.len);
    try std.testing.expectError(error.InvalidAluSourcePhase, source.generate(challenge, range.dictionary));
}
test "ALUSource allocation borrowed validation poles dictionary and late ledger errors publish nothing" {
    const values = facts();
    var setup = try U.Setup.init(a);
    defer setup.deinit();
    var base = try S.Source.init(a, &values, 5);
    defer base.deinit();
    var range = try U.Source.init(a, &setup, base.range16_counts);
    defer range.deinit();
    const challenge = ch();
    _ = try range.generate(challenge.range16);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, inputs: []const S.Fact, c: P.Challenges, dictionary: []const Q) !void {
            var s = try S.Source.init(allocator, inputs, 5);
            defer s.deinit();
            s.releaseMain();
            _ = try s.generate(c, dictionary);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{ &values, challenge, range.dictionary });
    var buffer: [P.MAIN * N]M = @splat(M.fromCanonical(23));
    var wrong = values;
    wrong[0].c ^= @as(u64, 1) << 63;
    try std.testing.expectError(error.InvalidAluFact, S.Source.initWithMainBuffers(a, &wrong, 5, .{ .main = &buffer }));
    for (buffer) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
    for (0..5) |failure| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = failure });
        try std.testing.expectError(error.OutOfMemory, S.Source.initWithMainBuffers(failing.allocator(), &values, 5, .{ .main = &buffer }));
        for (buffer) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
    }
    base.releaseMain();
    var wrong_ch = challenge;
    wrong_ch.range16.coefficient = wrong_ch.range16.coefficient.add(Q.one());
    try std.testing.expectError(error.InvalidAluDictionary, base.generate(wrong_ch, range.dictionary));
    var pole = challenge;
    pole.function.offset = Q.zero();
    pole.function.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, base.generate(pole, range.dictionary));
    try std.testing.expectEqual(@as(usize, 0), base.interaction.len);
    base.range16_counts[0] += 1;
    try std.testing.expectError(error.InvalidAluMetadata, base.generate(challenge, range.dictionary));
    try std.testing.expectEqual(@as(usize, 0), base.interaction.len);
    base.range16_counts[0] -= 1;
    _ = try base.generate(challenge, range.dictionary);
}

test "ALU weighted source copies full u32 multiplicity and preserves unweighted range authority after main release" {
    var values = facts();
    var weights: [10]u32 = .{ 70000, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    var source = try S.Source.initWeighted(a, &values, &weights, 5);
    defer source.deinit();
    const main = try a.dupe(M, source.main);
    defer a.free(main);
    var buffer: [P.MAIN * N]M = undefined;
    var borrowed = try S.Source.initWeightedWithMainBuffers(a, &values, &weights, 5, .{ .main = &buffer });
    defer borrowed.deinit();
    try std.testing.expectEqualSlices(M, main, borrowed.main);
    try std.testing.expectEqual(@as(u32, 70000), source.metadata[0].multiplicity());
    try std.testing.expectEqual(@as(u32, 0), source.metadata[1].multiplicity());
    var total: u64 = 0;
    for (source.range16_counts) |n| total += n;
    try std.testing.expectEqual(@as(u64, 20 * N), total);
    var setup = try U.Setup.init(a);
    defer setup.deinit();
    var range = try U.Source.init(a, &setup, source.range16_counts);
    defer range.deinit();
    const challenge = ch();
    const negative = try range.generate(challenge.range16);
    const oracle = try reference(main, challenge);
    defer a.free(oracle.data);
    @memset(&values, .{ .op = .add, .a = 0, .b = 0, .c = 0 });
    @memset(&weights, 0);
    const transferred = try source.takeMainForCommit();
    a.free(transferred);
    borrowed.releaseMain();
    @memset(&buffer, M.fromCanonical(17));
    const claims = try source.generate(challenge, range.dictionary);
    const other = try borrowed.generateSerial(challenge, range.dictionary);
    try std.testing.expect(claims.function.eql(oracle.claims.function) and claims.range16.add(negative).isZero());
    try std.testing.expect(claims.function.eql(other.function));
    try std.testing.expectEqualSlices(M, oracle.data, source.interaction);
    try std.testing.expectEqualSlices(M, oracle.data, borrowed.interaction);
}

test "ALU exact grouping is stable ordered full-word and shared by deduplicated owned borrowed constructors" {
    const x = S.Fact{ .op = .eq, .a = 0, .b = 0, .c = 1 };
    const y = S.Fact{ .op = .add, .a = 1, .b = 2, .c = 3 };
    const z = S.Fact{ .op = .add, .a = 2, .b = 1, .c = 3 };
    const inputs = [_]S.Fact{ x, y, x, z, y, x };
    var grouped = try S.deduplicate(a, &inputs);
    defer grouped.deinit();
    try std.testing.expectEqualSlices(S.Fact, &.{ x, y, z }, grouped.facts);
    try std.testing.expectEqualSlices(u32, &.{ 3, 2, 1 }, grouped.weights);
    var direct = try S.Source.initWeighted(a, grouped.facts, grouped.weights, 5);
    defer direct.deinit();
    var grouped_source = try S.Source.initDeduplicated(a, &inputs, 5);
    defer grouped_source.deinit();
    var buffer: [P.MAIN * N]M = undefined;
    var borrowed = try S.Source.initDeduplicatedWithMainBuffers(a, &inputs, 5, .{ .main = &buffer });
    defer borrowed.deinit();
    try std.testing.expectEqualSlices(M, direct.main, grouped_source.main);
    try std.testing.expectEqualSlices(M, direct.main, borrowed.main);
    try std.testing.expectEqual(@as(u32, inputs.len), grouped_source.function_mass);
    try std.testing.expectEqual(@as(usize, 3), grouped_source.fact_count);
}

test "ALU weighted validation rejects characteristic mass weight shape alias and invalid fact before borrowed publication" {
    const values = facts();
    var buffer: [P.MAIN * N]M = @splat(M.fromCanonical(23));
    const bound = core.fields.m31.Modulus;
    var weights: [10]u32 = @splat(1);
    try std.testing.expectError(error.InvalidAluWeights, S.Source.initWeightedWithMainBuffers(a, &values, weights[0..9], 5, .{ .main = &buffer }));
    weights[0] = bound;
    try std.testing.expectError(error.InvalidAluWeights, S.Source.initWeightedWithMainBuffers(a, &values, &weights, 5, .{ .main = &buffer }));
    weights[0] = bound - 1;
    try std.testing.expectError(error.AluMultiplicityMassExceeded, S.Source.initWeightedWithMainBuffers(a, &values, &weights, 5, .{ .main = &buffer }));
    const aliased: [*]const u32 = @ptrCast(&buffer);
    try std.testing.expectError(error.OverlappingAluInputs, S.Source.initWeightedWithMainBuffers(a, &values, aliased[0..10], 5, .{ .main = &buffer }));
    var invalid = values;
    invalid[0].c ^= 1 << 63;
    try std.testing.expectError(error.InvalidAluFact, S.Source.initDeduplicatedWithMainBuffers(a, &invalid, 5, .{ .main = &buffer }));
    for (buffer) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
}

test "ALU weighted and deduplicated exhaustive allocation failures preserve ownership" {
    const values = facts();
    var setup = try U.Setup.init(a);
    defer setup.deinit();
    var base = try S.Source.init(a, &values, 5);
    defer base.deinit();
    var range = try U.Source.init(a, &setup, base.range16_counts);
    defer range.deinit();
    const challenge = ch();
    _ = try range.generate(challenge.range16);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, inputs: []const S.Fact, c: P.Challenges, dictionary: []const Q) !void {
            var source = try S.Source.initDeduplicated(allocator, inputs, 5);
            defer source.deinit();
            source.releaseMain();
            _ = try source.generate(c, dictionary);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{ &values, challenge, range.dictionary });
    var buffer: [P.MAIN * N]M = @splat(M.fromCanonical(23));
    for (0..5) |failure| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = failure });
        try std.testing.expectError(error.OutOfMemory, S.Source.initWeightedWithMainBuffers(failing.allocator(), &values, &@as([10]u32, @splat(3)), 5, .{ .main = &buffer }));
        for (buffer) |v| try std.testing.expectEqual(@as(u32, 23), v.v);
    }
}

test "ALU weighted metadata corruption and poles publish no interaction and remain retryable" {
    const values = facts();
    var source = try S.Source.initWeighted(a, &values, &@as([10]u32, @splat(7)), 5);
    defer source.deinit();
    source.releaseMain();
    var setup = try U.Setup.init(a);
    defer setup.deinit();
    var range = try U.Source.init(a, &setup, source.range16_counts);
    defer range.deinit();
    const challenge = ch();
    _ = try range.generate(challenge.range16);
    source.metadata[0].multiplicity_words[0] += 1;
    try std.testing.expectError(error.InvalidAluMetadata, source.generate(challenge, range.dictionary));
    source.metadata[0].multiplicity_words[0] -= 1;
    var pole = challenge;
    pole.function.offset = Q.zero();
    pole.function.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, source.generate(pole, range.dictionary));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    _ = try source.generate(challenge, range.dictionary);
}
