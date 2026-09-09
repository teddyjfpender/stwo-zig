//! Actual GPU execution against the shared independent rational oracle. This
//! is a bounded kernel parity gate, not production AOT admission or a proof.
const std = @import("std");
const core = @import("stwo_core");
const component = @import("stwo_prover_engine").air.component_prover;
const generator = @import("framework_polynomial_codegen.zig");
const reference = @import("framework_polynomial_codegen_test.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

extern fn stwo_framework_polynomial_test_create([*]const u8, usize, [*]const u8, usize) ?*anyopaque;
extern fn stwo_framework_polynomial_test_destroy(*anyopaque) void;
extern fn stwo_framework_polynomial_test_run(
    *anyopaque,
    [*]const u32,
    usize,
    [*]const u32,
    usize,
    [*]const u32,
    usize,
    [*]const u64,
    usize,
    [*]const u32,
    usize,
    [*]const u32,
    usize,
    [*]const u32,
    usize,
    [*]u32,
    usize,
    u32,
    [*]const u32,
    u32,
    u32,
) bool;

fn sample(point: core.circle.CirclePointM31, seed: u32) QM31 {
    const s = M31.fromU64(seed);
    return QM31.fromM31Array(.{
        point.x.add(s), point.y.sub(s), point.x.square().add(s), point.y.square().sub(s),
    });
}

fn writeSecure(destination: []u32, offset: usize, value: QM31) void {
    for (value.toM31Array(), 0..) |coordinate, index| destination[offset + index] = coordinate.toU32();
}

fn writePlanes(destination: []u32, rows: usize, row: usize, value: QM31) void {
    for (value.toM31Array(), 0..) |coordinate, index| destination[index * rows + row] = coordinate.toU32();
}

const Shape = enum {
    pair_then_singleton,
    sole_singleton,
    sole_pair,
    singleton_then_pair,
    independent_pair_then_singleton,

    fn arities(self: Shape) []const u8 {
        return switch (self) {
            .pair_then_singleton => &.{ 1, 1, 1 },
            .sole_singleton => &.{33},
            .sole_pair => &.{ 33, 2 },
            .singleton_then_pair => &.{ 1, 33, 2 },
            .independent_pair_then_singleton => &.{ 33, 2, 1 },
        };
    }
};

/// Extend the maintained fixture without introducing another AIR definition.
/// Distinct tuple coordinates and reordered/repeated roots exercise lowering
/// paths that the original arity-one, single-root fixture cannot cover.
fn shapeFixture(allocator: std.mem.Allocator, shape: Shape) !component.OwnedFrameworkPolynomialProgramV1 {
    var program = try reference.fixture(allocator);
    if (shape == .pair_then_singleton) return program;
    var direct: std.ArrayList(component.BasePolynomialNode) = .empty;
    try direct.appendSlice(allocator, program.direct.nodes);
    try direct.appendSlice(allocator, &.{
        .{ .op = .add, .lhs = 0, .rhs = 1 },
        .{ .op = .neg, .lhs = 2 },
    });
    program.direct.nodes = try direct.toOwnedSlice(allocator);
    program.direct.roots = try allocator.dupe(u32, &.{ 5, 4, 1, 6, 4 });
    var lookup: std.ArrayList(component.BasePolynomialNode) = .empty;
    try lookup.appendSlice(allocator, program.lookup_nodes);
    const profile_slot: u32 = @intCast(lookup.items.len);
    try lookup.append(allocator, .{ .op = .column, .value = 2 });
    var tuple_nodes: [33]u32 = undefined;
    for (&tuple_nodes, 0..) |*root, coordinate| {
        const constant: u32 = @intCast(lookup.items.len);
        try lookup.append(allocator, .{ .op = .constant, .value = @intCast(coordinate + 1) });
        root.* = @intCast(lookup.items.len);
        try lookup.append(allocator, .{
            .op = .add,
            .lhs = switch (coordinate % 3) {
                0 => 0,
                1 => 1,
                else => profile_slot,
            },
            .rhs = constant,
        });
    }
    program.lookup_nodes = try lookup.toOwnedSlice(allocator);
    program.entries = program.entries[0..shape.arities().len];
    for (program.entries, shape.arities(), 0..) |*entry, arity, index| {
        entry.domain = @intCast(index + 1);
        entry.arity = arity;
        entry.values = @splat(0);
        @memcpy(entry.values[0..arity], tuple_nodes[0..arity]);
    }
    if (shape == .independent_pair_then_singleton) {
        program.layout = .independent_prefix_v1;
        program.is_first_input = 0;
        program.direct.nodes = &.{};
        program.direct.roots = &.{};
    } else if (shape == .singleton_then_pair) {
        program.batches[0].entry_count = 1;
        program.batches[1].first_entry = 1;
        program.batches[1].entry_count = 2;
    } else {
        program.batches = program.batches[0..1];
        program.batches[0].entry_count = @intCast(program.entries.len);
        program.interaction_columns = program.interaction_columns[0..4];
    }
    program.identity = program.identityDigest();
    return program;
}

/// Explicit scalar reference for the additional shapes. Tuple values and
/// direct roots are evaluated from their stated expressions, never by walking
/// the emitted DAG. Lookup residuals use rational fractions, independently of
/// the generator's denominator-cleared polynomial implementation.
fn shapeExpected(
    shape: Shape,
    pp: M31,
    main: M31,
    current: [2]QM31,
    previous: [2]QM31,
    parameters: component.FrameworkPolynomialParametersV1,
    powers: []const QM31,
    inverse: M31,
    initial: QM31,
) !QM31 {
    if (shape == .pair_then_singleton) return reference.expected(
        .{ pp, main, M31.zero() },
        current,
        previous[1],
        parameters,
        powers[0..3].*,
        inverse,
        initial,
    );
    const profile = parameters.profile_values[0];
    const direct = [_]M31{ pp.add(main), pp.mul(main).sub(profile), main, profile.neg(), pp.mul(main).sub(profile) };
    var folded = QM31.zero();
    if (shape != .independent_pair_then_singleton) {
        for (direct, 0..) |value, index| folded = folded.add(powers[powers.len - 1 - index].mulM31(value));
    }
    var denominators: [3]QM31 = undefined;
    var fractions: [3]QM31 = undefined;
    var parameter_index: usize = 0;
    for (shape.arities(), 0..) |arity, index| {
        var denominator = QM31.zero().sub(parameters.relation_values[parameter_index]);
        parameter_index += 1;
        for (0..arity) |coordinate| {
            const base = switch (coordinate % 3) {
                0 => pp,
                1 => main,
                else => profile,
            };
            const tuple_value = base.add(M31.fromU64(coordinate + 1));
            denominator = denominator.add(parameters.relation_values[parameter_index].mulM31(tuple_value));
            parameter_index += 1;
        }
        denominators[index] = denominator;
        const reciprocal = try denominator.inv();
        fractions[index] = if (index == 1) QM31.zero().sub(reciprocal) else reciprocal;
    }
    if (shape == .independent_pair_then_singleton) {
        // Two independent rational running sums, each with its own previous
        // row and raw terminal claim. There is no same-row prefix subtraction.
        const pair = current[0].sub(previous[0]).add(parameters.batch_claims[0].mulM31(pp))
            .sub(fractions[0]).sub(fractions[1]).mul(denominators[0]).mul(denominators[1]);
        const singleton = current[1].sub(previous[1]).add(parameters.batch_claims[1].mulM31(pp))
            .sub(fractions[2]).mul(denominators[2]);
        return initial.add(powers[1].mul(pair).add(powers[0].mul(singleton)).mulM31(inverse));
    }
    const shift = try parameters.claimedSumShift();
    if (shape == .sole_singleton) {
        const residual = current[0].sub(previous[0]).add(shift).sub(fractions[0]);
        folded = folded.add(powers[0].mul(residual.mul(denominators[0])));
    } else if (shape == .sole_pair) {
        const residual = current[0].sub(previous[0]).add(shift).sub(fractions[0]).sub(fractions[1]);
        folded = folded.add(powers[0].mul(residual.mul(denominators[0]).mul(denominators[1])));
    } else {
        const first = current[0].sub(fractions[0]).mul(denominators[0]);
        const final = current[1].sub(current[0]).sub(previous[1]).add(shift)
            .sub(fractions[1]).sub(fractions[2]).mul(denominators[1]).mul(denominators[2]);
        folded = folded.add(powers[1].mul(first)).add(powers[0].mul(final));
    }
    return initial.add(folded.mulM31(inverse));
}

fn runShape(shape: Shape) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var program = try shapeFixture(allocator, shape);
    const entry = generator.Entry{ .program = &program, .tree_column_counts = &reference.TREE_COUNTS };
    const source = try generator.generateLibrary(allocator, &.{entry});
    const name = try generator.kernelName(allocator, entry);
    const device = stwo_framework_polynomial_test_create(source.ptr, source.len, name.ptr, name.len) orelse
        return error.MetalFrameworkPolynomialCompilationFailed;
    defer stwo_framework_polynomial_test_destroy(device);

    var checked_rows: usize = 0;
    var dispatch_count: usize = 0;
    // One compiled program, with independently varied runtime geometry, public
    // parameters, challenges and claims. None may be specialized into source.
    for ([_]u32{ 2, 3, 5 }) |trace_log| for ([_]u32{ 1, 2, 3 }) |extension| {
        const eval_log = trace_log + extension;
        const rows = @as(usize, 1) << @intCast(eval_log);
        const denominator_count = @as(usize, 1) << @intCast(extension);
        const interval = rows / denominator_count;
        const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
        const trace = core.poly.circle.canonic.CanonicCoset.new(trace_log).coset();
        const inverses = try allocator.alloc(u32, denominator_count);
        for (inverses, 0..) |*inverse, index| {
            const point = domain.at(core.utils.bitReverseIndex(index * interval, eval_log));
            inverse.* = (try core.constraints.cosetVanishing(M31, trace, point).inv()).toU32();
        }

        for (0..3) |variant_index| {
            const variant: u32 = @intCast(variant_index);
            const profile = [_]M31{M31.fromU64(0x7ffffffe - variant)};
            const original_relations = [_]QM31{
                QM31.fromU32Unchecked(13 + variant, 2, 3, 4),
                QM31.fromU32Unchecked(5, 7 + variant, 11, 3),
                QM31.fromU32Unchecked(17, 19 + variant, 2, 9),
                QM31.fromU32Unchecked(23, 29, 3 + variant, 8),
                QM31.fromU32Unchecked(31, 4, 7, 6 + variant),
                QM31.fromU32Unchecked(37 + variant, 5, 2, 13),
            };
            const original_powers = [_]QM31{
                QM31.fromU32Unchecked(3 + variant, 2, 5, 7),
                QM31.fromU32Unchecked(11, 13 + variant, 17, 19),
                QM31.fromU32Unchecked(23, 29, 31 + variant, 37),
            };
            const relations = try allocator.alloc(QM31, program.lookupParameterCount());
            const powers = try allocator.alloc(QM31, program.direct.roots.len + program.batches.len);
            if (shape == .pair_then_singleton) {
                @memcpy(relations, &original_relations);
                @memcpy(powers, &original_powers);
            } else {
                for (relations, 0..) |*value, index| {
                    const seed: u32 = @intCast(101 + 13 * index + variant);
                    value.* = QM31.fromU32Unchecked(seed, seed + 7, seed + 19, seed + 37);
                }
                for (powers, 0..) |*value, index| {
                    const seed: u32 = @intCast(17 + 23 * index + variant);
                    value.* = QM31.fromU32Unchecked(seed + 5, seed + 11, seed + 41, seed + 67);
                }
            }
            const claims = [_]QM31{
                QM31.fromU32Unchecked(41 + variant, 43, 47, 53),
                QM31.fromU32Unchecked(59, 61 + variant, 67, 71),
            };
            const parameters = component.FrameworkPolynomialParametersV1{
                .profile_values = &profile,
                .relation_values = relations,
                .trace_log_size = trace_log,
                .claimed_sum = if (shape == .independent_pair_then_singleton or variant == 0) QM31.zero() else QM31.fromU32Unchecked(41, 43, 47, 53 + variant),
                .batch_claims = if (shape == .independent_pair_then_singleton) &claims else &.{},
            };
            var profile_words: [1]u32 = .{profile[0].toU32()};
            try parameters.validate(&program);
            if (shape != .independent_pair_then_singleton) {
                const shift = try parameters.claimedSumShift();
                try std.testing.expect(shift.mulM31(M31.fromU64(@as(u64, 1) << @intCast(trace_log))).eql(parameters.claimed_sum));
            }
            const claim_count = parameters.claimPayloadCount(&program);
            const relation_words = try allocator.alloc(u32, (relations.len + claim_count) * 4);
            for (relations, 0..) |value, index| writeSecure(relation_words, index * 4, value);
            for (0..claim_count) |index| writeSecure(relation_words, (relations.len + index) * 4, try parameters.claimPayload(&program, index));
            const power_words = try allocator.alloc(u32, powers.len * 4);
            for (powers, 0..) |value, index| writeSecure(power_words, index * 4, value);

            // Deliberately nonzero per-tree origins and unused columns catch
            // accidental packed/local addressing assumptions in the emitter.
            const tree0 = try allocator.alloc(u32, 3 * rows + 16);
            const tree1 = try allocator.alloc(u32, 5 * rows + 16);
            const tree2 = try allocator.alloc(u32, 18 * rows + 16);
            @memset(tree0, 101);
            @memset(tree1, 103);
            @memset(tree2, 107);
            const offsets = try allocator.alloc(u64, program.inputs.len + program.interaction_columns.len);
            offsets[0] = 2 * rows + 5;
            offsets[1] = 4 * rows + 7;
            offsets[2] = std.math.maxInt(u64); // A profile input has no trace address.
            for (3..offsets.len) |index| offsets[index] = (10 + index - 3) * rows + 11;
            const output = try allocator.alloc(u32, 4 * rows + 16);
            const expected = try allocator.alloc(u32, output.len);
            @memset(output, 109);
            @memset(expected, 109);
            const repetitions: u32 = if (variant == 2) 2 else 1;
            for (0..rows) |row| {
                const point = domain.at(core.utils.bitReverseIndex(row, eval_log));
                const previous_row = core.utils.previousBitReversedCircleDomainIndex(row, trace_log, eval_log);
                const previous_point = domain.at(core.utils.bitReverseIndex(previous_row, eval_log));
                const pp = point.x.add(M31.fromU64(59));
                const main = point.y.sub(M31.fromU64(61));
                tree0[@as(usize, @intCast(offsets[0])) + row] = pp.toU32();
                tree1[@as(usize, @intCast(offsets[1])) + row] = main.toU32();
                const current = [2]QM31{ sample(point, 67), sample(point, 71).square() };
                const previous = [2]QM31{ sample(previous_point, 67), sample(previous_point, 71).square() };
                for (current[0..program.batches.len], 0..) |value, secure_index| for (value.toM31Array(), 0..) |coordinate, coordinate_index| {
                    const offset: usize = @intCast(offsets[3 + secure_index * 4 + coordinate_index]);
                    tree2[offset + row] = coordinate.toU32();
                };
                // Independently verify that the uploaded piecewise inverse is
                // the actual vanishing inverse at every expanded-domain row.
                const inverse = try core.constraints.cosetVanishing(M31, trace, point).inv();
                try std.testing.expectEqual(inverse.toU32(), inverses[row / interval]);
                const initial = sample(point, 73);
                writePlanes(output, rows, row, initial);
                var result = initial;
                for (0..repetitions) |_| result = try shapeExpected(
                    shape,
                    pp,
                    main,
                    current,
                    previous,
                    parameters,
                    powers,
                    inverse,
                    result,
                );
                writePlanes(expected, rows, row, result);
            }
            try std.testing.expect(stwo_framework_polynomial_test_run(
                device,
                tree0.ptr,
                tree0.len,
                tree1.ptr,
                tree1.len,
                tree2.ptr,
                tree2.len,
                offsets.ptr,
                offsets.len,
                &profile_words,
                profile_words.len,
                relation_words.ptr,
                relation_words.len,
                power_words.ptr,
                power_words.len,
                output.ptr,
                output.len,
                @intCast(rows),
                inverses.ptr,
                @intCast(denominator_count),
                repetitions,
            ));
            // Includes unchanged guard tail, and all four output coordinates.
            try std.testing.expectEqualSlices(u32, expected, output);
            checked_rows += rows;
            dispatch_count += repetitions;
        }
    };
    std.debug.print("framework_polynomial_device: {s}, 27 cases, {d} completed GPU dispatches, {d} rows, all four coordinates matched\n", .{ @tagName(shape), dispatch_count, checked_rows });
}

test "Metal framework polynomial executes paired and final constraints over both circle halves" {
    try runShape(.pair_then_singleton);
}

test "Metal framework polynomial executes sole singleton with arity33 and reordered direct roots" {
    try runShape(.sole_singleton);
}

test "Metal framework polynomial executes sole pair with mixed arity33 and reordered direct roots" {
    try runShape(.sole_pair);
}

test "Metal framework polynomial executes final pair with mixed arity33 and reordered direct roots" {
    try runShape(.singleton_then_pair);
}

test "Metal framework polynomial executes independent prefixes with distinct claims and no direct roots" {
    try runShape(.independent_pair_then_singleton);
}
