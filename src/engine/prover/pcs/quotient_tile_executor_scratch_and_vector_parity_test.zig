//! scratch and vector parity contract cases for quotient_tile_executor.
//! Bounded CPU execution for direct contribution-to-quotient row tiles.

const std = @import("std");
const cm31 = @import("stwo_core").fields.cm31;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const tile_sink = @import("quotient_tile_sink.zig");
const constraints = @import("stwo_core").constraints;

const CM31 = cm31.CM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;

const Owner = @import("quotient_tile_executor.zig");
const shouldUseBoundedInput = Owner.shouldUseBoundedInput;
const MAX_SCRATCH_BYTES_PER_WORKER = Owner.MAX_SCRATCH_BYTES_PER_WORKER;
const Scratch = Owner.Scratch;
const rowCapacityForBatchCount = Owner.rowCapacityForBatchCount;
const accumulateLiftedRuns = Owner.accumulateLiftedRuns;
const finalizeGroupVec4 = Owner.finalizeGroupVec4;

test "quotient tile scratch is bounded and rejects overflowing geometry" {
    var scratch = try Scratch.init(std.testing.allocator, 3, tile_sink.DEFAULT_TILE_ROWS);
    defer scratch.deinit(std.testing.allocator);
    try std.testing.expect(scratch.row_capacity <= tile_sink.DEFAULT_TILE_ROWS);
    try std.testing.expect(scratch.retainedBytes() <= MAX_SCRATCH_BYTES_PER_WORKER);
    try std.testing.expect(scratch.numeratorBytes() > 0);
    try std.testing.expectError(
        error.ScratchMemoryLimitExceeded,
        rowCapacityForBatchCount(MAX_SCRATCH_BYTES_PER_WORKER, 1),
    );
    try std.testing.expectError(
        error.ScratchSizeOverflow,
        rowCapacityForBatchCount(std.math.maxInt(usize), 1),
    );
}

test "quotient tile input policy selects only the measured batched domain" {
    try std.testing.expect(!shouldUseBoundedInput(12));
    try std.testing.expect(shouldUseBoundedInput(13));
    try std.testing.expect(shouldUseBoundedInput(14));
}

test "lifted run accumulation matches scalar lifting across boundaries" {
    var scratch = try Scratch.init(std.testing.allocator, 1, 37);
    defer scratch.deinit(std.testing.allocator);
    var values: [64]M31 = undefined;
    for (&values, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i * 97 + 11));
    const coefficients = [qm31.SECURE_EXTENSION_DEGREE]M31{
        M31.fromCanonical(3), M31.fromCanonical(5),
        M31.fromCanonical(7), M31.fromCanonical(11),
    };
    const Case = struct { shift: u6, start: usize, len: usize };
    for ([_]Case{
        .{ .shift = 2, .start = 0, .len = 37 },
        .{ .shift = 3, .start = 3, .len = 31 },
        .{ .shift = 7, .start = 5, .len = 29 },
    }) |case| {
        @memset(scratch.numerators, M31.zero());
        accumulateLiftedRuns(&scratch, &values, case.shift, case.start, case.len, 0, coefficients);
        for (0..case.len) |row| {
            const position = case.start + row;
            const source_index = ((position >> case.shift) << 1) + (position & 1);
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                try std.testing.expectEqual(
                    values[source_index].mul(coefficients[coordinate]).v,
                    scratch.numerator(0, coordinate, row).v,
                );
            }
        }
    }
}

test "packed finalize matches scalar finalizeRowQuotients for all batch counts" {
    const allocator = std.testing.allocator;
    var rng_state: u64 = 0x9e3779b97f4a7c15;
    const nextM31 = struct {
        fn next(state: *u64) M31 {
            state.* ^= state.* << 13;
            state.* ^= state.* >> 7;
            state.* ^= state.* << 17;
            return M31.fromCanonical(@intCast(state.* % 2147483647));
        }
    }.next;

    for ([_]usize{ 1, 2, 3 }) |batch_count| {
        const line_coeffs = try allocator.alloc([]constraints.LineCoeffs, batch_count);
        defer allocator.free(line_coeffs);
        for (line_coeffs) |*lc| lc.* = &[_]constraints.LineCoeffs{};
        var constants: quotients.QuotientConstants = undefined;
        constants.line_coeffs = line_coeffs;
        constants.batch_linear_terms = try allocator.alloc(
            std.meta.Child(@TypeOf(constants.batch_linear_terms)),
            batch_count,
        );
        defer allocator.free(constants.batch_linear_terms);
        for (constants.batch_linear_terms) |*term| {
            term.* = .{
                .sum_a = QM31.fromM31(nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state)),
                .sum_b = QM31.fromM31(nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state)),
            };
        }

        const row_capacity: usize = 8;
        var scratch = try Scratch.init(allocator, batch_count, row_capacity);
        defer scratch.deinit(allocator);
        for (scratch.numerators) |*v| v.* = nextM31(&rng_state);

        var ys: [row_capacity]M31 = undefined;
        var inverses: [row_capacity][]CM31 = undefined;
        var inverse_storage: [row_capacity * 3]CM31 = undefined;
        for (0..row_capacity) |row| {
            ys[row] = nextM31(&rng_state);
            inverses[row] = inverse_storage[row * batch_count ..][0..batch_count];
            for (0..batch_count) |batch| {
                inverses[row][batch] = CM31.fromM31(nextM31(&rng_state), nextM31(&rng_state));
            }
        }
        scratch.row_scratch.prepared_rows = row_capacity;
        scratch.row_scratch.inverse_layout = .batch_major;
        for (0..batch_count) |batch| {
            for (0..row_capacity) |row| {
                scratch.row_scratch.denominator_inverses[batch * row_capacity + row] =
                    inverses[row][batch];
            }
        }

        for ([_]usize{ 0, 4 }) |row| {
            const packed_q = finalizeGroupVec4(
                &constants,
                m31.loadVec4(ys[row..].ptr),
                &scratch,
                row,
            );
            inline for (0..m31.VEC_WIDTH) |lane| {
                var numerators: [3]QM31 = undefined;
                for (0..batch_count) |batch| {
                    numerators[batch] = QM31.fromM31(
                        scratch.numerator(batch, 0, row + lane).*,
                        scratch.numerator(batch, 1, row + lane).*,
                        scratch.numerator(batch, 2, row + lane).*,
                        scratch.numerator(batch, 3, row + lane).*,
                    );
                }
                const scalar_q = try quotients.finalizeRowQuotients(
                    &constants,
                    ys[row + lane],
                    numerators[0..batch_count],
                    inverses[row + lane],
                );
                const scalar_coords = scalar_q.toM31Array();
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    try std.testing.expectEqual(
                        scalar_coords[coordinate].v,
                        packed_q[coordinate][lane],
                    );
                }
            }
        }
    }
}
