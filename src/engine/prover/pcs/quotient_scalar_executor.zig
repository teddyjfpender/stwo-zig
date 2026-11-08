//! Scalar lazy-quotient row execution with stack-chunked batch inversion
//! and quad-lane finalize.
//!
//! Domains below the heap-batched threshold (see
//! `quotient_row_executor.shouldBatchDomain`) evaluate quotients through
//! these scalar paths. Rows are processed in 32-row stack chunks: domain
//! points are generated (incremental coset walk), denominators prepared and
//! Montgomery-batch-inverted on the stack, and each quad of rows is
//! finalized in packed lanes. Every arithmetic step is the same exact field
//! operation as the per-row path, so outputs are byte-identical.

const std = @import("std");
const circle = @import("stwo_core").circle;
const cm31 = @import("stwo_core").fields.cm31;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const constraints = @import("stwo_core").constraints;
const tile_sink = @import("quotient_tile_sink.zig");
const domain_walk = @import("quotient_domain_walk.zig");
const row_executor = @import("quotient_row_executor.zig");

const CirclePointM31 = circle.CirclePointM31;
const CM31 = cm31.CM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const MaterializedWork = row_executor.MaterializedWork;
const StreamingWork = row_executor.StreamingWork;
const writeQuotientRow = row_executor.writeQuotientRow;
const accumulateStreamingNumerators = row_executor.accumulateStreamingNumerators;
const emitCompletedTile = row_executor.emitCompletedTile;

/// Rows per stack-resident inversion chunk in the scalar row paths.
/// 32 rows amortize one Montgomery batch inversion across the chunk
/// (~3 CM31 multiplies per row plus one inversion) instead of one full
/// inversion per row, without any heap allocation: the buffers live on the
/// stack, so peak RSS matches the old per-row path.
const SCALAR_INVERSION_CHUNK_ROWS: usize = 32;
const SCALAR_INVERSION_MAX_BATCHES: usize = 16;

const ScalarInversionChunk = struct {
    points: [SCALAR_INVERSION_CHUNK_ROWS]CirclePointM31,
    denominators: [SCALAR_INVERSION_CHUNK_ROWS * SCALAR_INVERSION_MAX_BATCHES]CM31,
    inverses: [SCALAR_INVERSION_CHUNK_ROWS * SCALAR_INVERSION_MAX_BATCHES]CM31,
};

/// Karatsuba CM31 multiply over four packed rows. Identical field
/// operations to the scalar CM31.mul, one row per lane.
inline fn mulCM31Vec4(
    lhs_re: m31.Vec4u32,
    lhs_im: m31.Vec4u32,
    rhs_re: m31.Vec4u32,
    rhs_im: m31.Vec4u32,
) struct { re: m31.Vec4u32, im: m31.Vec4u32 } {
    const ac = m31.mulVec4(lhs_re, rhs_re);
    const bd = m31.mulVec4(lhs_im, rhs_im);
    const cross = m31.mulVec4(
        m31.addVec4(lhs_re, lhs_im),
        m31.addVec4(rhs_re, rhs_im),
    );
    return .{
        .re = m31.subVec4(ac, bd),
        .im = m31.subVec4(m31.subVec4(cross, ac), bd),
    };
}

/// Finalizes quotients for four rows in packed lanes, reading staged
/// per-row QM31 numerators. Same exact field operations as
/// `quotients.finalizeRowQuotients` per row, so outputs are byte-identical
/// to the scalar writeQuotientRow calls it replaces.
fn finalizeQuadVec4(
    out_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    output_position: usize,
    quotient_constants: *const quotients.QuotientConstants,
    ys: m31.Vec4u32,
    staged_numerators: []const [m31.VEC_WIDTH]QM31,
    staged_inverses: []const [m31.VEC_WIDTH]CM31,
) void {
    var acc: [qm31.SECURE_EXTENSION_DEGREE]m31.Vec4u32 = @splat(@splat(0));
    for (quotient_constants.batch_linear_terms, 0..) |linear_term, batch| {
        const a_coords = linear_term.sum_a.toM31Array();
        const b_coords = linear_term.sum_b.toM31Array();
        var diff: [qm31.SECURE_EXTENSION_DEGREE]m31.Vec4u32 = undefined;
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            const lt = m31.addVec4(
                m31.mulVec4(@as(m31.Vec4u32, @splat(a_coords[coordinate].v)), ys),
                @as(m31.Vec4u32, @splat(b_coords[coordinate].v)),
            );
            var nums: [m31.VEC_WIDTH]u32 = undefined;
            inline for (0..m31.VEC_WIDTH) |lane| {
                nums[lane] = staged_numerators[batch][lane].toM31Array()[coordinate].v;
            }
            diff[coordinate] = m31.subVec4(nums, lt);
        }
        var inv_re: [m31.VEC_WIDTH]u32 = undefined;
        var inv_im: [m31.VEC_WIDTH]u32 = undefined;
        inline for (0..m31.VEC_WIDTH) |lane| {
            inv_re[lane] = staged_inverses[batch][lane].a.v;
            inv_im[lane] = staged_inverses[batch][lane].b.v;
        }
        const q0 = mulCM31Vec4(diff[0], diff[1], inv_re, inv_im);
        const q1 = mulCM31Vec4(diff[2], diff[3], inv_re, inv_im);
        acc[0] = m31.addVec4(acc[0], q0.re);
        acc[1] = m31.addVec4(acc[1], q0.im);
        acc[2] = m31.addVec4(acc[2], q1.re);
        acc[3] = m31.addVec4(acc[3], q1.im);
    }
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        m31.storeVec4(out_columns[coordinate][output_position..].ptr, acc[coordinate]);
    }
}

pub fn executeMaterialized(item: *const MaterializedWork) !void {
    const workspace = item.workspace;
    const batch_count = workspace.sample_point_components.len;
    if (batch_count > SCALAR_INVERSION_MAX_BATCHES) {
        return executeMaterializedScalarPerRow(item);
    }
    var walk = domain_walk.BitReversedCosetWalk.init(
        item.domain,
        item.lifting_log_size,
        item.start,
    );
    var chunk: ScalarInversionChunk = undefined;
    var position = item.start;
    while (position < item.end) {
        const row_count = @min(SCALAR_INVERSION_CHUNK_ROWS, item.end - position);
        for (0..row_count) |row| {
            chunk.points[row] = walk.next();
        }
        try workspace.prepareDenominatorInversesForRows(
            chunk.points[0..row_count],
            chunk.denominators[0 .. row_count * batch_count],
            chunk.inverses[0 .. row_count * batch_count],
        );
        var row: usize = 0;
        while (row + m31.VEC_WIDTH <= row_count) : (row += m31.VEC_WIDTH) {
            var staged_num: [SCALAR_INVERSION_MAX_BATCHES][m31.VEC_WIDTH]QM31 = undefined;
            var staged_inv: [SCALAR_INVERSION_MAX_BATCHES][m31.VEC_WIDTH]CM31 = undefined;
            var ys: [m31.VEC_WIDTH]M31 = undefined;
            inline for (0..m31.VEC_WIDTH) |lane| {
                const r = row + lane;
                ys[lane] = chunk.points[r].y;
                workspace.resetNumerators();
                for (item.lifted_columns, item.contribution_plan_ranges) |lifted_column, contribution_range| {
                    const base_value = lifted_column[position + r];
                    for (item.contributions[contribution_range.start..][0..contribution_range.len]) |contribution| {
                        workspace.batch_numerators[contribution.batch_index] =
                            workspace.batch_numerators[contribution.batch_index].add(
                                contribution.value_coeff.mulM31(base_value),
                            );
                    }
                }
                for (0..batch_count) |batch| {
                    staged_num[batch][lane] = workspace.batch_numerators[batch];
                    staged_inv[batch][lane] = chunk.inverses[r * batch_count + batch];
                }
            }
            finalizeQuadVec4(
                item.out_columns,
                position + row,
                item.quotient_constants,
                m31.loadVec4(&ys),
                staged_num[0..batch_count],
                staged_inv[0..batch_count],
            );
        }
        while (row < row_count) : (row += 1) {
            const domain_point = chunk.points[row];
            workspace.resetNumerators();
            for (item.lifted_columns, item.contribution_plan_ranges) |lifted_column, contribution_range| {
                const base_value = lifted_column[position + row];
                for (item.contributions[contribution_range.start..][0..contribution_range.len]) |contribution| {
                    workspace.batch_numerators[contribution.batch_index] =
                        workspace.batch_numerators[contribution.batch_index].add(
                            contribution.value_coeff.mulM31(base_value),
                        );
                }
            }
            try writeQuotientRow(
                item.out_columns,
                position + row,
                item.quotient_constants,
                domain_point.y,
                workspace.batch_numerators,
                chunk.inverses[row * batch_count ..][0..batch_count],
            );
        }
        position += row_count;
    }
}

fn executeMaterializedScalarPerRow(item: *const MaterializedWork) !void {
    const workspace = item.workspace;
    var walk = domain_walk.BitReversedCosetWalk.init(
        item.domain,
        item.lifting_log_size,
        item.start,
    );
    for (item.start..item.end) |position| {
        const domain_point = walk.next();
        try workspace.beginRow(domain_point);
        for (item.lifted_columns, item.contribution_plan_ranges) |lifted_column, contribution_range| {
            const base_value = lifted_column[position];
            for (item.contributions[contribution_range.start..][0..contribution_range.len]) |contribution| {
                workspace.batch_numerators[contribution.batch_index] =
                    workspace.batch_numerators[contribution.batch_index].add(
                        contribution.value_coeff.mulM31(base_value),
                    );
            }
        }
        try writeQuotientRow(
            item.out_columns,
            position,
            item.quotient_constants,
            domain_point.y,
            workspace.batch_numerators,
            workspace.denominator_inverses,
        );
    }
}

pub fn executeStreaming(item: *StreamingWork) !void {
    const workspace = item.workspace;
    const batch_count = workspace.sample_point_components.len;
    if (batch_count > SCALAR_INVERSION_MAX_BATCHES) {
        return executeStreamingScalarPerRow(item);
    }
    var walk = domain_walk.BitReversedCosetWalk.init(
        item.domain,
        item.lifting_log_size,
        item.start,
    );
    var chunk: ScalarInversionChunk = undefined;
    var tile_start = item.start;
    while (tile_start < item.end) {
        const tile_end = @min(item.end, tile_start + tile_sink.DEFAULT_TILE_ROWS);
        var position = tile_start;
        while (position < tile_end) {
            const row_count = @min(SCALAR_INVERSION_CHUNK_ROWS, tile_end - position);
            for (0..row_count) |row| {
                chunk.points[row] = walk.next();
            }
            try workspace.prepareDenominatorInversesForRows(
                chunk.points[0..row_count],
                chunk.denominators[0 .. row_count * batch_count],
                chunk.inverses[0 .. row_count * batch_count],
            );
            var row: usize = 0;
            while (row + m31.VEC_WIDTH <= row_count) : (row += m31.VEC_WIDTH) {
                var staged_num: [SCALAR_INVERSION_MAX_BATCHES][m31.VEC_WIDTH]QM31 = undefined;
                var staged_inv: [SCALAR_INVERSION_MAX_BATCHES][m31.VEC_WIDTH]CM31 = undefined;
                var ys: [m31.VEC_WIDTH]M31 = undefined;
                inline for (0..m31.VEC_WIDTH) |lane| {
                    const r = row + lane;
                    ys[lane] = chunk.points[r].y;
                    workspace.resetNumerators();
                    accumulateStreamingNumerators(workspace, item.combined_views, position + r);
                    for (0..batch_count) |batch| {
                        staged_num[batch][lane] = workspace.batch_numerators[batch];
                        staged_inv[batch][lane] = chunk.inverses[r * batch_count + batch];
                    }
                }
                finalizeQuadVec4(
                    item.out_columns,
                    position + row - item.output_start,
                    item.quotient_constants,
                    m31.loadVec4(&ys),
                    staged_num[0..batch_count],
                    staged_inv[0..batch_count],
                );
            }
            while (row < row_count) : (row += 1) {
                const domain_point = chunk.points[row];
                workspace.resetNumerators();
                accumulateStreamingNumerators(workspace, item.combined_views, position + row);
                try writeQuotientRow(
                    item.out_columns,
                    position + row - item.output_start,
                    item.quotient_constants,
                    domain_point.y,
                    workspace.batch_numerators,
                    chunk.inverses[row * batch_count ..][0..batch_count],
                );
            }
            position += row_count;
        }
        try emitCompletedTile(item, tile_start, tile_end);
        tile_start = tile_end;
    }
}

fn executeStreamingScalarPerRow(item: *StreamingWork) !void {
    const workspace = item.workspace;
    var tile_start = item.start;
    var walk = domain_walk.BitReversedCosetWalk.init(
        item.domain,
        item.lifting_log_size,
        item.start,
    );
    while (tile_start < item.end) {
        const tile_end = @min(item.end, tile_start + tile_sink.DEFAULT_TILE_ROWS);
        for (tile_start..tile_end) |position| {
            const domain_point = walk.next();
            try workspace.beginRow(domain_point);
            accumulateStreamingNumerators(workspace, item.combined_views, position);
            try writeQuotientRow(
                item.out_columns,
                position - item.output_start,
                item.quotient_constants,
                domain_point.y,
                workspace.batch_numerators,
                workspace.denominator_inverses,
            );
        }
        try emitCompletedTile(item, tile_start, tile_end);
        tile_start = tile_end;
    }
}

test "quad finalize matches scalar finalizeRowQuotients for all batch counts" {
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

        var out_columns: [qm31.SECURE_EXTENSION_DEGREE][m31.VEC_WIDTH]M31 = undefined;
        var outs: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |c| outs[c] = out_columns[c][0..];
        var staged_num: [SCALAR_INVERSION_MAX_BATCHES][m31.VEC_WIDTH]QM31 = undefined;
        var staged_inv: [SCALAR_INVERSION_MAX_BATCHES][m31.VEC_WIDTH]CM31 = undefined;
        var ys: [m31.VEC_WIDTH]M31 = undefined;
        for (0..batch_count) |batch| {
            for (0..m31.VEC_WIDTH) |lane| {
                staged_num[batch][lane] = QM31.fromM31(nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state));
                staged_inv[batch][lane] = CM31.fromM31(nextM31(&rng_state), nextM31(&rng_state));
            }
        }
        for (0..m31.VEC_WIDTH) |lane| ys[lane] = nextM31(&rng_state);

        finalizeQuadVec4(
            outs,
            0,
            &constants,
            m31.loadVec4(&ys),
            staged_num[0..batch_count],
            staged_inv[0..batch_count],
        );
        for (0..m31.VEC_WIDTH) |lane| {
            var numerators: [3]QM31 = undefined;
            var inverses: [3]CM31 = undefined;
            for (0..batch_count) |batch| {
                numerators[batch] = staged_num[batch][lane];
                inverses[batch] = staged_inv[batch][lane];
            }
            const scalar_q = try quotients.finalizeRowQuotients(
                &constants,
                ys[lane],
                numerators[0..batch_count],
                inverses[0..batch_count],
            );
            const scalar_coords = scalar_q.toM31Array();
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                try std.testing.expectEqual(
                    scalar_coords[coordinate].v,
                    out_columns[coordinate][lane].v,
                );
            }
        }
    }
}
