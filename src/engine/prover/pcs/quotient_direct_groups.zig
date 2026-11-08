//! Four-column packed reduction for direct quotient contributions.

const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const row_executor = @import("quotient_row_executor.zig");

const M31 = m31.M31;

pub fn canAccumulate(
    column_views: []const row_executor.LiftingColumnView,
    contribution_ranges: []const row_executor.ColumnContributionRange,
    contributions: []const row_executor.ColumnContribution,
    start: usize,
) bool {
    if (start + 4 > column_views.len) return false;
    var batch: ?usize = null;
    for (start..start + 4) |index| {
        if (!column_views[index].is_direct) return false;
        const range = contribution_ranges[index];
        if (range.len != 1 or range.start >= contributions.len) return false;
        const contribution_batch = contributions[range.start].batch_index;
        if (batch) |expected| {
            if (contribution_batch != expected) return false;
        } else {
            batch = contribution_batch;
        }
    }
    return true;
}

/// Accumulates four direct columns with one modular reduction per coordinate.
/// The direct views are contiguous in output-row space; grouping changes only
/// the parenthesization of field addition, never contribution membership.
pub fn accumulate(
    numerators_storage: []M31,
    row_capacity: usize,
    views: [4]row_executor.LiftingColumnView,
    start: usize,
    row_count: usize,
    batch: usize,
    coefficients: [4][qm31.SECURE_EXTENSION_DEGREE]M31,
) void {
    var coefficient_vectors: [qm31.SECURE_EXTENSION_DEGREE][4]m31.PackedM31 = undefined;
    var numerator_planes: [qm31.SECURE_EXTENSION_DEGREE][*]M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        inline for (0..4) |term| {
            coefficient_vectors[coordinate][term] =
                m31.splatPacked(coefficients[term][coordinate]);
        }
        const plane = batch * qm31.SECURE_EXTENSION_DEGREE + coordinate;
        numerator_planes[coordinate] = numerators_storage.ptr + plane * row_capacity;
    }

    var row: usize = 0;
    while (row + m31.PACK_WIDTH <= row_count) : (row += m31.PACK_WIDTH) {
        var values: [4]m31.PackedM31 = undefined;
        inline for (0..4) |term| {
            values[term] = m31.loadPacked(views[term].values.ptr + start + row);
        }
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            const numerators = numerator_planes[coordinate] + row;
            m31.storePacked(
                numerators,
                m31.addPacked(
                    m31.loadPacked(numerators),
                    m31.dot4Packed(values, coefficient_vectors[coordinate]),
                ),
            );
        }
    }
    while (row < row_count) : (row += 1) {
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            const numerator = numerator_planes[coordinate] + row;
            var value = numerator[0];
            inline for (0..4) |term| {
                value = value.add(
                    views[term].values[start + row].mul(coefficients[term][coordinate]),
                );
            }
            numerator[0] = value;
        }
    }
}
