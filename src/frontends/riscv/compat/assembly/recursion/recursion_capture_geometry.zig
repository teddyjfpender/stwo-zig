//! Manifest-derived column, sample and quotient geometry admission.

const Root = @import("recursion_air_composition_capture_layout.zig");
const std = @import("std");
const stwo_core = @import("stwo_core");
const universal_manifest_mod = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;
const qm31 = stwo_core.fields.qm31;
const verifier_types = stwo_core.verifier_types;
const TREE_COUNT = Root.TREE_COUNT;
const COMPOSITION_TREE_INDEX = Root.COMPOSITION_TREE_INDEX;
const Error = Root.Error;

pub fn deriveNormalizedCompositionLogSize(manifest: anytype, split: u32) Error!u32 {
    var result: u32 = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        if (geometry.protocol_constraint_degree < 2)
            return error.InvalidCompositionGeometry;
        const local_split = @max(@as(u32, 1), std.math.log2_int_ceil(u32, geometry.protocol_constraint_degree - 1));
        if (local_split > split) return error.InvalidCompositionGeometry;
        const bound = std.math.add(u32, geometry.log_size, split) catch return error.ArithmeticOverflow;
        if (bound >= stwo_core.circle.M31_CIRCLE_LOG_ORDER)
            return error.InvalidCompositionGeometry;
        result = @max(result, bound);
    }
    return result;
}

pub fn deriveCompositionLogSize(manifest: anytype) Error!u32 {
    var composition_log_size: u32 = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        const degree_minus_one: u32 = geometry.protocol_constraint_degree - 1;
        const quotient_blowup: u32 = @max(
            1,
            std.math.log2_int_ceil(u32, degree_minus_one),
        );
        composition_log_size = @max(
            composition_log_size,
            std.math.add(u32, geometry.log_size, quotient_blowup) catch
                return error.ArithmeticOverflow,
        );
    }
    return composition_log_size;
}

pub fn expectedTreeColumnCounts(manifest: anytype, split: u32) Error![TREE_COUNT]usize {
    return .{
        @intCast(manifest.total_preprocessed_columns),
        @intCast(manifest.total_main_columns),
        @intCast(manifest.total_interaction_columns),
        verifier_types.compositionColumnCount(split, qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidCompositionGeometry,
    };
}

pub fn expectedSampleCount(
    manifest: anytype,
    poseidon_roster_row: usize,
    tree: usize,
    column: usize,
) Error!usize {
    if (tree != universal_manifest_mod.INTERACTION_TREE_INDEX) return 1;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = @intCast(placement.interaction_offset);
        const end = start + placement.geometry.interaction_columns;
        if (column >= start and column < end) {
            if (@as(usize, row) == poseidon_roster_row) return 2;
            const final_start = end - qm31.SECURE_EXTENSION_DEGREE;
            return if (column >= final_start) 2 else 1;
        }
    }
    return error.InvalidSampleGeometry;
}

pub fn deriveFriLogBlowup(manifest: anytype, logs: anytype) Error!u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const geometry = placement.geometry;
        const candidates = [_]struct { tree: usize, start: u32, count: u16 }{
            .{ .tree = universal_manifest_mod.PREPROCESSED_TREE_INDEX, .start = placement.preprocessed_offset, .count = geometry.preprocessed_columns },
            .{ .tree = universal_manifest_mod.MAIN_TREE_INDEX, .start = placement.main_offset, .count = geometry.main_columns },
            .{ .tree = universal_manifest_mod.INTERACTION_TREE_INDEX, .start = placement.interaction_offset, .count = geometry.interaction_columns },
        };
        for (candidates) |candidate| {
            if (candidate.count == 0) continue;
            const observed = logs[candidate.tree][candidate.start];
            if (observed < geometry.log_size)
                return error.InvalidTraceLogGeometry;
            return observed - geometry.log_size;
        }
    }
    return error.InvalidTraceLogGeometry;
}

pub fn validateColumnLogs(
    manifest: anytype,
    logs: anytype,
    composition_chunk_log_size: u32,
    fri_log_blowup: u32,
) Error!void {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const geometry = placement.geometry;
        const expected = std.math.add(
            u32,
            geometry.log_size,
            fri_log_blowup,
        ) catch return error.ArithmeticOverflow;
        const ranges = [_]struct { tree: usize, start: u32, count: u16 }{
            .{ .tree = universal_manifest_mod.PREPROCESSED_TREE_INDEX, .start = placement.preprocessed_offset, .count = geometry.preprocessed_columns },
            .{ .tree = universal_manifest_mod.MAIN_TREE_INDEX, .start = placement.main_offset, .count = geometry.main_columns },
            .{ .tree = universal_manifest_mod.INTERACTION_TREE_INDEX, .start = placement.interaction_offset, .count = geometry.interaction_columns },
        };
        for (ranges) |range| for (logs[range.tree][range.start..][0..range.count]) |
            actual,
        | if (actual != expected) return error.InvalidTraceLogGeometry;
    }
    const expected_composition = std.math.add(
        u32,
        composition_chunk_log_size,
        fri_log_blowup,
    ) catch return error.ArithmeticOverflow;
    for (logs[COMPOSITION_TREE_INDEX]) |actual|
        if (actual != expected_composition)
            return error.InvalidTraceLogGeometry;
}
