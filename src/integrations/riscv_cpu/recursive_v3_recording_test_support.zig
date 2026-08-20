//! Shared geometry-only capture support for finalized V3 recorder tests.
//!
//! The sampled values are synthetic, but the manifest geometry is always
//! derived from a validated real component cohort.  This helper is test-only:
//! it supplies layout material to the recorder and is never a proof or
//! verifier authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const recursion = frontend.recursion;
const binary_driver = integration.recursive_binary_outer;
const capture_layout = recursion.recursion_air_composition_circuit_v3
    .capture_layout_v3;

const FRI_LOG_BLOWUP: u32 = 1;
const COMPOSITION_COLUMN_COUNT: usize = 8;
const COMPOSITION_LOG_SPLIT: u32 =
    stwo_core.verifier_types.COMPOSITION_LOG_SPLIT;

pub fn syntheticCapture(
    allocator: std.mem.Allocator,
    manifest: anytype,
    seed: u32,
) !binary_driver.OuterProofCapture {
    const column_counts = [capture_layout.TREE_COUNT]usize{
        manifest.total_preprocessed_columns,
        manifest.total_main_columns,
        manifest.total_interaction_columns,
        COMPOSITION_COLUMN_COUNT,
    };
    const commitments = try allocator.alloc(
        recursion.engine.Hasher.Hash,
        capture_layout.TREE_COUNT,
    );
    for (commitments, 0..) |*commitment, index|
        commitment.* = nativeDigest(seed + @as(u32, @intCast(10 * index)));

    const points = try allocator.alloc(
        [][]CirclePointQM31,
        capture_layout.TREE_COUNT,
    );
    const logs = try allocator.alloc([]u32, capture_layout.TREE_COUNT);
    var sampled_value_count: usize = 0;
    const composition_log_size = deriveCompositionLogSize(manifest);
    for (column_counts, 0..) |column_count, tree| {
        points[tree] = try allocator.alloc([]CirclePointQM31, column_count);
        logs[tree] = try allocator.alloc(u32, column_count);
        for (points[tree], 0..) |*column_points, column_index| {
            const count = if (tree == capture_layout.INTERACTION_TREE_INDEX)
                interactionSamples(manifest, column_index)
            else
                1;
            column_points.* = try allocator.alloc(CirclePointQM31, count);
            @memset(column_points.*, CirclePointQM31.zero());
            sampled_value_count += count;
            logs[tree][column_index] = if (tree ==
                capture_layout.COMPOSITION_TREE_INDEX)
                composition_log_size - COMPOSITION_LOG_SPLIT + FRI_LOG_BLOWUP
            else
                traceColumnLog(manifest, tree, column_index) + FRI_LOG_BLOWUP;
        }
    }
    const sampled_values = try allocator.alloc(QM31, sampled_value_count);
    for (sampled_values, 0..) |*value, index|
        value.* = felt(seed + 100 + @as(u32, @intCast(index % 10_000)));

    return .{
        .queries = .{
            .raw = try allocator.alloc(usize, 0),
            .unique = try allocator.alloc(usize, 0),
        },
        .commitments = commitments,
        .column_log_sizes = logs,
        .sampled_points = points,
        .sampled_values = sampled_values,
        .queried_values = try allocator.alloc(M31, 0),
        .deep_answers = try allocator.alloc(QM31, 0),
        .trace_paths = try allocator.alloc(
            stwo_core.vcs_lifted.verifier.MerklePathCapture(
                recursion.engine.Hasher,
            ),
            0,
        ),
        .fri = .{ .layers = try allocator.alloc(
            stwo_core.fri.FriLayerQueryCapture(recursion.engine.Hasher),
            0,
        ) },
        .last_layer_coefficients = try allocator.alloc(QM31, 0),
        .proof_of_work = seed,
        .composition_randomness = felt(seed + 17),
        .oods_seed = felt(seed + 19),
        .deep_randomness = felt(seed + 23),
    };
}

pub fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn interactionSamples(manifest: anytype, column: usize) usize {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = placement.interaction_offset;
        const end = start + placement.geometry.interaction_columns;
        if (column >= start and column < end) {
            if (row == binary_driver.POSEIDON_PROVIDER_ROW) return 2;
            return if (column >= end - 4) 2 else 1;
        }
    }
    unreachable;
}

fn traceColumnLog(manifest: anytype, tree: usize, column: usize) u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const range = switch (tree) {
            capture_layout.PREPROCESSED_TREE_INDEX => .{
                placement.preprocessed_offset,
                placement.geometry.preprocessed_columns,
            },
            capture_layout.MAIN_TREE_INDEX => .{
                placement.main_offset,
                placement.geometry.main_columns,
            },
            capture_layout.INTERACTION_TREE_INDEX => .{
                placement.interaction_offset,
                placement.geometry.interaction_columns,
            },
            else => unreachable,
        };
        const start: usize = range[0];
        const end = start + range[1];
        if (column >= start and column < end)
            return placement.geometry.log_size;
    }
    unreachable;
}

fn deriveCompositionLogSize(manifest: anytype) u32 {
    var result: u32 = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        const quotient_blowup = @max(
            @as(u32, 1),
            std.math.log2_int_ceil(
                u32,
                geometry.protocol_constraint_degree - 1,
            ),
        );
        result = @max(result, geometry.log_size + quotient_blowup);
    }
    return result;
}

fn felt(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
