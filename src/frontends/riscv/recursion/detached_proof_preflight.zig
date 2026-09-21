//! Decoder allocation geometry derived solely from admitted verifier components.
//! Shared by detached child and parent protocols; no proof-dependent lengths
//! participate in these bounds.
const std = @import("std");
const core = @import("stwo_core");
const Hasher = @import("poseidon2_channel.zig").MerkleHasher;
const postcard = @import("interop_postcard");
const TREE_COUNT = 3;

pub fn shape(allocator: std.mem.Allocator, admitted: core.air.components.Components, config: core.pcs.PcsConfig, max_proof_bytes: usize) !postcard.proof_preflight.Shape {
    const composition_split = try admitted.compositionLogSplit();
    const composition_log = core.verifier_types.compositionMaskLogSize(admitted.compositionLogDegreeBound(), composition_split) orelse
        return error.SegmentDetachedPreflightShapeMismatch;
    const composition_columns = core.verifier_types.compositionColumnCount(composition_split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse
        return error.SegmentDetachedPreflightShapeMismatch;
    var logs = try admitted.columnLogSizes(allocator);
    defer logs.deinitDeep(allocator);
    const point = core.circle.secureFieldPointFromRandomSeed(core.fields.qm31.QM31.one());
    var masks = try admitted.maskPoints(allocator, point, composition_log, false);
    defer masks.deinitDeep(allocator);
    if (logs.items.len != TREE_COUNT or masks.items.len != TREE_COUNT)
        return error.SegmentDetachedPreflightShapeMismatch;
    var tree_columns: [TREE_COUNT + 1]u32 = undefined;
    var sample_width_limits: [TREE_COUNT + 1]u32 = @splat(1);
    var max_column_log_size = composition_log;
    for (logs.items, masks.items, 0..) |tree_logs, tree_masks, tree| {
        if (tree_logs.len != tree_masks.len) return error.SegmentDetachedPreflightShapeMismatch;
        tree_columns[tree] = std.math.cast(u32, tree_logs.len) orelse return error.ArithmeticOverflow;
        for (tree_logs, tree_masks) |log, mask| {
            max_column_log_size = @max(max_column_log_size, log);
            sample_width_limits[tree] = @max(sample_width_limits[tree], std.math.cast(u32, mask.len) orelse return error.ArithmeticOverflow);
        }
    }
    tree_columns[TREE_COUNT] = std.math.cast(u32, composition_columns) orelse return error.ArithmeticOverflow;
    return .{
        .config = .{
            .pow_bits = config.pow_bits,
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .n_queries = config.fri_config.n_queries,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .fold_step = config.fri_config.fold_step,
            .lifting_log_size = config.lifting_log_size,
        },
        .tree_columns = tree_columns,
        .max_column_log_size = max_column_log_size,
        .sample_width_limits = sample_width_limits,
        .hash_size = @sizeOf(Hasher.Hash),
        .hash_encoding = .canonical_m31_words,
        .max_wire_bytes = max_proof_bytes,
    };
}
