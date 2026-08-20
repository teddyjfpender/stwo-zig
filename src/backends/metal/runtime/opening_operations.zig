const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const protocol_mode = @import("protocol_mode.zig");

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const CommandEpoch = runtime.CommandEpoch;
const CommandEpochStats = runtime.CommandEpochStats;
const ArenaCopyRange = runtime.ArenaCopyRange;
const DecommitFriRoundParams = runtime.DecommitFriRoundParams;
const DecommitTraceGroupParams = runtime.DecommitTraceGroupParams;
const PipelineCacheStats = runtime.PipelineCacheStats;
const PreparedStateRange = runtime.PreparedStateRange;
const QuotientCoefficientTask = runtime.QuotientCoefficientTask;
const QuotientCoefficientTerm = runtime.QuotientCoefficientTerm;
const ArenaCopyPlan = runtime.ArenaCopyPlan;
const WitnessFeedPlan = runtime.WitnessFeedPlan;
const WitnessFeedBatchPlan = runtime.WitnessFeedBatchPlan;
const CircleLdePlan = runtime.CircleLdePlan;
const CircleIfftPlan = runtime.CircleIfftPlan;
const FixedTablePlan = runtime.FixedTablePlan;
const FixedTableBatchPlan = runtime.FixedTableBatchPlan;
const MerkleParentChainPlan = runtime.MerkleParentChainPlan;
const MerkleLeafPlan = runtime.MerkleLeafPlan;
const ResidentMerklePlan = runtime.ResidentMerklePlan;
const EcOpPlan = runtime.EcOpPlan;
const CompactLayout = runtime.CompactLayout;
const CompactPlan = runtime.CompactPlan;
const EvalLayout = runtime.EvalLayout;
const WitnessLayout = runtime.WitnessLayout;
const EvalLibrary = runtime.EvalLibrary;
const EvalPlan = runtime.EvalPlan;
const WitnessPlan = runtime.WitnessPlan;
const EvalBatchPlan = runtime.EvalBatchPlan;
const CompositionFinalizePlan = runtime.CompositionFinalizePlan;
const CompositionLdeOptions = runtime.CompositionLdeOptions;
const CompositionLdePlan = runtime.CompositionLdePlan;
const CompositionExtParamDescriptor = runtime.CompositionExtParamDescriptor;
const CompositionInputPlan = runtime.CompositionInputPlan;
const CompositionFrontPlan = runtime.CompositionFrontPlan;
const RelationPlan = runtime.RelationPlan;
const FriFoldPlan = runtime.FriFoldPlan;
const QuotientCombinePlan = runtime.QuotientCombinePlan;
const FriRoundPlan = runtime.FriRoundPlan;
const FriTreePlan = runtime.FriTreePlan;
const FriFinalPlan = runtime.FriFinalPlan;
const QuotientCommitResult = runtime.QuotientCommitResult;
const FriFoldCommitResult = runtime.FriFoldCommitResult;
const FriCircleFoldResult = runtime.FriCircleFoldResult;
const FriLineCascadeResult = runtime.FriLineCascadeResult;
const ResidentBuffer = runtime.ResidentBuffer;
const Tree = runtime.Tree;
const validDomainPrefixBytes = protocol_mode.validDomainPrefixBytes;
const resource_plans = @import("resource_plans.zig").ResourcePlans(MetalError);
const evalArguments = resource_plans.evalArguments;
pub fn foldFriCircle(
    self: *Runtime,
    source: [*]const u32,
    source_count: u32,
    inverse_y: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    alpha: [4]u32,
    destination: [*]u32,
) MetalError!f64 {
    return foldFriCircleInternal(
        self,
        source,
        source_count,
        inverse_y,
        domain_initial_index,
        domain_step_size,
        alpha,
        destination,
        null,
    );
}

pub fn foldFriCircleWithReceipt(
    self: *Runtime,
    source: [*]const u32,
    source_count: u32,
    inverse_y: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    alpha: [4]u32,
    destination: [*]u32,
) MetalError!FriCircleFoldResult {
    var inverse_generated = false;
    const gpu_ms = try foldFriCircleInternal(
        self,
        source,
        source_count,
        inverse_y,
        domain_initial_index,
        domain_step_size,
        alpha,
        destination,
        &inverse_generated,
    );
    return .{ .gpu_ms = gpu_ms, .inverse_generated = inverse_generated };
}

fn foldFriCircleInternal(
    self: *Runtime,
    source: [*]const u32,
    source_count: u32,
    inverse_y: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    alpha: [4]u32,
    destination: [*]u32,
    inverse_generated: ?*bool,
) MetalError!f64 {
    if (inverse_y) |values| {
        if (values.len != source_count / 2) return MetalError.InvalidColumns;
    }
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const inverse_ptr = if (inverse_y) |values| values.ptr else null;
    if (!ffi.stwo_zig_metal_fri_fold_circle(
        self.handle,
        source,
        source_count,
        inverse_ptr,
        domain_initial_index,
        domain_step_size,
        &alpha,
        destination,
        inverse_generated,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal FRI circle fold failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn foldFriLine(
    self: *Runtime,
    source: [*]const u32,
    source_count: u32,
    inverse_x: []const u32,
    alpha: [4]u32,
    destination: [*]u32,
) MetalError!f64 {
    if (inverse_x.len != source_count / 2) return MetalError.InvalidColumns;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_fri_fold_line(self.handle, source, source_count, inverse_x.ptr, &alpha, destination, &gpu_ms, &message, message.len)) {
        std.log.err("Metal FRI line fold failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

/// Folds a resident interleaved QM31 evaluation and commits its final
/// coordinate planes without an intermediate submission or host copy.
pub fn foldFriLineAndCommit(
    self: *Runtime,
    source: *anyopaque,
    source_count: u32,
    inverse_x: []const u32,
    alphas: []const [4]u32,
    destination: *anyopaque,
    coordinates: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!FriFoldCommitResult {
    if (source_count < 2 or alphas.len == 0 or alphas.len >= 31 or
        source_count & (source_count - 1) != 0 or
        !validDomainPrefixBytes(domain_prefix_bytes))
    {
        return MetalError.InvalidColumns;
    }
    const fold_count = std.math.cast(u32, alphas.len) orelse return MetalError.InvalidColumns;
    const destination_count = source_count >> @intCast(fold_count);
    if (destination_count == 0) return MetalError.InvalidColumns;
    var expected_inverse_count: u64 = 0;
    var count = source_count;
    for (0..alphas.len) |_| {
        count >>= 1;
        expected_inverse_count += count;
    }
    if (inverse_x.len != expected_inverse_count or inverse_x.len > std.math.maxInt(u32))
        return MetalError.InvalidColumns;

    var stats: CommandEpochStats = undefined;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const tree = ffi.stwo_zig_metal_fri_fold_line_and_commit(
        self.handle,
        source,
        source_count,
        inverse_x.ptr,
        @intCast(inverse_x.len),
        @ptrCast(alphas.ptr),
        fold_count,
        destination,
        coordinates,
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        &stats,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal FRI fold + commitment failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{
        .stats = stats,
        .tree = .{
            .handle = tree,
            .runtime_handle = self.handle,
            .log_size = std.math.log2_int(u32, destination_count),
        },
    };
}

pub fn prepareFriFold(
    self: *Runtime,
    source_offset_words: u32,
    inverse_offset_words: u32,
    alpha_offset_words: u32,
    destination_offset_words: u32,
    source_count: u32,
    circle: bool,
) MetalError!FriFoldPlan {
    if (source_count < 2 or source_count & 1 != 0) return MetalError.InvalidColumns;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_fri_fold_prepare(
        self.handle,
        source_offset_words,
        inverse_offset_words,
        alpha_offset_words,
        destination_offset_words,
        source_count,
        circle,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal FRI fold preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    };
    return .{ .handle = handle };
}

pub fn friFoldPrepared(self: *Runtime, arena: ResidentBuffer, plan: FriFoldPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_fri_fold_prepared(
        self.handle,
        arena.handle,
        plan.handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal prepared FRI fold failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn prepareQuotientCombine(
    self: *Runtime,
    partial_offsets: []const u32,
    partial_logs: []const u32,
    sample_offset: u32,
    linear_offset: u32,
    scratch_offset: u32,
    output_offset: u32,
    log_size: u32,
    initial_index: u32,
    step_size: u32,
) MetalError!QuotientCombinePlan {
    if (partial_logs.len == 0 or partial_offsets.len != partial_logs.len * 4 or log_size < 2 or log_size >= 31)
        return MetalError.QuotientFailed;
    for (partial_logs) |partial_log| if (partial_log > log_size) return MetalError.QuotientFailed;
    const row_count = @as(u32, 1) << @intCast(log_size);
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_quotient_combine_prepare(
        self.handle,
        partial_offsets.ptr,
        partial_logs.ptr,
        @intCast(partial_logs.len),
        sample_offset,
        linear_offset,
        scratch_offset,
        output_offset,
        row_count,
        log_size,
        initial_index,
        step_size,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal quotient-combine preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.QuotientFailed;
    };
    return .{ .handle = handle };
}

pub fn quotientCombinePrepared(self: *Runtime, arena: ResidentBuffer, plan: QuotientCombinePlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_quotient_combine_prepared(
        self.handle,
        arena.handle,
        plan.handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal prepared quotient combine failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.QuotientFailed;
    }
    return gpu_ms;
}

pub fn accumulateQuotientCoefficientsResident(
    self: *Runtime,
    arena: ResidentBuffer,
    terms: []const QuotientCoefficientTerm,
    tasks: []const QuotientCoefficientTask,
    row_starts: []const u32,
) MetalError!f64 {
    if (terms.len == 0 or tasks.len == 0 or row_starts.len != tasks.len + 1 or
        row_starts[0] != 0 or row_starts[row_starts.len - 1] == 0)
        return MetalError.QuotientFailed;
    const total_rows = row_starts[row_starts.len - 1];
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_quotient_coefficients_resident(
        self.handle,
        arena.handle,
        terms.ptr,
        @intCast(terms.len),
        tasks.ptr,
        @intCast(tasks.len),
        row_starts.ptr,
        total_rows,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal quotient coefficient accumulation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.QuotientFailed;
    }
    return gpu_ms;
}

pub fn prepareFriRound(
    self: *Runtime,
    twiddle_base: u32,
    twiddle_words: u32,
    input_base: u32,
    input_stride: u32,
    alpha_base: u32,
    output_base: u32,
    output_stride: u32,
    n: u32,
    fold_count: u32,
    first_circle: bool,
) MetalError!FriRoundPlan {
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_fri_round_prepare(
        self.handle,
        twiddle_base,
        twiddle_words,
        input_base,
        input_stride,
        alpha_base,
        output_base,
        output_stride,
        n,
        fold_count,
        first_circle,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal FRI round preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    };
    return .{ .handle = handle };
}

pub fn friRoundPrepared(self: *Runtime, arena: ResidentBuffer, plan: FriRoundPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_fri_round_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal prepared FRI round failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn prepareFriTree(
    self: *Runtime,
    evaluation_base: u32,
    coordinate_stride: u32,
    evaluation_size: u32,
    log_rows_per_leaf: u32,
    layer_offsets: []const u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!FriTreePlan {
    if (layer_offsets.len < 2) return MetalError.CommitmentFailed;
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_fri_tree_prepare(
        self.handle,
        evaluation_base,
        coordinate_stride,
        evaluation_size,
        log_rows_per_leaf,
        layer_offsets.ptr,
        @intCast(layer_offsets.len),
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal FRI tree preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle };
}

pub fn friTreePrepared(self: *Runtime, arena: ResidentBuffer, plan: FriTreePlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_fri_tree_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal prepared FRI tree failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn prepareFriFinal(
    self: *Runtime,
    evaluation_base: u32,
    coordinate_stride: u32,
    inverse_x: u32,
    coefficient_base: u32,
    degree_error: u32,
) MetalError!FriFinalPlan {
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_fri_final_prepare(
        self.handle,
        evaluation_base,
        coordinate_stride,
        inverse_x,
        coefficient_base,
        degree_error,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal FRI final preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    };
    return .{ .handle = handle };
}

pub fn friFinalPrepared(self: *Runtime, arena: ResidentBuffer, plan: FriFinalPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_fri_final_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal prepared FRI final failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn transcriptInit(self: *Runtime, arena: ResidentBuffer, state_base: u32) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_transcript_init, .{state_base});
}

pub fn transcriptMix(self: *Runtime, arena: ResidentBuffer, state_base: u32, source_base: u32, source_words: u32) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_transcript_mix(self.handle, arena.handle, state_base, source_base, source_words, &gpu_ms, &message, message.len)) {
        std.log.err("Metal transcript mix failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

fn transcriptCall(self: *Runtime, arena: ResidentBuffer, comptime call: anytype, args: anytype) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!@call(.auto, call, .{ self.handle, arena.handle } ++ args ++ .{ &gpu_ms, &message, message.len })) {
        std.log.err("Metal transcript operation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn transcriptDrawSecure(self: *Runtime, arena: ResidentBuffer, state_base: u32, destination_base: u32, felt_count: u32) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_transcript_draw_secure, .{ state_base, destination_base, felt_count });
}

pub fn transcriptDrawQueries(self: *Runtime, arena: ResidentBuffer, state_base: u32, destination_base: u32, log_domain_size: u32, query_count: u32) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_transcript_draw_queries, .{ state_base, destination_base, log_domain_size, query_count });
}

pub fn decommitNormalizeQueries(
    self: *Runtime,
    arena: ResidentBuffer,
    raw_base: u64,
    raw_count: u32,
    log_domain_size: u32,
    unique_base: u64,
    unique_count_base: u64,
    tree_count: u32,
    assembly_base: u64,
    assembly_capacity: u32,
) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_decommit_normalize_queries, .{
        raw_base, raw_count, log_domain_size, unique_base, unique_count_base, tree_count, assembly_base, assembly_capacity,
    });
}

pub fn decommitPrepareFriQueries(
    self: *Runtime,
    arena: ResidentBuffer,
    unique_base: u64,
    unique_count_base: u64,
    max_queries: u32,
    cumulative_fold: u32,
    fold_step: u32,
    packed_log: u32,
    tree_queries_base: u64,
    tree_count_base: u64,
    expanded_base: u64,
    expanded_count_base: u64,
    walk_base: u64,
    walk_count_base: u64,
) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_decommit_prepare_fri_queries, .{
        unique_base,       unique_count_base, max_queries,   cumulative_fold,     fold_step, packed_log,
        tree_queries_base, tree_count_base,   expanded_base, expanded_count_base, walk_base, walk_count_base,
    });
}

pub fn decommitPrepareTraceQueries(
    self: *Runtime,
    arena: ResidentBuffer,
    unique_base: u64,
    unique_count_base: u64,
    max_queries: u32,
    source_log: u32,
    tree_log: u32,
    leaf_log: u32,
    unretained: u32,
    mapped_base: u64,
    mapped_count_base: u64,
    walk_base: u64,
    walk_count_base: u64,
    leaves_base: u64,
    leaf_count_base: u64,
) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_decommit_prepare_trace_queries, .{
        unique_base, unique_count_base, max_queries, source_log,      tree_log,    leaf_log,        unretained,
        mapped_base, mapped_count_base, walk_base,   walk_count_base, leaves_base, leaf_count_base,
    });
}

pub fn decommitGatherTraceValues(
    self: *Runtime,
    arena: ResidentBuffer,
    column_offsets_base: u64,
    column_logs_base: u64,
    column_count: u32,
    lifting_log: u32,
    queries_base: u64,
    query_count_base: u64,
    max_queries: u32,
    first_column: u32,
    stride: u32,
    output_base: u64,
) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_decommit_gather_trace_values, .{
        column_offsets_base, column_logs_base, column_count, lifting_log, queries_base,
        query_count_base,    max_queries,      first_column, stride,      output_base,
    });
}

pub fn decommitGatherFriValues(
    self: *Runtime,
    arena: ResidentBuffer,
    coordinate_bases: u64,
    positions_base: u64,
    count_base: u64,
    max_positions: u32,
    values_base: u64,
) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_decommit_gather_fri_values, .{
        coordinate_bases, positions_base, count_base, max_positions, values_base,
    });
}

pub fn decommitAssembleFri(
    self: *Runtime,
    arena: ResidentBuffer,
    tree_index: u32,
    leaf_log: u32,
    tree_queries: u64,
    tree_count_at: u64,
    expanded: u64,
    expanded_count_at: u64,
    values: u64,
    walk: u64,
    scratch: u64,
    walk_count_at: u64,
    retained_offsets: u64,
    assembly: u64,
    capacity: u32,
) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_decommit_assemble_fri, .{
        tree_index, leaf_log, tree_queries, tree_count_at, expanded,         expanded_count_at,
        values,     walk,     scratch,      walk_count_at, retained_offsets, assembly,
        capacity,
    });
}

pub fn decommitFriRound(
    self: *Runtime,
    arena: ResidentBuffer,
    params: DecommitFriRoundParams,
) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_decommit_fri_round(
        self.handle,
        arena.handle,
        &params,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal decommit FRI round failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn decommitSparseParent(
    self: *Runtime,
    arena: ResidentBuffer,
    child_indices: u64,
    child_hashes: u64,
    child_count_at: u64,
    max_child_count: u32,
    parent_indices: u64,
    parent_hashes: u64,
    parent_count_at: u64,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!f64 {
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_decommit_sparse_parent(
        self.handle,
        arena.handle,
        child_indices,
        child_hashes,
        child_count_at,
        max_child_count,
        parent_indices,
        parent_hashes,
        parent_count_at,
        &node_seed,
        domain_prefix_bytes,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal decommit sparse parent failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn decommitSparseLeaves(
    self: *Runtime,
    arena: ResidentBuffer,
    column_offsets: u64,
    column_logs: u64,
    column_count: u32,
    lifting_log: u32,
    leaf_indices: u64,
    leaf_count_at: u64,
    max_leaf_count: u32,
    output_hashes: u64,
    leaf_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!f64 {
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_decommit_sparse_leaves(
        self.handle,
        arena.handle,
        column_offsets,
        column_logs,
        column_count,
        lifting_log,
        leaf_indices,
        leaf_count_at,
        max_leaf_count,
        output_hashes,
        &leaf_seed,
        domain_prefix_bytes,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal decommit sparse leaves failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn decommitSparseLeafGroup(
    self: *Runtime,
    arena: ResidentBuffer,
    column_offsets: u64,
    column_logs: u64,
    column_count: u32,
    first_column: u32,
    total_columns: u32,
    lifting_log: u32,
    leaf_indices: u64,
    leaf_count_at: u64,
    max_leaf_count: u32,
    output_hashes: u64,
    leaf_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!f64 {
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_decommit_sparse_leaf_group(
        self.handle,
        arena.handle,
        column_offsets,
        column_logs,
        column_count,
        first_column,
        total_columns,
        lifting_log,
        leaf_indices,
        leaf_count_at,
        max_leaf_count,
        output_hashes,
        &leaf_seed,
        domain_prefix_bytes,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal decommit sparse leaf group failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn decommitTraceGroup(
    self: *Runtime,
    arena: ResidentBuffer,
    params: DecommitTraceGroupParams,
) MetalError!f64 {
    if (!validDomainPrefixBytes(params.domain_prefix_bytes)) return MetalError.CommitmentFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_decommit_trace_group(
        self.handle,
        arena.handle,
        &params,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal decommit trace group failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn decommitAssembleTrace(
    self: *Runtime,
    arena: ResidentBuffer,
    tree_index: u32,
    role: u32,
    leaf_log: u32,
    first_retained_log: u32,
    column_count: u32,
    mapped: u64,
    mapped_count_at: u64,
    max_queries: u32,
    walk: u64,
    scratch: u64,
    walk_count_at: u64,
    values: u64,
    retained_offsets: u64,
    sparse_indices: u64,
    sparse_hashes: u64,
    sparse_offsets: u64,
    sparse_counts: u64,
    sparse_level_count: u32,
    assembly: u64,
    capacity: u32,
) MetalError!f64 {
    return transcriptCall(self, arena, ffi.stwo_zig_metal_decommit_assemble_trace, .{
        tree_index,    role,           leaf_log,      first_retained_log, column_count, mapped,           mapped_count_at,
        max_queries,   walk,           scratch,       walk_count_at,      values,       retained_offsets, sparse_indices,
        sparse_hashes, sparse_offsets, sparse_counts, sparse_level_count, assembly,     capacity,
    });
}
