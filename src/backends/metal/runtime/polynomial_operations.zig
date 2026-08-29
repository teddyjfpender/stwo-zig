const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const protocol_mode = @import("protocol_mode.zig");
const telemetry = @import("../telemetry.zig");
const work_profile = @import("stwo_prover_api").work_profile;

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
const QuotientFriCommitResult = runtime.QuotientFriCommitResult;
const FriFoldCommitResult = runtime.FriFoldCommitResult;
const FriLineCascadeResult = runtime.FriLineCascadeResult;
const ResidentBuffer = runtime.ResidentBuffer;
const Tree = runtime.Tree;
const validDomainPrefixBytes = protocol_mode.validDomainPrefixBytes;
const resource_plans = @import("resource_plans.zig").ResourcePlans(MetalError);
const evalArguments = resource_plans.evalArguments;
const QuotientCommitConfig = struct {
    resident_output: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    fri: ?QuotientFriConfig = null,
};

const QuotientFriConfig = struct {
    line_output: *anyopaque,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    domain_initial_index: u32,
    domain_step_size: u32,
    channel_state: *[10]u32,
};

const QuotientComputeResult = struct {
    gpu_ms: f64,
    tree: ?Tree,
    fri: ?FriLineCascadeResult = null,
    execution: ?work_profile.QuotientRowExecution = null,
};

pub const QuotientExecutionResult = struct {
    gpu_ms: f64,
    execution: work_profile.QuotientRowExecution,
};

pub const QuotientCommitExecutionResult = struct {
    gpu_ms: f64,
    tree: Tree,
    execution: work_profile.QuotientRowExecution,
};

pub const QuotientFriCommitExecutionResult = struct {
    gpu_ms: f64,
    tree: Tree,
    fri: FriLineCascadeResult,
    execution: work_profile.QuotientRowExecution,
};

// Below this log size, indexed reconstruction is too small a fraction of a
// proof to repay perturbing the short host/GPU schedule. The production wide
// and deep quotient domains are log 15; the small fixture is log 11.
const resident_quotient_domain_log_threshold: u32 = 13;

pub const CircleLdeExecutionResult = circle_transform_ops.CircleLdeExecutionResult;
pub fn computeQuotients(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
) (MetalError || std.mem.Allocator.Error)!f64 {
    const result = try computeQuotientsConfigured(
        self,
        allocator,
        provider,
        out,
        null,
        false,
    );
    return result.gpu_ms;
}

pub fn computeQuotientsWithReceipt(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
) (MetalError || std.mem.Allocator.Error)!QuotientExecutionResult {
    const result = try computeQuotientsConfigured(
        self,
        allocator,
        provider,
        out,
        null,
        true,
    );
    return .{
        .gpu_ms = result.gpu_ms,
        .execution = result.execution orelse return MetalError.QuotientFailed,
    };
}

pub fn computeQuotientsAndCommit(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) (MetalError || std.mem.Allocator.Error)!QuotientCommitResult {
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.QuotientFailed;
    const storage = out.resident_storage orelse return MetalError.QuotientFailed;
    const result = try computeQuotientsConfigured(
        self,
        allocator,
        provider,
        out,
        .{
            .resident_output = storage.handle,
            .leaf_seed = leaf_seed,
            .node_seed = node_seed,
            .domain_prefix_bytes = domain_prefix_bytes,
        },
        false,
    );
    return .{
        .gpu_ms = result.gpu_ms,
        .tree = result.tree orelse return MetalError.CommitmentFailed,
    };
}

pub fn computeQuotientsAndCommitWithReceipt(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) (MetalError || std.mem.Allocator.Error)!QuotientCommitExecutionResult {
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.QuotientFailed;
    const storage = out.resident_storage orelse return MetalError.QuotientFailed;
    const result = try computeQuotientsConfigured(
        self,
        allocator,
        provider,
        out,
        .{
            .resident_output = storage.handle,
            .leaf_seed = leaf_seed,
            .node_seed = node_seed,
            .domain_prefix_bytes = domain_prefix_bytes,
        },
        true,
    );
    return .{
        .gpu_ms = result.gpu_ms,
        .tree = result.tree orelse return MetalError.CommitmentFailed,
        .execution = result.execution orelse return MetalError.QuotientFailed,
    };
}

pub fn computeQuotientsAndCommitFri(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
    line_output: *anyopaque,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    fri_domain_initial_index: u32,
    fri_domain_step_size: u32,
    channel_state: *[10]u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) (MetalError || std.mem.Allocator.Error)!QuotientFriCommitResult {
    if (!validDomainPrefixBytes(domain_prefix_bytes) or coordinates.len == 0)
        return MetalError.QuotientFailed;
    const storage = out.resident_storage orelse return MetalError.QuotientFailed;
    const result = try computeQuotientsConfigured(
        self,
        allocator,
        provider,
        out,
        .{
            .resident_output = storage.handle,
            .leaf_seed = leaf_seed,
            .node_seed = node_seed,
            .domain_prefix_bytes = domain_prefix_bytes,
            .fri = .{
                .line_output = line_output,
                .coordinates = coordinates,
                .final_destination = final_destination,
                .domain_initial_index = fri_domain_initial_index,
                .domain_step_size = fri_domain_step_size,
                .channel_state = channel_state,
            },
        },
        false,
    );
    return .{
        .gpu_ms = result.gpu_ms,
        .tree = result.tree orelse return MetalError.CommitmentFailed,
        .fri = result.fri orelse return MetalError.CommitmentFailed,
    };
}

pub fn computeQuotientsAndCommitFriWithReceipt(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
    line_output: *anyopaque,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    fri_domain_initial_index: u32,
    fri_domain_step_size: u32,
    channel_state: *[10]u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) (MetalError || std.mem.Allocator.Error)!QuotientFriCommitExecutionResult {
    if (!validDomainPrefixBytes(domain_prefix_bytes) or coordinates.len == 0)
        return MetalError.QuotientFailed;
    const storage = out.resident_storage orelse return MetalError.QuotientFailed;
    const result = try computeQuotientsConfigured(
        self,
        allocator,
        provider,
        out,
        .{
            .resident_output = storage.handle,
            .leaf_seed = leaf_seed,
            .node_seed = node_seed,
            .domain_prefix_bytes = domain_prefix_bytes,
            .fri = .{
                .line_output = line_output,
                .coordinates = coordinates,
                .final_destination = final_destination,
                .domain_initial_index = fri_domain_initial_index,
                .domain_step_size = fri_domain_step_size,
                .channel_state = channel_state,
            },
        },
        true,
    );
    return .{
        .gpu_ms = result.gpu_ms,
        .tree = result.tree orelse return MetalError.CommitmentFailed,
        .fri = result.fri orelse return MetalError.CommitmentFailed,
        .execution = result.execution orelse return MetalError.QuotientFailed,
    };
}

fn computeQuotientsConfigured(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
    commitment: ?QuotientCommitConfig,
    comptime capture_work: bool,
) (MetalError || std.mem.Allocator.Error)!QuotientComputeResult {
    var total_timer = try std.time.Timer.start();
    const raw_views = provider.raw_columns.len != 0;
    const view_count = if (raw_views)
        provider.prepared.contribution_plan.contributions.len
    else
        provider.combined_views.len;
    const descriptor_width: usize = if (raw_views) 9 else 5;
    const descriptors = try allocator.alloc(u32, view_count * descriptor_width);
    defer allocator.free(descriptors);
    const raw_column_count = if (raw_views)
        provider.prepared.contribution_plan.active_column_indices.len
    else
        0;
    const raw_column_ptrs = try allocator.alloc([*]const u32, raw_column_count);
    defer allocator.free(raw_column_ptrs);
    const raw_column_lengths = try allocator.alloc(usize, raw_column_count);
    defer allocator.free(raw_column_lengths);
    var flat_len: usize = 0;
    if (!raw_views) {
        for (provider.combined_views) |view| flat_len += 4 * view.coordinates[0].len;
    }
    const flat = try allocator.alloc(u32, flat_len);
    defer allocator.free(flat);
    var cursor: usize = 0;
    var descriptor_index: usize = 0;
    if (raw_views) {
        for (
            provider.prepared.contribution_plan.active_column_indices,
            provider.prepared.contribution_plan.ranges,
            0..,
        ) |column_index, contribution_range, raw_column_index| {
            const column = provider.raw_columns[column_index];
            const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values));
            raw_column_ptrs[raw_column_index] = words.ptr;
            raw_column_lengths[raw_column_index] = words.len;
            const log_shift = provider.lifting_log_size - column.log_size;
            const contributions = provider.prepared.contribution_plan.contributions[contribution_range.start .. contribution_range.start + contribution_range.len];
            for (contributions) |contribution| {
                const coefficient = contribution.value_coeff.toM31Array();
                const base = descriptor_index * descriptor_width;
                descriptors[base..][0..9].* = .{
                    @intCast(cursor),
                    @intCast(column.values.len),
                    @intCast(contribution.batch_index),
                    @intCast(log_shift + 1),
                    @intFromBool(column.log_size == provider.lifting_log_size),
                    coefficient[0].v,
                    coefficient[1].v,
                    coefficient[2].v,
                    coefficient[3].v,
                };
                descriptor_index += 1;
            }
            cursor += words.len;
        }
    } else {
        for (provider.combined_views, 0..) |view, index| {
            const coordinate_len = view.coordinates[0].len;
            const base = index * descriptor_width;
            descriptors[base..][0..5].* = .{
                @intCast(cursor),
                @intCast(coordinate_len),
                @intCast(view.batch_index),
                @intCast(view.shift_amt),
                @intFromBool(view.is_direct),
            };
            for (view.coordinates) |coordinate| {
                const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(coordinate));
                @memcpy(flat[cursor .. cursor + words.len], words);
                cursor += words.len;
            }
        }
    }
    std.debug.assert((raw_views and flat.len == 0) or cursor == flat.len);
    std.debug.assert(descriptor_index == 0 or descriptor_index == view_count);

    const samples = provider.workspace.sample_point_components;
    const packed_ns = total_timer.lap();
    const sample_words = try allocator.alloc(u32, samples.len * 8);
    defer allocator.free(sample_words);
    for (samples, 0..) |sample, index| {
        const base = index * 8;
        sample_words[base..][0..8].* = .{
            sample.determinant.a.v, sample.determinant.b.v,
            0,                      0,
            sample.pix.a.v,         sample.pix.b.v,
            sample.piy.a.v,         sample.piy.b.v,
        };
    }

    const terms = provider.prepared.quotient_constants.batch_linear_terms;
    const linear_words = try allocator.alloc(u32, terms.len * 8);
    defer allocator.free(linear_words);
    for (terms, 0..) |term, index| {
        const sum_a = term.sum_a.toM31Array();
        const sum_b = term.sum_b.toM31Array();
        const base = index * 8;
        inline for (0..4) |coordinate| {
            linear_words[base + coordinate] = sum_a[coordinate].v;
            linear_words[base + 4 + coordinate] = sum_b[coordinate].v;
        }
    }

    const row_count = provider.domain_size;
    std.debug.assert(provider.lifting_log_size == provider.domain.logSize());
    const cache_domain = provider.lifting_log_size >= resident_quotient_domain_log_threshold;
    const domain_x: ?[]u32 = if (cache_domain) null else try allocator.alloc(u32, row_count);
    defer if (domain_x) |values| allocator.free(values);
    const domain_y: ?[]u32 = if (cache_domain) null else try allocator.alloc(u32, row_count);
    defer if (domain_y) |values| allocator.free(values);
    if (!cache_domain) {
        const core_utils = @import("stwo_core").utils;
        for (0..row_count) |position| {
            const point = provider.domain.at(core_utils.bitReverseIndex(position, provider.lifting_log_size));
            domain_x.?[position] = point.x.v;
            domain_y.?[position] = point.y.v;
        }
    }

    if (!out.contiguous or out.columns[0].len != row_count) return MetalError.QuotientFailed;
    const output = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(out.columns[0].ptr[0 .. row_count * 4]));
    const prepared_ns = total_timer.lap();
    var gpu_ms: f64 = 0;
    var tree_handle: ?*anyopaque = null;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const resident_output = if (commitment) |config| config.resident_output else null;
    const leaf_seed = if (commitment) |*config| &config.leaf_seed else null;
    const node_seed = if (commitment) |*config| &config.node_seed else null;
    const domain_prefix_bytes = if (commitment) |config| config.domain_prefix_bytes else 0;
    const fri_config = if (commitment) |config| config.fri else null;
    const fri_tree_handles = if (fri_config) |config|
        try allocator.alloc(?*anyopaque, config.coordinates.len)
    else
        null;
    defer if (fri_tree_handles) |handles| allocator.free(handles);
    if (fri_tree_handles) |handles| @memset(handles, null);
    var fri_stats: CommandEpochStats = undefined;
    var fri_inverse_generation_mask: u32 = 0;
    var quotient_work_receipt: ffi.QuotientWorkReceipt = undefined;
    if (!ffi.stwo_zig_metal_compute_quotients(
        self.handle,
        flat.ptr,
        flat.len,
        raw_column_ptrs.ptr,
        raw_column_lengths.ptr,
        @intCast(raw_column_count),
        provider.backend_residency_handles.ptr,
        @intCast(provider.backend_residency_handles.len),
        @ptrCast(descriptors.ptr),
        @intCast(view_count),
        raw_views,
        sample_words.ptr,
        linear_words.ptr,
        @intCast(samples.len),
        cache_domain,
        provider.lifting_log_size,
        @intCast(provider.domain.half_coset.initial_index.v),
        @intCast(provider.domain.half_coset.step_size.v),
        if (domain_x) |values| values.ptr else null,
        if (domain_y) |values| values.ptr else null,
        @intCast(row_count),
        output.ptr,
        resident_output,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        if (fri_config) |config| config.line_output else null,
        if (fri_config) |config| config.coordinates.ptr else null,
        if (fri_config) |config| config.final_destination else null,
        if (fri_config) |config| @intCast(config.coordinates.len) else 0,
        if (fri_config) |config| config.domain_initial_index else 0,
        if (fri_config) |config| config.domain_step_size else 0,
        if (fri_config) |config| config.channel_state else null,
        if (fri_tree_handles) |handles| handles.ptr else null,
        if (fri_config != null) &fri_inverse_generation_mask else null,
        if (fri_config != null) &fri_stats else null,
        if (capture_work) &quotient_work_receipt else null,
        &tree_handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal quotient failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.QuotientFailed;
    }
    const quotient_execution: ?work_profile.QuotientRowExecution = if (capture_work) blk: {
        const expected_row_count: u64 = @intCast(row_count);
        const expected_batch_count: u64 = @intCast(samples.len);
        const expected_view_count: u64 = @intCast(view_count);
        if (quotient_work_receipt.schema_version != 1 or
            quotient_work_receipt.reserved0 != 0 or
            quotient_work_receipt.reserved1 != 0 or
            quotient_work_receipt.row_count != expected_row_count or
            quotient_work_receipt.batch_count != expected_batch_count or
            quotient_work_receipt.view_count != expected_view_count)
        {
            return MetalError.QuotientFailed;
        }
        const path: work_profile.QuotientRowPath = switch (quotient_work_receipt.path) {
            0 => if (!raw_views) .metal_combined else return MetalError.QuotientFailed,
            1 => if (raw_views) .metal_raw_direct else return MetalError.QuotientFailed,
            2 => if (raw_views) .metal_raw_segmented else return MetalError.QuotientFailed,
            3 => if (raw_views) .metal_raw_grouped_partials else return MetalError.QuotientFailed,
            else => return MetalError.QuotientFailed,
        };
        const host_domain_circle_additions = if (cache_domain)
            0
        else
            provider.materializedDomainCircleAdditions() catch
                return MetalError.QuotientFailed;
        const domain_circle_additions = std.math.add(
            u64,
            quotient_work_receipt.domain_circle_additions,
            host_domain_circle_additions,
        ) catch return MetalError.QuotientFailed;
        const execution = work_profile.QuotientRowExecution{
            .path = path,
            .lifting_log_size = provider.lifting_log_size,
            .row_count = quotient_work_receipt.row_count,
            .sample_batch_count = quotient_work_receipt.batch_count,
            .contribution_count = @intCast(provider.executedContributionCount()),
            .combined_view_count = @intCast(provider.combined_views.len),
            .grouped_partial_count = quotient_work_receipt.grouped_partial_count,
            .numerator_additions = quotient_work_receipt.numerator_additions,
            .numerator_multiplications = quotient_work_receipt.numerator_multiplications,
            .combined_plan_source_cells = provider.combinedPlanSourceCells(),
            .domain_circle_additions = domain_circle_additions,
            .batch_inverse_multiplications = 0,
            .batch_inverse_calls = quotient_work_receipt.batch_inverse_calls,
        };
        execution.validate() catch return MetalError.QuotientFailed;
        break :blk execution;
    } else null;
    var fri_result: ?FriLineCascadeResult = null;
    if (fri_config) |config| {
        const trees = try allocator.alloc(Tree, config.coordinates.len);
        var initialized_trees: usize = 0;
        errdefer {
            for (trees[0..initialized_trees]) |*tree| tree.deinit();
            allocator.free(trees);
        }
        for (trees, fri_tree_handles.?, 0..) |*tree, handle, stage| {
            tree.* = .{
                .handle = handle orelse return MetalError.CommitmentFailed,
                .runtime_handle = self.handle,
                .log_size = std.math.log2_int(
                    u32,
                    @as(u32, @intCast(row_count >> @intCast(stage + 1))),
                ),
            };
            initialized_trees += 1;
        }
        fri_result = .{
            .stats = fri_stats,
            .trees = trees,
            .inverse_generation_mask = fri_inverse_generation_mask,
        };
    }
    const dispatch_and_copy_ns = total_timer.lap();
    std.log.debug(
        "Metal quotient wall: pack={d:.3}ms prepare={d:.3}ms dispatch-copy={d:.3}ms",
        .{
            @as(f64, @floatFromInt(packed_ns)) / std.time.ns_per_ms,
            @as(f64, @floatFromInt(prepared_ns)) / std.time.ns_per_ms,
            @as(f64, @floatFromInt(dispatch_and_copy_ns)) / std.time.ns_per_ms,
        },
    );
    return .{
        .gpu_ms = gpu_ms,
        .tree = if (tree_handle) |handle| .{
            .handle = handle,
            .runtime_handle = self.handle,
            .log_size = provider.lifting_log_size,
        } else null,
        .fri = fri_result,
        .execution = quotient_execution,
    };
}

const sampled_coefficient_ops = @import("sampled_coefficient_operations.zig");
pub const SampledCoefficientEvaluationResult = sampled_coefficient_ops.SampledCoefficientEvaluationResult;
pub const evaluateCoefficientPlans = sampled_coefficient_ops.evaluateCoefficientPlans;
pub const evaluateCoefficientPlansUnprofiled = sampled_coefficient_ops.evaluateCoefficientPlansUnprofiled;
pub const evaluateCoefficientTreePlans = sampled_coefficient_ops.evaluateCoefficientTreePlans;
pub const evaluateCoefficientTreePlansUnprofiled = sampled_coefficient_ops.evaluateCoefficientTreePlansUnprofiled;

const circle_transform_ops = @import("circle_transform_operations.zig");
pub const transformCircle = circle_transform_ops.transformCircle;
pub const transformCircleResident = circle_transform_ops.transformCircleResident;
pub const transformCircleLdeInto = circle_transform_ops.transformCircleLdeInto;
pub const beginCircleLdeBatch = circle_transform_ops.beginCircleLdeBatch;
pub const destroyCircleLdeBatch = circle_transform_ops.destroyCircleLdeBatch;
pub const finishCircleLdeBatch = circle_transform_ops.finishCircleLdeBatch;
pub const transformCircleLdeIntoBatch = circle_transform_ops.transformCircleLdeIntoBatch;
pub const evaluateRecurrenceComposition = circle_transform_ops.evaluateRecurrenceComposition;
pub const transformCircleLde = circle_transform_ops.transformCircleLde;
