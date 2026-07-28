const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const protocol_mode = @import("protocol_mode.zig");
const telemetry = @import("../telemetry.zig");

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
};

// Below this log size, indexed reconstruction is too small a fraction of a
// proof to repay perturbing the short host/GPU schedule. The production wide
// and deep quotient domains are log 15; the small fixture is log 11.
const resident_quotient_domain_log_threshold: u32 = 13;

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
    );
    return result.gpu_ms;
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
    );
    return .{
        .gpu_ms = result.gpu_ms,
        .tree = result.tree orelse return MetalError.CommitmentFailed,
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
    );
    return .{
        .gpu_ms = result.gpu_ms,
        .tree = result.tree orelse return MetalError.CommitmentFailed,
        .fri = result.fri orelse return MetalError.CommitmentFailed,
    };
}

fn computeQuotientsConfigured(
    self: *Runtime,
    allocator: std.mem.Allocator,
    provider: anytype,
    out: anytype,
    commitment: ?QuotientCommitConfig,
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
        if (fri_config != null) &fri_stats else null,
        &tree_handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal quotient failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.QuotientFailed;
    }
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
        fri_result = .{ .stats = fri_stats, .trees = trees };
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
    };
}

pub fn evaluateCoefficientPlans(
    self: *Runtime,
    allocator: std.mem.Allocator,
    coefficients: anytype,
    tree_values: anytype,
    plans: anytype,
) (MetalError || std.mem.Allocator.Error)!f64 {
    const TreePlan = struct {
        coefficients: @TypeOf(coefficients),
        tree_values: @TypeOf(tree_values),
        plans: @TypeOf(plans),
    };
    const tree_plans = [_]TreePlan{.{
        .coefficients = coefficients,
        .tree_values = tree_values,
        .plans = plans,
    }};
    return evaluateCoefficientTreePlans(self, allocator, &tree_plans);
}

pub fn evaluateCoefficientTreePlans(
    self: *Runtime,
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) (MetalError || std.mem.Allocator.Error)!f64 {
    var coefficient_column_count: usize = 0;
    var coefficient_count: usize = 0;
    var factor_word_count: usize = 0;
    var task_count: usize = 0;
    var basis_task_count: usize = 0;
    var basis_count: usize = 0;
    var output_count: usize = 0;
    for (tree_plans) |tree_plan| {
        if (tree_plan.coefficients.len != tree_plan.tree_values.len)
            return MetalError.PolynomialEvaluationFailed;
        coefficient_column_count += tree_plan.coefficients.len;
        for (tree_plan.coefficients) |coefficient| {
            coefficient_count += std.mem.sliceAsBytes(coefficient.coefficients()).len / @sizeOf(u32);
        }
        for (tree_plan.plans) |plan| {
            factor_word_count += plan.flat_factors.len * 4;
            task_count += plan.column_indices.items.len * plan.normalized_points.len;
            basis_task_count += plan.normalized_points.len;
            basis_count += plan.normalized_points.len * (@as(usize, 1) << @intCast(plan.coeff_log_size));
        }
        for (tree_plan.tree_values) |values| output_count += values.len;
    }
    if (coefficient_column_count == 0 or task_count == 0) return 0;

    const coefficient_offsets = try allocator.alloc(u32, coefficient_column_count);
    defer allocator.free(coefficient_offsets);
    const coefficient_ptrs = try allocator.alloc([*]const u32, coefficient_column_count);
    defer allocator.free(coefficient_ptrs);
    const coefficient_lengths = try allocator.alloc(usize, coefficient_column_count);
    defer allocator.free(coefficient_lengths);
    var coefficient_cursor: usize = 0;
    var coefficient_word_cursor: usize = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.coefficients) |coefficient| {
            const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(coefficient.coefficients()));
            coefficient_offsets[coefficient_cursor] = @intCast(coefficient_word_cursor);
            coefficient_ptrs[coefficient_cursor] = words.ptr;
            coefficient_lengths[coefficient_cursor] = words.len;
            coefficient_cursor += 1;
            coefficient_word_cursor += words.len;
        }
    }
    std.debug.assert(coefficient_cursor == coefficient_column_count);
    std.debug.assert(coefficient_word_cursor == coefficient_count);

    const factor_words = try allocator.alloc(u32, factor_word_count);
    defer allocator.free(factor_words);
    const task_words = try allocator.alloc(u32, task_count * 5);
    defer allocator.free(task_words);
    const task_columns = try allocator.alloc(u32, task_count);
    defer allocator.free(task_columns);
    const basis_task_words = try allocator.alloc(u32, basis_task_count * 4);
    defer allocator.free(basis_task_words);

    const output_offsets = try allocator.alloc(u32, coefficient_column_count);
    defer allocator.free(output_offsets);
    var output_column_cursor: usize = 0;
    var output_cursor: usize = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.tree_values) |values| {
            output_offsets[output_column_cursor] = @intCast(output_cursor);
            output_column_cursor += 1;
            output_cursor += values.len;
        }
    }
    std.debug.assert(output_column_cursor == coefficient_column_count);
    std.debug.assert(output_cursor == output_count);

    var factor_cursor: usize = 0;
    var task_cursor: usize = 0;
    var basis_task_cursor: usize = 0;
    var basis_cursor: usize = 0;
    var tree_column_base: usize = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.plans) |plan| {
            const plan_factor_start = factor_cursor;
            for (plan.flat_factors) |factor| {
                const coordinates = factor.toM31Array();
                inline for (0..4) |coordinate| {
                    factor_words[factor_cursor] = coordinates[coordinate].v;
                    factor_cursor += 1;
                }
            }
            for (0..plan.normalized_points.len) |point_index| {
                const base = basis_task_cursor * 4;
                const coefficient_length = @as(usize, 1) << @intCast(plan.coeff_log_size);
                basis_task_words[base..][0..4].* = .{
                    @intCast(plan_factor_start + point_index * plan.coeff_log_size * 4),
                    plan.coeff_log_size,
                    @intCast(basis_cursor),
                    @intCast(coefficient_length),
                };
                basis_task_cursor += 1;
                basis_cursor += coefficient_length;
            }
            const coefficient_length = @as(usize, 1) << @intCast(plan.coeff_log_size);
            const plan_basis_start = basis_cursor - plan.normalized_points.len * coefficient_length;
            for (plan.column_indices.items) |column_index| {
                if (column_index >= tree_plan.coefficients.len)
                    return MetalError.PolynomialEvaluationFailed;
                const global_column = tree_column_base + column_index;
                for (0..plan.normalized_points.len) |point_index| {
                    const base = task_cursor * 5;
                    task_words[base..][0..5].* = .{
                        coefficient_offsets[global_column],
                        @intCast(tree_plan.coefficients[column_index].coefficients().len),
                        @intCast(plan_basis_start + point_index * coefficient_length),
                        plan.coeff_log_size,
                        output_offsets[global_column] + @as(u32, @intCast(point_index)),
                    };
                    task_columns[task_cursor] = @intCast(global_column);
                    task_cursor += 1;
                }
            }
        }
        tree_column_base += tree_plan.coefficients.len;
    }
    std.debug.assert(factor_cursor == factor_word_count);
    std.debug.assert(task_cursor == task_count);
    std.debug.assert(basis_task_cursor == basis_task_count);
    std.debug.assert(basis_cursor == basis_count);

    const output_words = try allocator.alloc(u32, output_count * 4);
    defer allocator.free(output_words);
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_eval_polynomials(
        self.handle,
        coefficient_ptrs.ptr,
        coefficient_lengths.ptr,
        @intCast(coefficient_column_count),
        coefficient_count,
        factor_words.ptr,
        factor_words.len,
        @ptrCast(basis_task_words.ptr),
        @intCast(basis_task_count),
        @intCast(basis_count),
        @ptrCast(task_words.ptr),
        task_columns.ptr,
        @intCast(task_count),
        @intCast(output_count),
        output_words.ptr,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal polynomial evaluation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    }
    output_column_cursor = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.tree_values) |values| {
            const output_offset = output_offsets[output_column_cursor];
            for (values, 0..) |*value, point_index| {
                var coordinates: [4]@import("stwo_core").fields.m31.M31 = undefined;
                inline for (0..4) |coordinate| {
                    coordinates[coordinate].v = output_words[(@as(usize, output_offset) + point_index) * 4 + coordinate];
                }
                value.* = @import("stwo_core").fields.qm31.QM31.fromM31Array(coordinates);
            }
            output_column_cursor += 1;
        }
    }
    return gpu_ms;
}

pub fn transformCircle(
    self: *Runtime,
    allocator: std.mem.Allocator,
    columns: []const []@import("stwo_core").fields.m31.M31,
    twiddles: []const @import("stwo_core").fields.m31.M31,
    log_size: u32,
    inverse: bool,
) (MetalError || std.mem.Allocator.Error)!f64 {
    if (columns.len == 0 or log_size < 3) return MetalError.CircleTransformFailed;
    const expected_len = @as(usize, 1) << @intCast(log_size);
    if (twiddles.len != expected_len / 2) return MetalError.CircleTransformFailed;
    const pointers = try allocator.alloc([*]u32, columns.len);
    defer allocator.free(pointers);
    for (columns, 0..) |column, index| {
        if (column.len != expected_len) return MetalError.CircleTransformFailed;
        pointers[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)).ptr;
    }
    const scale_factor = if (inverse)
        (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(expected_len)).inv() catch
            return MetalError.CircleTransformFailed).v
    else
        1;
    const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(twiddles));
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_transform(
        self.handle,
        pointers.ptr,
        @intCast(columns.len),
        log_size,
        words.ptr,
        inverse,
        scale_factor,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal circle transform failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

/// Allocation-free single-column transform for arena recomputation. The
/// column pointer already aliases resident shared storage.
pub fn transformCircleResident(
    self: *Runtime,
    column: []@import("stwo_core").fields.m31.M31,
    twiddles: []const @import("stwo_core").fields.m31.M31,
    log_size: u32,
    inverse: bool,
) MetalError!f64 {
    if (log_size < 3) return MetalError.CircleTransformFailed;
    const expected_len = @as(usize, 1) << @intCast(log_size);
    if (column.len != expected_len or twiddles.len != expected_len / 2) return MetalError.CircleTransformFailed;
    var pointers = [_][*]u32{std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)).ptr};
    const scale_factor = if (inverse)
        (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(expected_len)).inv() catch
            return MetalError.CircleTransformFailed).v
    else
        1;
    const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(twiddles));
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_transform(
        self.handle,
        &pointers,
        1,
        log_size,
        words.ptr,
        inverse,
        scale_factor,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal resident circle recomputation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn transformCircleLdeInto(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source_columns: []const []const @import("stwo_core").fields.m31.M31,
    base_columns: []const []@import("stwo_core").fields.m31.M31,
    extended_columns: []const []@import("stwo_core").fields.m31.M31,
    transform_buffer: []@import("stwo_core").fields.m31.M31,
    extended_start: usize,
    extended_stride: usize,
    inverse_twiddles: []const @import("stwo_core").fields.m31.M31,
    forward_twiddles: []const @import("stwo_core").fields.m31.M31,
    base_log_size: u32,
    extended_log_size: u32,
) (MetalError || std.mem.Allocator.Error)!f64 {
    if (base_columns.len == 0 or source_columns.len != base_columns.len or base_columns.len != extended_columns.len or base_log_size < 3 or extended_log_size <= base_log_size) {
        return MetalError.CircleTransformFailed;
    }
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    if (inverse_twiddles.len != base_len / 2 or forward_twiddles.len != extended_len / 2) return MetalError.CircleTransformFailed;
    const base_ptrs = try allocator.alloc([*]u32, base_columns.len);
    defer allocator.free(base_ptrs);
    const source_ptrs = try allocator.alloc([*]const u32, source_columns.len);
    defer allocator.free(source_ptrs);
    for (source_columns, base_columns, extended_columns, 0..) |source, base, extended, index| {
        if (source.len != base_len or base.len != base_len or extended.len != extended_len) return MetalError.CircleTransformFailed;
        if (extended.ptr != transform_buffer.ptr + extended_start + index * extended_stride) {
            return MetalError.CircleTransformFailed;
        }
        source_ptrs[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source)).ptr;
        base_ptrs[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(base)).ptr;
    }
    const required_words = extended_start + (extended_columns.len - 1) * extended_stride + extended_len;
    if (extended_stride < extended_len or required_words > transform_buffer.len) return MetalError.CircleTransformFailed;
    const transform_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(transform_buffer));
    const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_twiddles));
    const forward_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(forward_twiddles));
    const scale_factor = (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(base_len)).inv() catch
        return MetalError.CircleTransformFailed).v;
    var gpu_ms: f64 = 0;
    var source_binding: u32 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_lde(
        self.handle,
        source_ptrs.ptr,
        base_ptrs.ptr,
        transform_words.ptr,
        transform_words.len,
        @intCast(extended_start),
        @intCast(extended_stride),
        @intCast(base_columns.len),
        base_log_size,
        extended_log_size,
        inverse_words.ptr,
        forward_words.ptr,
        scale_factor,
        &source_binding,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal circle LDE failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    telemetry.recordCommitSourceBinding(source_binding);
    return gpu_ms;
}

pub fn evaluateRecurrenceComposition(
    self: *Runtime,
    resident_tree: ?*anyopaque,
    trace_first: [*]const @import("stwo_core").fields.m31.M31,
    row_count: usize,
    column_count: usize,
    column_stride: usize,
    power_words: []const u32,
    denominator_inverses: [2]u32,
    output: []@import("stwo_core").fields.m31.M31,
    inverse_twiddles: []const @import("stwo_core").fields.m31.M31,
) MetalError!f64 {
    if (row_count == 0 or column_count < 3 or column_stride < row_count or
        power_words.len != (column_count - 2) * 4 or output.len != row_count * 4 or
        inverse_twiddles.len != row_count / 2 or
        row_count > std.math.maxInt(u32) or column_count > std.math.maxInt(u32) or
        column_stride > std.math.maxInt(u32) or power_words.len > std.math.maxInt(u32))
    {
        return MetalError.CompositionEvaluationFailed;
    }
    const trace_words: [*]const u32 = @ptrCast(trace_first);
    const output_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(output));
    const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_twiddles));
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_recurrence_composition(
        self.handle,
        resident_tree,
        trace_words,
        @intCast(row_count),
        @intCast(column_count),
        @intCast(column_stride),
        power_words.ptr,
        @intCast(power_words.len),
        &denominator_inverses,
        output_words.ptr,
        output_words.len,
        inverse_words.ptr,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal composition evaluation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CompositionEvaluationFailed;
    }
    return gpu_ms;
}

pub fn transformCircleLde(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source_columns: []const []const @import("stwo_core").fields.m31.M31,
    base_columns: []const []@import("stwo_core").fields.m31.M31,
    extended_columns: []const []@import("stwo_core").fields.m31.M31,
    inverse_twiddles: []const @import("stwo_core").fields.m31.M31,
    forward_twiddles: []const @import("stwo_core").fields.m31.M31,
    base_log_size: u32,
    extended_log_size: u32,
) (MetalError || std.mem.Allocator.Error)!f64 {
    if (extended_columns.len == 0 or extended_log_size >= @bitSizeOf(usize)) {
        return MetalError.CircleTransformFailed;
    }
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    const transform_len = std.math.mul(usize, extended_columns.len, extended_len) catch
        return MetalError.CircleTransformFailed;
    const transform_buffer = try allocator.alloc(@import("stwo_core").fields.m31.M31, transform_len);
    defer allocator.free(transform_buffer);
    const transform_columns = try allocator.alloc([]@import("stwo_core").fields.m31.M31, extended_columns.len);
    defer allocator.free(transform_columns);
    for (transform_columns, 0..) |*column, index| {
        column.* = transform_buffer[index * extended_len .. (index + 1) * extended_len];
    }
    const gpu_ms = try self.transformCircleLdeInto(
        allocator,
        source_columns,
        base_columns,
        transform_columns,
        transform_buffer,
        0,
        extended_len,
        inverse_twiddles,
        forward_twiddles,
        base_log_size,
        extended_log_size,
    );
    for (extended_columns, transform_columns) |destination, source| @memcpy(destination, source);
    return gpu_ms;
}
