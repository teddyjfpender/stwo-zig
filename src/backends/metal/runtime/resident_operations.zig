const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const protocol_mode = @import("protocol_mode.zig");

const M31 = @import("stwo_core").fields.m31.M31;

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
const ResidentBuffer = runtime.ResidentBuffer;
const Tree = runtime.Tree;
const TraceGenerationStats = runtime.TraceGenerationStats;
const validDomainPrefixBytes = protocol_mode.validDomainPrefixBytes;
const lifted_merkle_prefix_bytes = runtime.lifted_merkle_prefix_bytes;
const resource_plans = @import("resource_plans.zig").ResourcePlans(MetalError);
const evalArguments = resource_plans.evalArguments;

pub fn quadraticRecurrenceTrace(
    self: *Runtime,
    columns: []const [*]u32,
    row_count: u32,
    log_n_rows: u32,
    recipe: [7]u32,
) MetalError!TraceGenerationStats {
    if (columns.len < 2 or columns.len > 256 or row_count == 0 or
        log_n_rows == 0 or log_n_rows >= 31 or
        row_count != @as(u32, 1) << @intCast(log_n_rows))
        return MetalError.InvalidColumns;
    for (recipe) |value| if (value >= 0x7fffffff) return MetalError.InvalidColumns;

    var gpu_ms: f64 = 0;
    var copyback_columns: u32 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_quadratic_recurrence_trace(
        self.handle,
        columns.ptr,
        @intCast(columns.len),
        row_count,
        log_n_rows,
        &recipe,
        &gpu_ms,
        &copyback_columns,
        &message,
        message.len,
    )) {
        std.log.err("Metal quadratic recurrence trace failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.TraceGenerationFailed;
    }
    return .{ .gpu_ms = gpu_ms, .copyback_columns = copyback_columns };
}

pub fn witnessInputGather(
    self: *Runtime,
    arena: ResidentBuffer,
    producer_offsets: []const u32,
    edge_descriptors: []const [5]u32,
    input_width: u32,
    total_real_rows: u32,
    consumer_rows: u32,
    consumer_offsets: []const u32,
    include_enabler: bool,
    include_iota: bool,
) MetalError!f64 {
    if (producer_offsets.len == 0 or producer_offsets.len != edge_descriptors.len or
        consumer_offsets.len != input_width + @intFromBool(include_enabler) + @intFromBool(include_iota))
        return MetalError.InvalidColumns;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_witness_input_gather(
        self.handle,
        arena.handle,
        producer_offsets.ptr,
        @ptrCast(edge_descriptors.ptr),
        @intCast(edge_descriptors.len),
        input_width,
        total_real_rows,
        consumer_rows,
        consumer_offsets.ptr,
        @intFromBool(include_enabler),
        @intFromBool(include_iota),
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal witness input gather failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn executionTableSplit(
    self: *Runtime,
    arena: ResidentBuffer,
    source_offset: u32,
    value_count: u32,
    column_rows: u32,
    source_words: u32,
    destination_offsets: []const u32,
) MetalError!f64 {
    if (!((source_words == 8 and destination_offsets.len == 28) or
        (source_words == 4 and destination_offsets.len == 8))) return MetalError.InvalidColumns;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_execution_table_split(
        self.handle,
        arena.handle,
        source_offset,
        value_count,
        column_rows,
        source_words,
        @intCast(destination_offsets.len),
        destination_offsets.ptr,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal execution table split failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn memoryAddressBaseTrace(
    self: *Runtime,
    arena: ResidentBuffer,
    raw_address_offset: u32,
    address_count: u32,
    multiplicity_offset: u32,
    multiplicity_words: u32,
    row_count: u32,
    output_offsets: []const u32,
) MetalError!f64 {
    if (output_offsets.len != 32 or row_count == 0 or
        multiplicity_words != 16 * row_count) return MetalError.InvalidColumns;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_memory_address_base_trace(
        self.handle,
        arena.handle,
        raw_address_offset,
        address_count,
        multiplicity_offset,
        multiplicity_words,
        row_count,
        output_offsets.ptr,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal memory address trace failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn memoryValueBaseTrace(
    self: *Runtime,
    arena: ResidentBuffer,
    source_offsets: []const u32,
    source_words: u32,
    source_row_offset: u32,
    multiplicity_offset: u32,
    multiplicity_words: u32,
    row_count: u32,
    output_offsets: []const u32,
) MetalError!f64 {
    if (!((source_offsets.len == 28 and output_offsets.len == 29) or
        (source_offsets.len == 8 and output_offsets.len == 9)) or row_count == 0)
        return MetalError.InvalidColumns;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_memory_value_base_trace(
        self.handle,
        arena.handle,
        source_offsets.ptr,
        @intCast(source_offsets.len),
        source_words,
        source_row_offset,
        multiplicity_offset,
        multiplicity_words,
        row_count,
        output_offsets.ptr,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal memory value trace failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn memoryRc99Count(
    self: *Runtime,
    arena: ResidentBuffer,
    limb_offsets: []const u32,
    row_count: u32,
    lut_offset: u32,
    table_size: u32,
    count_offset: u32,
) MetalError!f64 {
    if (limb_offsets.len == 0 or limb_offsets.len % 2 != 0 or
        limb_offsets.len > 28 or row_count == 0 or table_size == 0)
        return MetalError.InvalidColumns;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_memory_rc99_count(
        self.handle,
        arena.handle,
        limb_offsets.ptr,
        @intCast(limb_offsets.len / 2),
        row_count,
        lut_offset,
        table_size,
        count_offset,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal memory range-check count failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn publicMemorySeed(
    self: *Runtime,
    arena: ResidentBuffer,
    address_id_pairs: []const [2]u32,
    address_count_offset: u32,
    address_count_words: u32,
    big_count_offset: u32,
    big_count_words: u32,
    small_count_offset: u32,
    small_count_words: u32,
) MetalError!f64 {
    if (address_id_pairs.len == 0) return 0;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_public_memory_seed(
        self.handle,
        arena.handle,
        @ptrCast(address_id_pairs.ptr),
        @intCast(address_id_pairs.len),
        address_count_offset,
        address_count_words,
        big_count_offset,
        big_count_words,
        small_count_offset,
        small_count_words,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal public memory seed failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn leafAbsorb(
    self: *Runtime,
    arena: ResidentBuffer,
    column_offsets: []const u32,
    column_logs: []const u32,
    state_offset: u32,
    lifting_log: u32,
    first_column: u32,
    is_final: bool,
    prefix_bytes: u32,
    leaf_seed: [8]u32,
) MetalError!f64 {
    if (column_offsets.len == 0 or column_offsets.len > 16 or column_offsets.len != column_logs.len or
        (prefix_bytes != 0 and prefix_bytes != lifted_merkle_prefix_bytes))
        return MetalError.CommitmentFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_leaf_absorb(self.handle, arena.handle, column_offsets.ptr, column_logs.ptr, @intCast(column_offsets.len), state_offset, lifting_log, first_column, @intFromBool(is_final), prefix_bytes, &leaf_seed, &gpu_ms, &message, message.len)) {
        std.log.err("Metal leaf absorb failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn leafAbsorbCompact(
    self: *Runtime,
    arena: ResidentBuffer,
    column_offsets: []const u32,
    column_logs: []const u32,
    source_state_offset: u32,
    source_state_log: u32,
    destination_state_offset: u32,
    destination_log: u32,
    first_column: u32,
    is_final: bool,
    prefix_bytes: u32,
    leaf_seed: [8]u32,
) MetalError!f64 {
    if (column_offsets.len == 0 or column_offsets.len > 16 or column_offsets.len != column_logs.len or
        (first_column != 0 and source_state_log > destination_log) or
        (prefix_bytes != 0 and prefix_bytes != lifted_merkle_prefix_bytes))
        return MetalError.CommitmentFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_leaf_absorb_compact(
        self.handle,
        arena.handle,
        column_offsets.ptr,
        column_logs.ptr,
        @intCast(column_offsets.len),
        source_state_offset,
        source_state_log,
        destination_state_offset,
        destination_log,
        first_column,
        @intFromBool(is_final),
        prefix_bytes,
        &leaf_seed,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal compact leaf absorb failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn parentSeeded(
    self: *Runtime,
    arena: ResidentBuffer,
    child_offset: u32,
    destination_offset: u32,
    parent_count: u32,
    node_seed: [8]u32,
) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_parent_seeded(self.handle, arena.handle, child_offset, destination_offset, parent_count, &node_seed, &gpu_ms, &message, message.len)) {
        std.log.err("Metal seeded parent hash failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn parentPlain(
    self: *Runtime,
    arena: ResidentBuffer,
    child_offset: u32,
    destination_offset: u32,
    parent_count: u32,
) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_parent_plain(self.handle, arena.handle, child_offset, destination_offset, parent_count, &gpu_ms, &message, message.len)) {
        std.log.err("Metal plain parent hash failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn qm31ToCoordinates(
    self: *Runtime,
    source: [*]const u32,
    value_count: u32,
    destination: [*]u32,
) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_qm31_to_coordinates(self.handle, source, value_count, destination, &gpu_ms, &message, message.len)) {
        std.log.err("Metal QM31 coordinate conversion failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn felt252Oracle(self: *Runtime, inputs: []const u32, outputs: []u32) MetalError!f64 {
    if (inputs.len == 0 or inputs.len % 16 != 0 or outputs.len != inputs.len) return MetalError.InvalidColumns;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_felt252_oracle(
        self.handle,
        inputs.ptr,
        @intCast(inputs.len / 16),
        outputs.ptr,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal Felt252 oracle failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    }
    return gpu_ms;
}

pub fn commitColumns(
    self: *Runtime,
    allocator: std.mem.Allocator,
    columns: []const []const u32,
    log_sizes: []const u32,
    lifting_log_size: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) (MetalError || std.mem.Allocator.Error)!Tree {
    return commitColumnsConfigured(
        self,
        allocator,
        columns,
        log_sizes,
        lifting_log_size,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        null,
    );
}

pub fn commitColumnsWithBacking(
    self: *Runtime,
    allocator: std.mem.Allocator,
    columns: []const []const u32,
    log_sizes: []const u32,
    lifting_log_size: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    backings: []const []M31,
) (MetalError || std.mem.Allocator.Error)!Tree {
    return commitColumnsConfigured(
        self,
        allocator,
        columns,
        log_sizes,
        lifting_log_size,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        backings,
    );
}

fn commitColumnsConfigured(
    self: *Runtime,
    allocator: std.mem.Allocator,
    columns: []const []const u32,
    log_sizes: []const u32,
    lifting_log_size: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    backings: ?[]const []M31,
) (MetalError || std.mem.Allocator.Error)!Tree {
    if (columns.len == 0 or columns.len != log_sizes.len) return MetalError.InvalidColumns;
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.InvalidColumns;

    const order = try allocator.alloc(usize, columns.len);
    defer allocator.free(order);
    for (order, 0..) |*entry, index| entry.* = index;
    const SortContext = struct {
        log_sizes: []const u32,

        fn lessThan(context: @This(), lhs: usize, rhs: usize) bool {
            const lhs_log = context.log_sizes[lhs];
            const rhs_log = context.log_sizes[rhs];
            return lhs_log < rhs_log or (lhs_log == rhs_log and lhs < rhs);
        }
    };
    std.sort.heap(usize, order, SortContext{ .log_sizes = log_sizes }, SortContext.lessThan);

    const sorted_log_sizes = try allocator.alloc(u32, columns.len);
    defer allocator.free(sorted_log_sizes);
    const sorted_columns = try allocator.alloc([*]const u32, columns.len);
    defer allocator.free(sorted_columns);
    const sorted_lengths = try allocator.alloc(usize, columns.len);
    defer allocator.free(sorted_lengths);
    for (order, 0..) |source_index, sorted_index| {
        const column = columns[source_index];
        const log_size = log_sizes[source_index];
        if (log_size > lifting_log_size or column.len != @as(usize, 1) << @intCast(log_size)) {
            return MetalError.InvalidColumns;
        }
        sorted_columns[sorted_index] = column.ptr;
        sorted_lengths[sorted_index] = column.len;
        sorted_log_sizes[sorted_index] = log_size;
    }

    const backing_ptrs = if (backings) |values| blk: {
        const ptrs = try allocator.alloc([*]const u32, values.len);
        for (values, ptrs) |backing, *ptr| ptr.* = @ptrCast(backing.ptr);
        break :blk ptrs;
    } else null;
    defer if (backing_ptrs) |ptrs| allocator.free(ptrs);
    const backing_lengths = if (backings) |values| blk: {
        const lengths = try allocator.alloc(usize, values.len);
        for (values, lengths) |backing, *len| len.* = backing.len;
        break :blk lengths;
    } else null;
    defer if (backing_lengths) |lengths| allocator.free(lengths);

    var message: [1024]u8 = [_]u8{0} ** 1024;
    const tree = ffi.stwo_zig_metal_merkle_commit(
        self.handle,
        sorted_columns.ptr,
        sorted_lengths.ptr,
        sorted_log_sizes.ptr,
        if (backing_ptrs) |ptrs| ptrs.ptr else null,
        if (backing_lengths) |lengths| lengths.ptr else null,
        if (backings) |values| @intCast(values.len) else 0,
        @intCast(columns.len),
        lifting_log_size,
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal commitment failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = tree, .runtime_handle = self.handle, .log_size = lifting_log_size };
}
