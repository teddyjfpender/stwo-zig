const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const protocol_mode = @import("protocol_mode.zig");

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const CommandEpoch = runtime.CommandEpoch;
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
const validDomainPrefixBytes = protocol_mode.validDomainPrefixBytes;
const resource_plans = @import("resource_plans.zig").ResourcePlans(MetalError);
const evalArguments = resource_plans.evalArguments;

pub fn prepareCircleLde(
    self: *Runtime,
    source_offsets: []const u64,
    destination_offsets: []const u64,
    base_log_size: u32,
    extended_log_size: u32,
    twiddle_offset_words: u32,
) MetalError!CircleLdePlan {
    if (source_offsets.len == 0 or source_offsets.len != destination_offsets.len or
        base_log_size < 3 or extended_log_size <= base_log_size or extended_log_size >= 31)
        return MetalError.CircleTransformFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_circle_lde_prepare(
        self.handle,
        source_offsets.ptr,
        destination_offsets.ptr,
        @intCast(source_offsets.len),
        base_log_size,
        extended_log_size,
        twiddle_offset_words,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal sparse circle LDE preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    };
    return .{ .handle = handle };
}

pub fn circleLdePrepared(self: *Runtime, arena: ResidentBuffer, plan: CircleLdePlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_lde_prepared(
        self.handle,
        arena.handle,
        plan.handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal sparse circle LDE failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn prepareCircleIfft(
    self: *Runtime,
    source_offsets: []const u64,
    destination_offsets: []const u64,
    log_size: u32,
    twiddle_offset_words: u32,
    scale_factor: u32,
) MetalError!CircleIfftPlan {
    if (source_offsets.len == 0 or source_offsets.len != destination_offsets.len or log_size < 3 or log_size >= 31)
        return MetalError.CircleTransformFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_circle_ifft_prepare(
        self.handle,
        source_offsets.ptr,
        destination_offsets.ptr,
        @intCast(source_offsets.len),
        log_size,
        twiddle_offset_words,
        scale_factor,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal sparse circle IFFT preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    };
    return .{ .handle = handle };
}

pub fn circleIfftPrepared(self: *Runtime, arena: ResidentBuffer, plan: CircleIfftPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_ifft_prepared(
        self.handle,
        arena.handle,
        plan.handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal sparse circle IFFT failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn prepareFixedTable(
    self: *Runtime,
    descriptors: []const u32,
    source_offsets: []const u32,
    multiplicity_offsets: []const u32,
    destination_offset: u32,
    row_count: u32,
) MetalError!FixedTablePlan {
    if (descriptors.len == 0 or descriptors.len % 4 != 0 or multiplicity_offsets.len == 0 or row_count == 0)
        return MetalError.WitnessFeedFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_fixed_table_prepare(
        self.handle,
        descriptors.ptr,
        @intCast(descriptors.len),
        source_offsets.ptr,
        @intCast(source_offsets.len),
        multiplicity_offsets.ptr,
        @intCast(multiplicity_offsets.len),
        destination_offset,
        row_count,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal fixed-table preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    };
    return .{ .handle = handle };
}

pub fn prepareFixedTableBatch(self: *Runtime, plans: []const FixedTablePlan) MetalError!FixedTableBatchPlan {
    if (plans.len == 0 or plans.len > 64) return MetalError.WitnessFeedFailed;
    var handles: [64]*anyopaque = undefined;
    for (plans, handles[0..plans.len]) |plan, *handle| handle.* = plan.handle;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_fixed_table_batch_prepare(
        self.handle,
        handles[0..plans.len].ptr,
        @intCast(plans.len),
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal fixed-table batch preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    };
    return .{ .handle = handle };
}

pub fn fixedTableBatchPrepared(self: *Runtime, arena: ResidentBuffer, batch: FixedTableBatchPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_fixed_table_batch_prepared(self.handle, arena.handle, batch.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal fixed-table batch failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn prepareMerkleParentChain(
    self: *Runtime,
    child_offsets: []const u32,
    destination_offsets: []const u32,
    parent_counts: []const u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!MerkleParentChainPlan {
    if (child_offsets.len == 0 or child_offsets.len > std.math.maxInt(u32) or
        child_offsets.len != destination_offsets.len or child_offsets.len != parent_counts.len)
        return MetalError.CommitmentFailed;
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    var required_words: u64 = 0;
    for (child_offsets, destination_offsets, parent_counts) |child, destination, count| {
        if (count == 0) return MetalError.CommitmentFailed;
        const child_words = std.math.mul(u64, count, 16) catch return MetalError.CommitmentFailed;
        const destination_words = std.math.mul(u64, count, 8) catch return MetalError.CommitmentFailed;
        required_words = @max(
            required_words,
            std.math.add(u64, child, child_words) catch return MetalError.CommitmentFailed,
            std.math.add(u64, destination, destination_words) catch return MetalError.CommitmentFailed,
        );
    }
    const required_arena_bytes = std.math.cast(
        usize,
        std.math.mul(u64, required_words, @sizeOf(u32)) catch return MetalError.CommitmentFailed,
    ) orelse return MetalError.CommitmentFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_merkle_parent_chain_prepare(
        self.handle,
        child_offsets.ptr,
        destination_offsets.ptr,
        parent_counts.ptr,
        @intCast(child_offsets.len),
        &node_seed,
        domain_prefix_bytes,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal Merkle parent-chain preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle, .required_arena_bytes = required_arena_bytes };
}

pub fn prepareMerkleLeaves(
    self: *Runtime,
    column_offsets: []const u32,
    column_log_sizes: []const u32,
    lifting_log_size: u32,
    destination_offset: u32,
    leaf_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!MerkleLeafPlan {
    if (column_offsets.len == 0 or column_offsets.len != column_log_sizes.len or lifting_log_size >= 31 or
        destination_offset % 64 != 0)
        return MetalError.CommitmentFailed;
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    for (column_log_sizes, 0..) |log_size, index| {
        if (log_size > lifting_log_size or (index != 0 and column_log_sizes[index - 1] > log_size))
            return MetalError.CommitmentFailed;
    }
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_merkle_leaf_prepare(
        self.handle,
        column_offsets.ptr,
        column_log_sizes.ptr,
        @intCast(column_offsets.len),
        lifting_log_size,
        destination_offset,
        &leaf_seed,
        domain_prefix_bytes,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal Merkle leaf preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle };
}

pub fn merkleLeavesPrepared(self: *Runtime, arena: ResidentBuffer, plan: MerkleLeafPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_merkle_leaf_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal Merkle leaves failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn prepareResidentMerkle(
    self: *Runtime,
    column_offsets: []const u32,
    column_log_sizes: []const u32,
    lifting_log_size: u32,
    layer_offsets: []const u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) MetalError!ResidentMerklePlan {
    if (column_offsets.len == 0 or column_offsets.len != column_log_sizes.len or lifting_log_size >= 31 or
        layer_offsets.len < 2 or layer_offsets.len > lifting_log_size + 1)
        return MetalError.CommitmentFailed;
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    for (column_log_sizes, 0..) |log_size, index| {
        if (log_size > lifting_log_size or (index != 0 and column_log_sizes[index - 1] > log_size))
            return MetalError.CommitmentFailed;
    }
    for (layer_offsets) |offset| if (offset % 64 != 0) return MetalError.CommitmentFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_resident_merkle_prepare(
        self.handle,
        column_offsets.ptr,
        column_log_sizes.ptr,
        @intCast(column_offsets.len),
        lifting_log_size,
        layer_offsets.ptr,
        @intCast(layer_offsets.len),
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal resident Merkle preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle, .lifting_log_size = lifting_log_size };
}

pub fn prepareResidentMerkleForHash(
    self: *Runtime,
    column_offsets: []const u32,
    column_log_sizes: []const u32,
    lifting_log_size: u32,
    layer_offsets: []const u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    hash_family: u32,
) MetalError!ResidentMerklePlan {
    if (column_offsets.len == 0 or column_offsets.len != column_log_sizes.len or
        lifting_log_size >= 31 or layer_offsets.len < 2 or
        layer_offsets.len > lifting_log_size + 1 or
        (hash_family != 1 and hash_family != 2))
        return MetalError.CommitmentFailed;
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    for (column_log_sizes, 0..) |log_size, index| {
        if (log_size > lifting_log_size or
            (index != 0 and column_log_sizes[index - 1] > log_size))
            return MetalError.CommitmentFailed;
    }
    for (layer_offsets) |offset| if (offset % 64 != 0)
        return MetalError.CommitmentFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_resident_merkle_prepare_v2(
        self.handle,
        column_offsets.ptr,
        column_log_sizes.ptr,
        @intCast(column_offsets.len),
        lifting_log_size,
        layer_offsets.ptr,
        @intCast(layer_offsets.len),
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        hash_family,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal resident Merkle preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle, .lifting_log_size = lifting_log_size };
}

/// ABI22 staged Poseidon leaf plan. The retained plan owns the exact sorted
/// column geometry and scratch offsets, so completed-arena adoption can require
/// provenance from this exact encoder rather than accepting a host assertion.
pub fn prepareStagedPoseidonResidentMerkleV1(
    self: *Runtime,
    column_offsets: []const u32,
    column_log_sizes: []const u32,
    lifting_log_size: u32,
    layer_offsets: []const u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    state_offsets: [2]u32,
) MetalError!ResidentMerklePlan {
    if (column_offsets.len <= 16 or column_offsets.len != column_log_sizes.len or
        lifting_log_size >= 31 or layer_offsets.len < 2 or
        layer_offsets.len > lifting_log_size + 1 or
        state_offsets[0] == state_offsets[1] or
        state_offsets[0] % 64 != 0 or state_offsets[1] % 64 != 0)
        return MetalError.CommitmentFailed;
    if (!validDomainPrefixBytes(domain_prefix_bytes)) return MetalError.CommitmentFailed;
    var has_distinct_log = false;
    for (column_log_sizes, 0..) |log_size, index| {
        if (log_size > lifting_log_size or
            (index != 0 and column_log_sizes[index - 1] > log_size))
            return MetalError.CommitmentFailed;
        if (index != 0 and column_log_sizes[index - 1] != log_size)
            has_distinct_log = true;
    }
    if (!has_distinct_log or column_log_sizes[column_log_sizes.len - 1] != lifting_log_size)
        return MetalError.CommitmentFailed;
    for (layer_offsets) |offset| if (offset % 64 != 0)
        return MetalError.CommitmentFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_resident_merkle_prepare_staged_poseidon_v1(
        self.handle,
        column_offsets.ptr,
        column_log_sizes.ptr,
        @intCast(column_offsets.len),
        lifting_log_size,
        layer_offsets.ptr,
        @intCast(layer_offsets.len),
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        &state_offsets,
        state_offsets.len,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal staged Poseidon Merkle preparation failed: {s}", .{
            std.mem.sliceTo(&message, 0),
        });
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle, .lifting_log_size = lifting_log_size };
}

/// Wraps a page-aligned, allocator-owned commitment arena without copying it.
/// The caller remains the sole owner of `words`; the returned Metal buffer only
/// retains a no-copy view and must be destroyed before the allocator frees it.
pub fn aliasCommitArena(self: *Runtime, words: []@import("stwo_core").fields.m31.M31) MetalError!ResidentBuffer {
    const byte_length = std.math.mul(usize, words.len, @sizeOf(@import("stwo_core").fields.m31.M31)) catch
        return MetalError.ColumnTooLarge;
    if (byte_length == 0 or @as(u64, @intCast(byte_length)) > self.maxBufferLength())
        return MetalError.ColumnTooLarge;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_commit_arena_alias(
        self.handle,
        @ptrCast(words.ptr),
        byte_length,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal commitment arena alias failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle, .contents = @ptrCast(words.ptr), .byte_length = byte_length };
}

/// Adopts the Merkle layers materialized by a completed caller-owned epoch.
/// No command is submitted here. Objective-C consumes proof that this exact
/// epoch completed this exact plan in this exact arena, and rejects reuse.
pub fn residentMerkleTreeFromCompletedArena(
    self: *Runtime,
    arena: ResidentBuffer,
    plan: ResidentMerklePlan,
    epoch: *CommandEpoch,
) MetalError!Tree {
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_resident_merkle_tree_from_completed_arena(
        self.handle,
        epoch.handle,
        arena.handle,
        plan.handle,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal completed Merkle arena adoption failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{ .handle = handle, .runtime_handle = self.handle, .log_size = plan.lifting_log_size };
}

pub fn residentMerklePrepared(self: *Runtime, arena: ResidentBuffer, plan: ResidentMerklePlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_resident_merkle_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal resident Merkle execution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn merkleParentChainPrepared(self: *Runtime, arena: ResidentBuffer, plan: MerkleParentChainPlan) MetalError!f64 {
    if (plan.required_arena_bytes > arena.byte_length) return MetalError.CommitmentFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_merkle_parent_chain_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal Merkle parent-chain failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }
    return gpu_ms;
}

pub fn prepareEcOp(
    self: *Runtime,
    execution_offsets: [37]u32,
    trace_offsets: [273]u32,
    partial_offsets: [127]u32,
    multiplicity_offsets: [4]u32,
    lookup_offset: u32,
    segment_offset: u32,
    scratch_offset: u32,
    row_count: u32,
    write_base: bool,
    write_lookup: bool,
) MetalError!EcOpPlan {
    if (row_count < 16 or !std.math.isPowerOfTwo(row_count)) return MetalError.WitnessFeedFailed;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_ec_op_prepare(
        self.handle,
        &execution_offsets,
        &trace_offsets,
        &partial_offsets,
        &multiplicity_offsets,
        lookup_offset,
        segment_offset,
        scratch_offset,
        row_count,
        write_base,
        write_lookup,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal EC-op preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    };
    return .{ .handle = handle };
}

pub fn ecOpPrepared(self: *Runtime, arena: ResidentBuffer, plan: EcOpPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_ec_op_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal EC-op execution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn prepareCompact(
    self: *Runtime,
    source_offsets: []const u32,
    descriptors: []const u32,
    output_offsets: []const u32,
    layout: CompactLayout,
) MetalError!CompactPlan {
    if (source_offsets.len == 0 or descriptors.len != source_offsets.len * 5 or output_offsets.len == 0 or
        layout.tuple_words == 0 or layout.key_words == 0 or layout.key_words > layout.tuple_words or
        layout.total_rows == 0 or layout.sort_rows < layout.total_rows or !std.math.isPowerOfTwo(layout.sort_rows) or
        layout.consumer_rows < 16 or !std.math.isPowerOfTwo(layout.consumer_rows))
        return MetalError.WitnessFeedFailed;
    const params = [21]u32{
        @intCast(source_offsets.len), layout.tuple_words,      layout.total_rows,       layout.sort_rows,
        layout.tuples_offset,         layout.indices_a_offset, layout.indices_b_offset, layout.counts_offset,
        layout.radix_offsets_offset,  layout.bases_offset,     layout.heads_offset,     layout.positions_offset,
        layout.block_sums_offset,     layout.error_offset,     layout.key_words,        @intCast(output_offsets.len),
        layout.consumer_rows,         layout.unique_offset,    layout.enabler_slot,     layout.multiplicity_slot,
        layout.iota_slot,
    };
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_compact_prepare(
        self.handle,
        source_offsets.ptr,
        @intCast(source_offsets.len),
        descriptors.ptr,
        @intCast(descriptors.len),
        output_offsets.ptr,
        @intCast(output_offsets.len),
        &params,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal compact preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    };
    return .{ .handle = handle };
}

pub fn compactPrepared(self: *Runtime, arena: ResidentBuffer, plan: CompactPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_compact_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal compact execution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn prepareEval(self: *Runtime, source: []const u8, name: []const u8, layout: EvalLayout) MetalError!EvalPlan {
    if (source.len == 0 or name.len == 0) return MetalError.PolynomialEvaluationFailed;
    const arguments = try evalArguments(layout);
    var message: [4096]u8 = [_]u8{0} ** 4096;
    const handle = ffi.stwo_zig_metal_eval_prepare(
        self.handle,
        source.ptr,
        source.len,
        name.ptr,
        name.len,
        &arguments,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal evaluation preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    };
    return .{ .handle = handle };
}

pub fn loadEvalLibrary(self: *Runtime, path: []const u8) MetalError!EvalLibrary {
    if (path.len == 0) return MetalError.PolynomialEvaluationFailed;
    var message: [4096]u8 = [_]u8{0} ** 4096;
    const handle = ffi.stwo_zig_metal_eval_library_load(self.handle, path.ptr, path.len, &message, message.len) orelse {
        std.log.err("Metal evaluation library load failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    };
    return .{ .handle = handle };
}

pub fn compileEvalLibrary(self: *Runtime, source: []const u8) MetalError!EvalLibrary {
    if (source.len == 0) return MetalError.PolynomialEvaluationFailed;
    var message: [4096]u8 = [_]u8{0} ** 4096;
    const handle = ffi.stwo_zig_metal_eval_library_compile(self.handle, source.ptr, source.len, &message, message.len) orelse {
        std.log.err("Metal source library compilation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    };
    return .{ .handle = handle };
}

pub fn prepareEvalFromLibrary(self: *Runtime, library: EvalLibrary, name: []const u8, layout: EvalLayout) MetalError!EvalPlan {
    if (name.len == 0) return MetalError.PolynomialEvaluationFailed;
    const arguments = try evalArguments(layout);
    var message: [4096]u8 = [_]u8{0} ** 4096;
    const handle = ffi.stwo_zig_metal_eval_prepare_library(
        self.handle,
        library.handle,
        name.ptr,
        name.len,
        &arguments,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal evaluation pipeline resolution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    };
    return .{ .handle = handle };
}

pub fn prepareWitnessFromLibrary(
    self: *Runtime,
    library: EvalLibrary,
    name: []const u8,
    layout: WitnessLayout,
) MetalError!WitnessPlan {
    if (name.len == 0 or layout.row_count == 0) return MetalError.WitnessFeedFailed;
    var message: [4096]u8 = [_]u8{0} ** 4096;
    const handle = ffi.stwo_zig_metal_witness_prepare_library(
        self.handle,
        library.handle,
        name.ptr,
        name.len,
        &layout,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal witness pipeline resolution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    };
    return .{ .handle = handle };
}

pub fn witnessPrepared(self: *Runtime, arena: ResidentBuffer, plan: WitnessPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_witness_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal witness execution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn evalPrepared(self: *Runtime, arena: ResidentBuffer, plan: EvalPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_eval_prepared(self.handle, arena.handle, plan.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal evaluation execution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    }
    return gpu_ms;
}

pub fn prepareEvalBatch(self: *Runtime, plans: []const EvalPlan) MetalError!EvalBatchPlan {
    _ = self;
    if (plans.len == 0) return MetalError.PolynomialEvaluationFailed;
    const handles: []const *anyopaque = @ptrCast(plans);
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_eval_batch_prepare(handles.ptr, @intCast(handles.len), &message, message.len) orelse {
        std.log.err("Metal evaluation batch preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    };
    return .{ .handle = handle };
}

pub fn evalBatchPrepared(self: *Runtime, arena: ResidentBuffer, batch: EvalBatchPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_eval_batch_prepared(self.handle, arena.handle, batch.handle, &gpu_ms, &message, message.len)) {
        std.log.err("Metal evaluation batch execution failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    }
    return gpu_ms;
}
