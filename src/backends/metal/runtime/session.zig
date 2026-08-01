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
const ArchiveStoreStatsV1 = runtime.ArchiveStoreStatsV1;
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
const core_aot = @import("../core_aot.zig");
const shader_manifest = @import("../shaders/manifest.zig");
const runtime_initialization = @import("initialization.zig").Initialization(MetalError);

pub fn init() MetalError!Runtime {
    return .{ .handle = try runtime_initialization.fromSource(shader_manifest.native_amalgamated_source.ptr) };
}

/// Compatibility path for deferred Cairo integrations that still share this runtime ABI.
pub fn initFull() MetalError!Runtime {
    return .{ .handle = try runtime_initialization.fromFullSource(shader_manifest.amalgamated_source.ptr) };
}

/// Deferred diagnostic escape hatch. Native production callers must use `initFromAotBundle`.
pub fn initFromMetallibUnchecked(path: []const u8) MetalError!Runtime {
    return .{ .handle = try runtime_initialization.fromMetallib(path) };
}

/// Loads only after the complete Native AOT bundle matches the compiled-in authority.
pub fn initFromAotBundle(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
    expected_manifest_sha256: [32]u8,
) MetalError!Runtime {
    var admission = core_aot.admit(allocator, bundle_path, expected_manifest_sha256) catch |err| {
        std.log.err("Metal core AOT admission failed: {s}", .{@errorName(err)});
        return MetalError.RuntimeInitializationFailed;
    };
    defer admission.deinit();

    return initFromAotAdmission(&admission);
}

/// Constructs a runtime from bytes already admitted by the process owner.
pub fn initFromAotAdmission(admission: *const core_aot.Admission) MetalError!Runtime {
    return .{ .handle = try runtime_initialization.fromMetallibData(admission.metallib_bytes) };
}

/// Constructs from admitted bytes on an explicitly selected device.
///
/// Process owners normally use `initFromAotAdmission`; this boundary exists
/// for multi-device schedulers and deterministic device-admission tests.
pub fn initFromMetallibDataOnDevice(
    device: ?*anyopaque,
    bytes: []const u8,
) MetalError!Runtime {
    return .{
        .handle = try runtime_initialization.fromMetallibDataOnDevice(
            device,
            bytes,
        ),
    };
}

pub fn deinit(self: *Runtime) void {
    ffi.stwo_zig_metal_runtime_destroy(self.handle);
    self.* = undefined;
}

pub fn pipelineCacheStats(self: *const Runtime) PipelineCacheStats {
    var stats = PipelineCacheStats.zero();
    _ = ffi.stwo_zig_metal_pipeline_cache_stats(self.handle, &stats);
    return stats;
}

pub fn archiveStoreStats(self: *const Runtime) ArchiveStoreStatsV1 {
    var stats = ArchiveStoreStatsV1.zero();
    _ = ffi.stwo_zig_metal_archive_store_stats_v1(self.handle, &stats, @sizeOf(ArchiveStoreStatsV1));
    return stats;
}

pub fn maxBufferLength(self: *const Runtime) u64 {
    return ffi.stwo_zig_metal_max_buffer_length(self.handle);
}

pub fn recommendedMaxWorkingSetSize(self: *const Runtime) u64 {
    return ffi.stwo_zig_metal_recommended_max_working_set_size(self.handle);
}

pub fn platformIdentityAlloc(self: *const Runtime, allocator: std.mem.Allocator) MetalError![]u8 {
    const length = ffi.stwo_zig_metal_runtime_identity(self.handle, null, 0);
    if (length == 0) return MetalError.RuntimeIdentityFailed;
    const result = allocator.alloc(u8, length) catch return MetalError.RuntimeIdentityFailed;
    errdefer allocator.free(result);
    if (ffi.stwo_zig_metal_runtime_identity(self.handle, result.ptr, result.len) != length)
        return MetalError.RuntimeIdentityFailed;
    return result;
}

pub fn allocateResidentBuffer(self: *Runtime, byte_length: usize) MetalError!ResidentBuffer {
    const maximum = self.maxBufferLength();
    if (maximum == 0 or byte_length > maximum) {
        std.log.err("Metal resident buffer length {} exceeds device maxBufferLength {}", .{ byte_length, maximum });
        return MetalError.ColumnTooLarge;
    }
    var contents: *anyopaque = undefined;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_buffer_create(
        self.handle,
        byte_length,
        &contents,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal resident buffer allocation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.RuntimeInitializationFailed;
    };
    return .{ .handle = handle, .contents = contents, .byte_length = byte_length };
}

pub fn beginCommandEpoch(self: *Runtime, arena: ResidentBuffer) MetalError!CommandEpoch {
    return CommandEpoch.init(
        self.handle,
        arena.handle,
        arena.byte_length,
    ) catch MetalError.CommandEpochFailed;
}

pub fn prepareArenaCopies(self: *Runtime, ranges: []const ArenaCopyRange) MetalError!ArenaCopyPlan {
    if (ranges.len == 0) return MetalError.InvalidColumns;
    for (ranges) |range| if (range.word_count == 0) return MetalError.InvalidColumns;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_arena_copy_prepare(
        self.handle,
        ranges.ptr,
        @intCast(ranges.len),
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal arena copy preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.InvalidColumns;
    };
    return .{ .handle = handle };
}

pub fn arenaCopyPrepared(self: *Runtime, arena: ResidentBuffer, plan: ArenaCopyPlan) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_arena_copy_prepared(
        self.handle,
        arena.handle,
        plan.handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal prepared arena copy failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.InvalidColumns;
    }
    return gpu_ms;
}

pub fn preparedStateTransfer(
    self: *Runtime,
    arena: ResidentBuffer,
    snapshot: ResidentBuffer,
    ranges: []const PreparedStateRange,
    capture: bool,
    clear_arena: bool,
) MetalError!f64 {
    if (ranges.len == 0 or (capture and clear_arena)) return MetalError.InvalidColumns;
    for (ranges) |range| {
        if (range.byte_count == 0) return MetalError.InvalidColumns;
        const arena_end = std.math.add(u64, range.arena_byte_offset, range.byte_count) catch
            return MetalError.InvalidColumns;
        const snapshot_end = std.math.add(u64, range.snapshot_byte_offset, range.byte_count) catch
            return MetalError.InvalidColumns;
        if (arena_end > arena.byte_length or snapshot_end > snapshot.byte_length)
            return MetalError.InvalidColumns;
    }
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_prepared_state_transfer(
        self.handle,
        arena.handle,
        snapshot.handle,
        ranges.ptr,
        @intCast(ranges.len),
        capture,
        clear_arena,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal prepared-state transfer failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.InvalidColumns;
    }
    return gpu_ms;
}

pub fn clearArenaRanges(self: *Runtime, arena: ResidentBuffer, ranges: []const [2]u32) MetalError!void {
    if (ranges.len == 0) return;
    var max_length: u32 = 0;
    for (ranges) |range| {
        max_length = @max(max_length, range[1]);
        const end = @as(u64, range[0]) + range[1];
        if (end * @sizeOf(u32) > arena.byte_length) return MetalError.WitnessFeedFailed;
    }
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_clear_arena_ranges(self.handle, arena.handle, ranges.ptr, @intCast(ranges.len), max_length, &message, message.len)) {
        std.log.err("Metal arena clear failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
}

pub fn witnessFeedCounts(
    self: *Runtime,
    arena: ResidentBuffer,
    column_length: u32,
    descriptors: []const u32,
    luts: []const u32,
    destination_offsets: []const u32,
    source_offsets: []const u32,
    clear_ranges: []const [2]u32,
) MetalError!f64 {
    if (descriptors.len == 0 or descriptors.len % 14 != 0 or column_length == 0 or destination_offsets.len == 0 or source_offsets.len == 0)
        return MetalError.WitnessFeedFailed;
    const arena_words = arena.byte_length / @sizeOf(u32);
    for (source_offsets) |offset| {
        if (@as(u64, offset) + column_length > arena_words) return MetalError.WitnessFeedFailed;
    }
    var descriptor_index: usize = 0;
    while (descriptor_index < descriptors.len) : (descriptor_index += 14) {
        const e = descriptors[descriptor_index .. descriptor_index + 14];
        const source_count: u32 = if (e[11] == 1) 1 else if (e[11] == 2 or e[11] == 3) 3 else e[1];
        if (@as(u64, e[0]) + source_count > source_offsets.len) return MetalError.WitnessFeedFailed;
        const destination_count: u32 = if (e[11] == 3) 16 else e[7] + 1;
        if (@as(u64, e[10]) + destination_count > destination_offsets.len) return MetalError.WitnessFeedFailed;
        for (destination_offsets[e[10] .. e[10] + destination_count]) |offset| {
            if (@as(u64, offset) + e[8] > arena_words) return MetalError.WitnessFeedFailed;
        }
        if (e[11] == 1) {
            if (@as(u64, e[13]) + e[7] >= destination_offsets.len or
                @as(u64, destination_offsets[e[13] + e[7]]) + e[12] > arena_words)
                return MetalError.WitnessFeedFailed;
        }
        if (e[9] != std.math.maxInt(u32)) {
            const required_lut_words: u64 = if (e[11] == 2)
                @as(u64, 1) << @intCast(2 * e[2])
            else
                e[8];
            if (@as(u64, e[9]) + required_lut_words > luts.len) return MetalError.WitnessFeedFailed;
        }
    }
    const descriptor_count: u32 = @intCast(descriptors.len / 14);
    _ = descriptor_count;
    var plan = try self.prepareWitnessFeed(descriptors, luts, destination_offsets, source_offsets, clear_ranges);
    defer plan.deinit();
    return self.witnessFeedCountsPrepared(arena, column_length, plan);
}

pub fn prepareWitnessFeed(
    self: *Runtime,
    descriptors: []const u32,
    luts: []const u32,
    destination_offsets: []const u32,
    source_offsets: []const u32,
    clear_ranges: []const [2]u32,
) MetalError!WitnessFeedPlan {
    if (descriptors.len == 0 or descriptors.len % 14 != 0 or destination_offsets.len == 0 or source_offsets.len == 0 or clear_ranges.len == 0)
        return MetalError.WitnessFeedFailed;
    var clear_max_length: u32 = 0;
    for (clear_ranges) |range| {
        if (range[1] == 0) return MetalError.WitnessFeedFailed;
        clear_max_length = @max(clear_max_length, range[1]);
    }
    const empty_lut = [_]u32{0};
    const lut_words = if (luts.len == 0) empty_lut[0..] else luts;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_witness_feed_prepare(
        self.handle,
        descriptors.ptr,
        @intCast(descriptors.len / 14),
        lut_words.ptr,
        luts.len,
        destination_offsets.ptr,
        destination_offsets.len,
        source_offsets.ptr,
        source_offsets.len,
        clear_ranges.ptr,
        @intCast(clear_ranges.len),
        clear_max_length,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal witness feed preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    };
    return .{ .handle = handle };
}

pub fn witnessFeedCountsPrepared(
    self: *Runtime,
    arena: ResidentBuffer,
    column_length: u32,
    plan: WitnessFeedPlan,
) MetalError!f64 {
    if (column_length == 0) return MetalError.WitnessFeedFailed;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_witness_feed_counts_prepared(
        self.handle,
        arena.handle,
        plan.handle,
        column_length,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal witness feed failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn prepareWitnessFeedBatch(
    self: *Runtime,
    plans: []const WitnessFeedPlan,
    column_lengths: []const u32,
    clear_ranges: []const [2]u32,
) MetalError!WitnessFeedBatchPlan {
    if (plans.len == 0 or plans.len > 256 or plans.len != column_lengths.len or clear_ranges.len == 0)
        return MetalError.WitnessFeedFailed;
    var handles: [256]*anyopaque = undefined;
    for (plans, handles[0..plans.len]) |plan, *handle| handle.* = plan.handle;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_witness_feed_batch_prepare(
        self.handle,
        handles[0..plans.len].ptr,
        column_lengths.ptr,
        @intCast(plans.len),
        clear_ranges.ptr,
        @intCast(clear_ranges.len),
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal witness feed batch preparation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    };
    return .{ .handle = handle };
}

pub fn witnessFeedBatchCountsPrepared(
    self: *Runtime,
    arena: ResidentBuffer,
    batch: WitnessFeedBatchPlan,
) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_witness_feed_batch_counts_prepared(
        self.handle,
        arena.handle,
        batch.handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal witness feed batch failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn witnessFeedBatchClearPrepared(
    self: *Runtime,
    arena: ResidentBuffer,
    batch: WitnessFeedBatchPlan,
) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_witness_feed_batch_clear_prepared(
        self.handle,
        arena.handle,
        batch.handle,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal witness feed batch clear failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}

pub fn witnessFeedBatchIndexPrepared(
    self: *Runtime,
    arena: ResidentBuffer,
    batch: WitnessFeedBatchPlan,
    index: u32,
) MetalError!f64 {
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_witness_feed_batch_index_prepared(
        self.handle,
        arena.handle,
        batch.handle,
        index,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal witness feed batch index failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.WitnessFeedFailed;
    }
    return gpu_ms;
}
