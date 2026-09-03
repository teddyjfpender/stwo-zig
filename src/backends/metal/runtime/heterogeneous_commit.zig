//! One-submit circle LDE and resident Merkle commitment for backed mixed-log trees.
//!
//! Admission is deliberately narrow: a materialized tree must arrive in one
//! page-aligned allocator-owned arena, retain its coefficients, use blowup one,
//! and contain at least two log sizes. All fallible layout and Metal-plan work
//! completes before the backing is resized. After that ownership boundary,
//! errors propagate and the caller's single backing list remains authoritative.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover = @import("stwo_prover_engine");
const combined_commit = @import("combined_commit.zig");
const commit_memory = @import("commit_memory.zig");
const metal_merkle = @import("../merkle_tree.zig");
const hash_domain = @import("../hash_domain.zig");
const ownership_testing = @import("ownership_testing.zig");
const precommitted_work = @import("precommitted_work.zig");
const shared_runtime = @import("../shared_runtime.zig");
const telemetry = @import("../telemetry.zig");

const M31 = m31.M31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const CircleCoefficients = prover.poly.circle.CircleCoefficients;
const ColumnSource = prover.pcs.ColumnSource;
const BackingTeardownToken = prover.pcs.BackingTeardownToken;

pub const StagedPoseidonTrafficReceiptV1 = struct {
    column_count: u32,
    lifting_log_size: u32,
    wide_column_reads: u64,
    staged_column_reads: u64,
    avoided_column_reads: u64,
    wide_leaf_permutations: u64,
    staged_leaf_permutations: u64,
    avoided_leaf_permutations: u64,
    retained_state_words: u64,
    terminal_digest_words: u64,
};

// Until a Tree2-sized device benchmark demonstrates a win, require enough
// eliminated permutations to amortize two 16-plane state slabs and the
// terminal packing pass. This is shape-derived and independent of any block,
// campaign, or fixed column count.
const minimum_staged_poseidon_permutations_avoided: u64 = 1 << 20;

pub fn admitsStagedPoseidonTrafficV1(receipt: StagedPoseidonTrafficReceiptV1) bool {
    return receipt.avoided_leaf_permutations >=
        minimum_staged_poseidon_permutations_avoided;
}

/// Exact traffic model for the ABI22 sorted-log staged Poseidon leaf encoder.
/// Null means the wide path remains authoritative (including Tree2-sized
/// inventories of at most sixteen columns).
pub fn stagedPoseidonTrafficReceiptV1(
    sorted_column_logs: []const u32,
    lifting_log_size: u32,
) ?StagedPoseidonTrafficReceiptV1 {
    if (sorted_column_logs.len <= 16 or lifting_log_size >= 31 or
        sorted_column_logs[sorted_column_logs.len - 1] != lifting_log_size)
        return null;
    var distinct_logs: u32 = 1;
    var staged_column_reads: u64 = 0;
    var staged_leaf_permutations: u64 = 0;
    var group_start: usize = 0;
    while (group_start < sorted_column_logs.len) {
        const group_log = sorted_column_logs[group_start];
        if (group_log > lifting_log_size or
            (group_start != 0 and sorted_column_logs[group_start - 1] > group_log))
            return null;
        var group_end = group_start + 1;
        while (group_end < sorted_column_logs.len and
            sorted_column_logs[group_end] == group_log)
            group_end += 1;
        if (group_start != 0) distinct_logs += 1;
        const rows = @as(u64, 1) << @intCast(group_log);
        const group_count: u64 = @intCast(group_end - group_start);
        staged_column_reads = std.math.add(
            u64,
            staged_column_reads,
            std.math.mul(u64, rows, group_count) catch return null,
        ) catch return null;
        const first_column: u64 = @intCast(group_start);
        const completed_rate_blocks = (first_column + group_count) / 8 - first_column / 8;
        staged_leaf_permutations = std.math.add(
            u64,
            staged_leaf_permutations,
            std.math.mul(u64, rows, completed_rate_blocks) catch return null,
        ) catch return null;
        group_start = group_end;
    }
    if (distinct_logs < 2) return null;
    const lifting_rows = @as(u64, 1) << @intCast(lifting_log_size);
    staged_leaf_permutations = std.math.add(
        u64,
        staged_leaf_permutations,
        lifting_rows,
    ) catch return null; // the canonical terminator permutation
    const column_count: u64 = @intCast(sorted_column_logs.len);
    const wide_column_reads = std.math.mul(u64, lifting_rows, column_count) catch return null;
    const wide_leaf_permutations = std.math.mul(
        u64,
        lifting_rows,
        column_count / 8 + 1,
    ) catch return null;
    if (staged_column_reads >= wide_column_reads or
        staged_leaf_permutations > wide_leaf_permutations)
        return null;
    return .{
        .column_count = std.math.cast(u32, sorted_column_logs.len) orelse return null,
        .lifting_log_size = lifting_log_size,
        .wide_column_reads = wide_column_reads,
        .staged_column_reads = staged_column_reads,
        .avoided_column_reads = wide_column_reads - staged_column_reads,
        .wide_leaf_permutations = wide_leaf_permutations,
        .staged_leaf_permutations = staged_leaf_permutations,
        .avoided_leaf_permutations = wide_leaf_permutations - staged_leaf_permutations,
        .retained_state_words = std.math.mul(u64, lifting_rows, 32) catch return null,
        .terminal_digest_words = std.math.mul(u64, lifting_rows, 16) catch return null,
    };
}

fn releaseArenaReservation(_: ?*anyopaque, bytes: u64) void {
    commit_memory.release(bytes);
}

// A base M1 can have only 8 GiB of unified memory. Keep all live heterogeneous
// commit arenas, including a source+destination resize peak, below both 1 GiB
// and one quarter of Metal's recommended working set. A zero device
// recommendation uses the conservative absolute cap.
const conservative_arena_byte_cap: u64 = 1 << 30;

fn arenaAdmissionByteCap(recommended_working_set_size: u64) u64 {
    if (recommended_working_set_size == 0) return conservative_arena_byte_cap;
    return @min(conservative_arena_byte_cap, recommended_working_set_size / 4);
}

// This is exactly the canonical key used by
// `vcs_lifted/columns.zig:sortByLogSizeAsc`: log size, then original index.
fn canonicalColumnLessThan(columns: []const ColumnEvaluation, lhs: usize, rhs: usize) bool {
    const lhs_log = columns[lhs].log_size;
    const rhs_log = columns[rhs].log_size;
    return lhs_log < rhs_log or (lhs_log == rhs_log and lhs < rhs);
}

const Group = struct {
    log_size: u32,
    indices: std.ArrayList(usize),
    inverse_twiddles: []const M31 = &.{},
    forward_twiddles: []const M31 = &.{},
    inverse_twiddle_offset: u32 = 0,
    forward_twiddle_offset: u32 = 0,
    ifft_plan: ?@import("../runtime.zig").CircleIfftPlan = null,
    lde_plan: ?@import("../runtime.zig").CircleLdePlan = null,

    fn deinit(self: *Group, allocator: std.mem.Allocator) void {
        if (self.ifft_plan) |*plan| plan.deinit();
        if (self.lde_plan) |*plan| plan.deinit();
        self.indices.deinit(allocator);
        self.* = undefined;
    }
};

/// Keeps the established uniform epoch first, then admits a single backed
/// mixed-log arena. Returning null never mutates the caller's inputs.
pub fn prepareAndCommitOwned(
    comptime H: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
    source_backing_buffers: ?[][]M31,
    source: ColumnSource,
) !?combined_commit.PreparedCommitment(H) {
    return prepareAndCommitOwnedImpl(
        false,
        H,
        allocator,
        owned_columns,
        log_blowup_factor,
        retention_policy,
        twiddle_source,
        source_backing_buffers,
        source,
        {},
    );
}

pub fn prepareAndCommitOwnedWithWorkRecorder(
    comptime H: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
    source_backing_buffers: ?[][]M31,
    source: ColumnSource,
    work_recorder: *precommitted_work.Recorder,
) !?combined_commit.PreparedCommitment(H) {
    return prepareAndCommitOwnedImpl(
        true,
        H,
        allocator,
        owned_columns,
        log_blowup_factor,
        retention_policy,
        twiddle_source,
        source_backing_buffers,
        source,
        work_recorder,
    );
}

fn prepareAndCommitOwnedImpl(
    comptime capture_work: bool,
    comptime H: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
    source_backing_buffers: ?[][]M31,
    source: ColumnSource,
    work_recorder: if (capture_work) *precommitted_work.Recorder else void,
) !?combined_commit.PreparedCommitment(H) {
    const uniform = if (capture_work)
        try combined_commit.prepareAndCommitOwnedWithWorkRecorder(
            H,
            allocator,
            owned_columns,
            log_blowup_factor,
            retention_policy,
            twiddle_source,
            source_backing_buffers,
            source,
            work_recorder,
        )
    else
        try combined_commit.prepareAndCommitOwned(
            H,
            allocator,
            owned_columns,
            log_blowup_factor,
            retention_policy,
            twiddle_source,
            source_backing_buffers,
            source,
        );
    if (uniform) |prepared| return prepared;

    return prepareAndCommitBackedHeterogeneous(
        capture_work,
        H,
        allocator,
        owned_columns,
        log_blowup_factor,
        retention_policy,
        twiddle_source,
        source_backing_buffers,
        source,
        work_recorder,
    );
}

fn prepareAndCommitBackedHeterogeneous(
    comptime capture_work: bool,
    comptime H: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
    source_backing_buffers: ?[][]M31,
    source: ColumnSource,
    work_recorder: if (capture_work) *precommitted_work.Recorder else void,
) !?combined_commit.PreparedCommitment(H) {
    const maybe_domain = comptime hash_domain.parameters(H);
    if (comptime maybe_domain == null) return null;
    const domain = maybe_domain.?;
    if (retention_policy != .always or log_blowup_factor != 1 or
        !source.isMaterialized() or owned_columns.len == 0 or
        @sizeOf(H.Hash) != 32)
        return null;
    const backing_buffers = source_backing_buffers orelse return null;
    if (backing_buffers.len != 1) return null;
    const original_arena = backing_buffers[0];
    const original_arena_address = @intFromPtr(original_arena.ptr);
    const page_words = std.heap.pageSize() / @sizeOf(M31);
    if (page_words == 0 or original_arena.len == 0 or
        @intFromPtr(original_arena.ptr) % std.heap.pageSize() != 0 or
        original_arena.len % page_words != 0)
        return null;

    const source_offsets = try allocator.alloc(usize, owned_columns.len);
    defer allocator.free(source_offsets);
    var groups = std.ArrayList(Group).empty;
    var total_base_words: u64 = 0;
    var maximum_base_log_size: u32 = 0;
    defer {
        for (groups.items) |*group| group.deinit(allocator);
        groups.deinit(allocator);
    }
    for (owned_columns, source_offsets, 0..) |column, *source_offset, column_index| {
        column.validate() catch return null;
        if (column.log_size < 3 or column.log_size >= 30) return null;
        total_base_words = std.math.add(
            u64,
            total_base_words,
            @intCast(column.values.len),
        ) catch return null;
        maximum_base_log_size = @max(maximum_base_log_size, column.log_size);
        const arena_begin = @intFromPtr(original_arena.ptr);
        const column_begin = @intFromPtr(column.values.ptr);
        if (column_begin < arena_begin or (column_begin - arena_begin) % @sizeOf(M31) != 0)
            return null;
        const offset = (column_begin - arena_begin) / @sizeOf(M31);
        if (offset > original_arena.len or column.values.len > original_arena.len - offset)
            return null;
        // Every IFFT mutates its source range in place. Reject aliased source
        // columns so a malformed backed input cannot create overlapping GPU
        // reads/writes; the generic path retains its normal ownership rules.
        for (owned_columns[0..column_index], source_offsets[0..column_index]) |prior, prior_offset| {
            if (offset < prior_offset + prior.values.len and
                prior_offset < offset + column.values.len)
                return null;
        }
        source_offset.* = offset;

        var group_index: ?usize = null;
        for (groups.items, 0..) |group, index| {
            if (group.log_size == column.log_size) {
                group_index = index;
                break;
            }
        }
        if (group_index) |index| {
            try groups.items[index].indices.append(allocator, column_index);
        } else {
            try groups.append(allocator, .{
                .log_size = column.log_size,
                .indices = std.ArrayList(usize).empty,
            });
            try groups.items[groups.items.len - 1].indices.append(allocator, column_index);
        }
    }
    if (groups.items.len < 2) return null;
    if (!combined_commit.admitsMeasuredHeterogeneousShape(
        owned_columns.len,
        maximum_base_log_size,
        total_base_words,
    ) and !ownership_testing.forceHeterogeneousAdmission()) return null;

    const evaluation_offsets = try allocator.alloc(usize, owned_columns.len);
    defer allocator.free(evaluation_offsets);
    // Twiddles are live only through the transform encoders. Fetch them now,
    // then place them over the later Merkle workspace rather than permanently
    // extending the retained arena.
    for (groups.items) |*group| {
        const base_twiddles = if (capture_work)
            try twiddle_source.getWithWorkRecorder(
                allocator,
                group.log_size,
                work_recorder,
            )
        else
            try twiddle_source.get(allocator, group.log_size);
        const extended_twiddles = if (capture_work)
            try twiddle_source.getWithWorkRecorder(
                allocator,
                group.log_size + 1,
                work_recorder,
            )
        else
            try twiddle_source.get(allocator, group.log_size + 1);
        group.inverse_twiddles = base_twiddles.itwiddles;
        group.forward_twiddles = extended_twiddles.twiddles;
    }

    var cursor = original_arena.len;
    var evaluation_words: u64 = 0;
    for (groups.items) |group| {
        cursor = std.mem.alignForward(usize, cursor, page_words);
        const extended_log_size = group.log_size + 1;
        const extended_len = @as(usize, 1) << @intCast(extended_log_size);
        const page_rotate = group.indices.items.len >= 64 and extended_len >= (1 << 18);
        const stride = std.math.add(
            usize,
            extended_len,
            if (page_rotate) page_words + 16 else if (group.indices.items.len >= 64) 16 else 0,
        ) catch return null;
        for (group.indices.items, 0..) |column_index, position| {
            const delta = std.math.mul(usize, position, stride) catch return null;
            evaluation_offsets[column_index] = std.math.add(usize, cursor, delta) catch return null;
        }
        const group_span = std.math.add(
            usize,
            std.math.mul(usize, group.indices.items.len - 1, stride) catch return null,
            extended_len,
        ) catch return null;
        cursor = std.math.add(usize, cursor, group_span) catch return null;
        evaluation_words = std.math.add(
            u64,
            evaluation_words,
            std.math.mul(
                u64,
                @intCast(group.indices.items.len),
                @intCast(extended_len),
            ) catch return null,
        ) catch return null;
    }

    var lifting_log_size: u32 = 0;
    for (owned_columns) |column| lifting_log_size = @max(lifting_log_size, column.log_size + 1);
    const order = try allocator.alloc(usize, owned_columns.len);
    defer allocator.free(order);
    for (order, 0..) |*entry, index| entry.* = index;
    std.sort.heap(usize, order, owned_columns, canonicalColumnLessThan);
    const merkle_offsets = try allocator.alloc(u32, owned_columns.len);
    defer allocator.free(merkle_offsets);
    const merkle_logs = try allocator.alloc(u32, owned_columns.len);
    defer allocator.free(merkle_logs);
    for (order, merkle_offsets, merkle_logs) |column_index, *offset, *log_size| {
        offset.* = std.math.cast(u32, evaluation_offsets[column_index]) orelse return null;
        log_size.* = owned_columns[column_index].log_size + 1;
    }
    const staged_traffic = if (domain.family == .poseidon2_m31)
        stagedPoseidonTrafficReceiptV1(merkle_logs, lifting_log_size)
    else
        null;
    const staged_poseidon = if (staged_traffic) |receipt|
        admitsStagedPoseidonTrafficV1(receipt)
    else
        false;
    const layer_offsets = try allocator.alloc(u32, @intCast(lifting_log_size + 1));
    defer allocator.free(layer_offsets);
    cursor = std.mem.alignForward(usize, cursor, 64);
    const merkle_workspace_start = cursor;
    var hashes = @as(u64, 1) << @intCast(lifting_log_size);
    for (layer_offsets) |*layer_offset| {
        cursor = std.mem.alignForward(usize, cursor, 64);
        layer_offset.* = std.math.cast(u32, cursor) orelse return null;
        cursor = std.math.add(
            usize,
            cursor,
            std.math.cast(usize, std.math.mul(u64, hashes, 8) catch return null) orelse return null,
        ) catch return null;
        hashes >>= 1;
    }
    const merkle_workspace_end = cursor;

    // Two disjoint full-capacity state slabs let each larger log lift from the
    // prior group without an in-flight read/write alias. They remain alive
    // through the terminal state-to-digest dispatch in the same command epoch.
    var staged_state_offsets = [_]u32{0} ** 2;
    if (staged_poseidon) {
        const state_words = std.math.mul(
            usize,
            @as(usize, 1) << @intCast(lifting_log_size),
            16,
        ) catch return null;
        for (&staged_state_offsets) |*state_offset| {
            cursor = std.mem.alignForward(usize, cursor, 64);
            state_offset.* = std.math.cast(u32, cursor) orelse return null;
            cursor = std.math.add(usize, cursor, state_words) catch return null;
        }
    }

    // Every transform encoder precedes the Merkle encoder in one command
    // buffer, so the Merkle layers may safely overwrite these temporary slabs.
    var twiddle_cursor = merkle_workspace_start;
    for (groups.items) |*group| {
        twiddle_cursor = std.mem.alignForward(usize, twiddle_cursor, 16);
        group.inverse_twiddle_offset = std.math.cast(u32, twiddle_cursor) orelse return null;
        twiddle_cursor = std.math.add(usize, twiddle_cursor, group.inverse_twiddles.len) catch return null;
        twiddle_cursor = std.mem.alignForward(usize, twiddle_cursor, 16);
        group.forward_twiddle_offset = std.math.cast(u32, twiddle_cursor) orelse return null;
        twiddle_cursor = std.math.add(usize, twiddle_cursor, group.forward_twiddles.len) catch return null;
    }
    if (twiddle_cursor > merkle_workspace_end) return null;
    const total_words = std.mem.alignForward(usize, cursor, page_words);
    if (total_words <= original_arena.len or total_words > std.math.maxInt(u32)) return null;

    var lease = shared_runtime.acquireExisting() catch return null;
    defer lease.deinit();
    const total_bytes = std.math.mul(usize, total_words, @sizeOf(M31)) catch return null;
    const total_bytes_u64 = std.math.cast(u64, total_bytes) orelse return null;
    if (total_bytes_u64 > lease.runtime.maxBufferLength()) return null;
    const original_bytes_u64 = std.math.mul(
        u64,
        @intCast(original_arena.len),
        @sizeOf(M31),
    ) catch return null;
    var arena_reservation = commit_memory.tryReserve(
        arenaAdmissionByteCap(lease.runtime.recommendedMaxWorkingSetSize()),
        total_bytes_u64,
        original_bytes_u64,
    ) orelse return null;
    defer arena_reservation.deinit();

    for (groups.items) |*group| {
        const group_sources = try allocator.alloc(u64, group.indices.items.len);
        defer allocator.free(group_sources);
        const group_evaluations = try allocator.alloc(u64, group.indices.items.len);
        defer allocator.free(group_evaluations);
        for (group.indices.items, group_sources, group_evaluations) |column_index, *source_offset, *evaluation_offset| {
            source_offset.* = @intCast(source_offsets[column_index]);
            evaluation_offset.* = @intCast(evaluation_offsets[column_index]);
        }
        const base_len = @as(u32, 1) << @intCast(group.log_size);
        const scale = try M31.fromCanonical(base_len).inv();
        group.ifft_plan = lease.runtime.prepareCircleIfft(
            group_sources,
            group_sources,
            group.log_size,
            group.inverse_twiddle_offset,
            scale.v,
        ) catch return null;
        group.lde_plan = lease.runtime.prepareCircleLde(
            group_sources,
            group_evaluations,
            group.log_size,
            group.log_size + 1,
            group.forward_twiddle_offset,
        ) catch return null;
    }
    var merkle_plan = if (staged_poseidon)
        lease.runtime.prepareStagedPoseidonResidentMerkleV1(
            merkle_offsets,
            merkle_logs,
            lifting_log_size,
            layer_offsets,
            domain.leaf_seed,
            domain.node_seed,
            domain.domain_prefix_bytes,
            staged_state_offsets,
        ) catch return null
    else
        lease.runtime.prepareResidentMerkleForHash(
            merkle_offsets,
            merkle_logs,
            lifting_log_size,
            layer_offsets,
            domain.leaf_seed,
            domain.node_seed,
            domain.domain_prefix_bytes,
            @intFromEnum(domain.family),
        ) catch return null;
    defer merkle_plan.deinit();

    // Allocate all returned descriptor storage before the ownership boundary.
    const columns = try allocator.alloc(ColumnEvaluation, owned_columns.len);
    var keep_columns = false;
    defer if (!keep_columns) allocator.free(columns);
    const coefficients = try allocator.alloc(CircleCoefficients, owned_columns.len);
    var initialized_coefficients: usize = 0;
    var keep_coefficients = false;
    defer if (!keep_coefficients) {
        for (coefficients[0..initialized_coefficients]) |*coefficient| coefficient.deinit(allocator);
        allocator.free(coefficients);
    };

    // Ownership boundary. `backing_buffers[0]` is updated immediately so the
    // caller's errdefer remains the only allocator owner if anything below
    // fails. Every borrowed source descriptor is then rebased by saved offset.
    const resized_arena = try allocator.realloc(original_arena, total_words);
    backing_buffers[0] = resized_arena;
    arena_reservation.finishResize();
    const resize_moved = @intFromPtr(resized_arena.ptr) != original_arena_address;
    if (resize_moved)
        telemetry.recordN(.metal_heterogeneous_commit_resize_moved_byte, original_bytes_u64);
    for (owned_columns, source_offsets) |*column, source_offset| {
        const column_len = @as(usize, 1) << @intCast(column.log_size);
        column.values = resized_arena[source_offset..][0..column_len];
    }
    if (@intFromPtr(resized_arena.ptr) % std.heap.pageSize() != 0 or
        resized_arena.len % page_words != 0)
        return error.UnsupportedArenaAlignment;
    try ownership_testing.failHeterogeneousAt(.after_resize);

    for (groups.items) |group| {
        @memcpy(
            resized_arena[group.inverse_twiddle_offset..][0..group.inverse_twiddles.len],
            group.inverse_twiddles,
        );
        @memcpy(
            resized_arena[group.forward_twiddle_offset..][0..group.forward_twiddles.len],
            group.forward_twiddles,
        );
    }

    var resident_arena = try lease.runtime.aliasCommitArena(resized_arena);
    defer resident_arena.deinit();
    try ownership_testing.failHeterogeneousAt(.after_alias);
    var epoch = try lease.runtime.beginCommandEpoch(resident_arena);
    defer epoch.deinit();
    var work_audit: if (capture_work) precommitted_work.Audit else void =
        if (capture_work)
            try precommitted_work.Audit.beginOwned(work_recorder)
        else {};
    defer if (capture_work) work_audit.deinit();
    for (groups.items) |group| {
        try epoch.encodeCircleIfft(group.ifft_plan.?);
        try epoch.encodeCircleLde(group.lde_plan.?);
    }
    try epoch.encodeResidentMerkle(merkle_plan);
    try epoch.submit();
    const stats = try epoch.wait();
    try ownership_testing.failHeterogeneousAt(.after_wait);

    var runtime_tree = try lease.runtime.residentMerkleTreeFromCompletedArena(
        resident_arena,
        merkle_plan,
        &epoch,
    );
    var runtime_tree_owned = true;
    errdefer if (runtime_tree_owned) runtime_tree.deinit();
    try ownership_testing.failHeterogeneousAt(.after_tree_adoption);
    // `fromSharedRuntime` consumes the runtime tree on both success and error.
    runtime_tree_owned = false;
    var commitment = try metal_merkle.MetalMerkleTree(H).fromSharedRuntime(runtime_tree);
    var keep_commitment = false;
    defer if (!keep_commitment) commitment.deinit(allocator);

    for (columns, coefficients, owned_columns, source_offsets, evaluation_offsets, 0..) |
        *column,
        *coefficient,
        source_column,
        source_offset,
        evaluation_offset,
        descriptor_index,
    | {
        const base_len = @as(usize, 1) << @intCast(source_column.log_size);
        const extended_len = base_len << 1;
        column.* = .{
            .log_size = source_column.log_size + 1,
            .values = resized_arena[evaluation_offset..][0..extended_len],
        };
        coefficient.* = try CircleCoefficients.initBorrowed(
            resized_arena[source_offset..][0..base_len],
        );
        initialized_coefficients += 1;
        if (descriptor_index == 0)
            try ownership_testing.failHeterogeneousAt(.during_descriptor_initialization);
    }

    if (capture_work) {
        var receipt_builder: precommitted_work.HeterogeneousReceipt = .{};
        for (groups.items) |group|
            try receipt_builder.addGroup(group.log_size, group.indices.items.len);
        const receipt = try receipt_builder.finish(
            @as(u64, 1) << @intCast(lifting_log_size),
        );
        try work_audit.complete(receipt);
    }

    // Only the descriptor array is obsolete; the resized backing now owns all
    // coefficients, evaluations, and resident Merkle layers. The temporary
    // twiddle ranges have already been overwritten by those layers.
    allocator.free(owned_columns);
    keep_columns = true;
    keep_coefficients = true;
    keep_commitment = true;

    telemetry.recordN(.metal_circle_lde_dispatch, @intCast(groups.items.len));
    telemetry.record(.resident_merkle_commit);
    telemetry.record(.metal_heterogeneous_commit_epoch);
    telemetry.recordN(.metal_heterogeneous_commit_command_buffer, stats.command_buffers);
    telemetry.recordN(.metal_heterogeneous_commit_wait, stats.wait_count);
    telemetry.recordN(.metal_heterogeneous_commit_dispatch, stats.dispatches);
    telemetry.recordN(.metal_heterogeneous_commit_arena_byte, total_bytes_u64);
    telemetry.recordN(
        .metal_heterogeneous_commit_staging_byte_avoided,
        evaluation_words * @sizeOf(M31),
    );
    if (staged_poseidon) {
        const traffic = staged_traffic.?;
        std.log.debug(
            "Metal staged Poseidon leaves: {} column reads avoided, {} leaf permutations avoided, {} retained-state bytes",
            .{
                traffic.avoided_column_reads,
                traffic.avoided_leaf_permutations,
                traffic.retained_state_words * @sizeOf(M31),
            },
        );
    }
    std.log.debug(
        "Metal heterogeneous commit epoch: {d:.3}ms, {} log groups, {} dispatches, {} command buffer, {} wait, {} arena bytes, {} staging bytes avoided",
        .{
            stats.gpu_milliseconds,
            groups.items.len,
            stats.dispatches,
            stats.command_buffers,
            stats.wait_count,
            total_bytes_u64,
            evaluation_words * @sizeOf(M31),
        },
    );
    const backing_teardown = BackingTeardownToken.init(
        null,
        arena_reservation.transferRetained(),
        releaseArenaReservation,
    );
    return .{
        .columns = columns,
        .coefficients = coefficients,
        .column_backing_buffers = backing_buffers,
        .coefficient_backing_buffers = null,
        .backing_teardown = backing_teardown,
        .commitment = commitment,
    };
}

test "heterogeneous commit sort order is log then canonical index" {
    const columns = [_]ColumnEvaluation{
        .{ .log_size = 7, .values = &.{} },
        .{ .log_size = 5, .values = &.{} },
        .{ .log_size = 7, .values = &.{} },
        .{ .log_size = 6, .values = &.{} },
    };
    var order = [_]usize{ 0, 1, 2, 3 };
    const column_context: []const ColumnEvaluation = &columns;
    std.sort.heap(usize, &order, column_context, canonicalColumnLessThan);
    try std.testing.expectEqualSlices(usize, &.{ 1, 3, 0, 2 }, &order);
}

test "heterogeneous commit arena admission reserves M1 working-set headroom" {
    try std.testing.expectEqual(
        conservative_arena_byte_cap,
        arenaAdmissionByteCap(0),
    );
    try std.testing.expectEqual(
        @as(u64, 512 << 20),
        arenaAdmissionByteCap(2 << 30),
    );
    try std.testing.expectEqual(
        conservative_arena_byte_cap,
        arenaAdmissionByteCap(8 << 30),
    );
}

test "heterogeneous commit reuses the measured uniform crossover" {
    const threshold_words = @as(u64, 8) << 16;
    try std.testing.expect(!combined_commit.admitsMeasuredHeterogeneousShape(
        8,
        15,
        threshold_words,
    ));
    try std.testing.expect(!combined_commit.admitsMeasuredHeterogeneousShape(
        8,
        16,
        threshold_words - 1,
    ));
    try std.testing.expect(combined_commit.admitsMeasuredHeterogeneousShape(
        8,
        16,
        threshold_words,
    ));
}
