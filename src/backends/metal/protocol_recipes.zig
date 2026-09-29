const std = @import("std");
const arena_plan = @import("arena_plan.zig");
const recovery = @import("recovery.zig");
const runtime = @import("runtime.zig");
const blake2s_channel = @import("stwo_core").channel.blake2s;
const fri_geometry = @import("stwo_core").fri.geometry;
const cairo_merkle = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const aot_witness = @import("recipes/aot_witness.zig");
const circle_recipes = @import("recipes/circle.zig");
const compact = @import("recipes/compact.zig");
const composition = @import("recipes/composition.zig");
const ec_op = @import("recipes/ec_op.zig");
const fixed_tables = @import("recipes/fixed_tables.zig");
const fri_recipes = @import("recipes/fri.zig");
const merkle_recipes = @import("recipes/merkle.zig");
const proof_assembly = @import("recipes/proof_assembly.zig");
const recovery_primitives = @import("recipes/recovery_primitives.zig");
const relation = @import("recipes/relation.zig");
const witness_feed = @import("recipes/witness_feed.zig");

const validateFriOpeningRound = fri_recipes.validateFriOpeningRound;

const cairo_domain_prefix_bytes = cairo_merkle.domainPrefixBytes();

pub const FriGeometry = fri_recipes.FriGeometry;
pub const AotWitnessInvocation = aot_witness.Invocation;
pub const AotWorkspaceWrite = aot_witness.WorkspaceWrite;
pub const AotWitnessBatchRecipe = aot_witness.BatchRecipe;
pub const CircleTransformRecipe = circle_recipes.TransformRecipe;
pub const CircleLdeRecipe = circle_recipes.LdeRecipe;
pub const CircleIfftRecipe = circle_recipes.IfftRecipe;
pub const CompactBindings = compact.Bindings;
pub const CompactRecipe = compact.Recipe;
pub const CompositionFinalizeRecipe = composition.FinalizeRecipe;
pub const CompositionRecipe = composition.Recipe;
pub const EcOpBindings = ec_op.Bindings;
pub const EcOpOutputMode = ec_op.OutputMode;
pub const EcOpRecipe = ec_op.Recipe;
pub const FixedTableBindings = fixed_tables.Bindings;
pub const FixedTableBatchRecipe = fixed_tables.BatchRecipe;
pub const FriFoldRecipe = fri_recipes.FriFoldRecipe;
pub const QuotientRecipe = fri_recipes.QuotientRecipe;
pub const FriRecipe = fri_recipes.FriRecipe;
pub const MerkleParentChainRecipe = merkle_recipes.ParentChainRecipe;
pub const MerkleCommitRecipe = merkle_recipes.CommitRecipe;
pub const ProofCopy = proof_assembly.ProofCopy;
pub const ProofAssemblyRecipe = proof_assembly.ProofAssemblyRecipe;
pub const CopyRecipe = recovery_primitives.CopyRecipe;
pub const HostCopyRecipe = recovery_primitives.HostCopyRecipe;
pub const ZeroRecipe = recovery_primitives.ZeroRecipe;
pub const RelationInstanceBindings = relation.RelationInstanceBindings;
pub const RelationRecipe = relation.RelationRecipe;
pub const DestinationColumns = witness_feed.DestinationColumns;
pub const BoundWitnessFeed = witness_feed.BoundWitnessFeed;
pub const WitnessFeedRecipe = witness_feed.WitnessFeedRecipe;
pub const WitnessFeedBatchEntry = witness_feed.WitnessFeedBatchEntry;
pub const WitnessFeedBatchRecipe = witness_feed.WitnessFeedBatchRecipe;

pub const TranscriptBinding = struct {
    ordinal: u32,
    binding: arena_plan.Binding,
};

fn bindingWordOffset(binding: arena_plan.Binding) !u64 {
    if (binding.offset_bytes % 4 != 0) return recovery.RecoveryError.BindingSizeMismatch;
    return binding.offset_bytes / 4;
}

const PendingTraceGather = struct {
    column_offsets: u64,
    column_logs: u64,
    column_count: u32,
    lifting_log: u32,
    first_column: u32,
    stride: u32,
    values: u64,
};

/// Query-normalization and FRI coset preparation for a validated Cairo opening
/// schedule. All FRI trees reuse the same epoch-local workspaces; only their
/// authenticated cumulative fold differs.
pub const DecommitQueryRecipe = struct {
    metal: *runtime.Runtime,
    arena: *arena_plan.ResidentArena,
    raw_queries: arena_plan.Binding,
    unique_queries: arena_plan.Binding,
    mapped_queries: arena_plan.Binding,
    expanded_positions: arena_plan.Binding,
    walk_queries: arena_plan.Binding,
    walk_scratch: arena_plan.Binding,
    sparse_indices: arena_plan.Binding,
    sparse_hashes: arena_plan.Binding,
    counts: arena_plan.Binding,
    assembly: arena_plan.Binding,
    tree_count: u32,
    fri_geometry: FriGeometry,
    pending_trace_gather: ?PendingTraceGather = null,
    accumulated_gpu_ms: f64 = 0,

    pub fn init(
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        raw_queries: arena_plan.Binding,
        unique_queries: arena_plan.Binding,
        mapped_queries: arena_plan.Binding,
        expanded_positions: arena_plan.Binding,
        walk_queries: arena_plan.Binding,
        walk_scratch: arena_plan.Binding,
        sparse_indices: arena_plan.Binding,
        sparse_hashes: arena_plan.Binding,
        counts: arena_plan.Binding,
        assembly: arena_plan.Binding,
        tree_count: u32,
        fri_start_log: u32,
    ) !DecommitQueryRecipe {
        return initWithGeometry(
            metal,
            resident_arena,
            raw_queries,
            unique_queries,
            mapped_queries,
            expanded_positions,
            walk_queries,
            walk_scratch,
            sparse_indices,
            sparse_hashes,
            counts,
            assembly,
            tree_count,
            try FriGeometry.init(fri_start_log),
        );
    }

    pub fn initWithGeometry(
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        raw_queries: arena_plan.Binding,
        unique_queries: arena_plan.Binding,
        mapped_queries: arena_plan.Binding,
        expanded_positions: arena_plan.Binding,
        walk_queries: arena_plan.Binding,
        walk_scratch: arena_plan.Binding,
        sparse_indices: arena_plan.Binding,
        sparse_hashes: arena_plan.Binding,
        counts: arena_plan.Binding,
        assembly: arena_plan.Binding,
        tree_count: u32,
        geometry: FriGeometry,
    ) !DecommitQueryRecipe {
        for ([_]arena_plan.Binding{ raw_queries, unique_queries, mapped_queries, expanded_positions, walk_queries, walk_scratch, sparse_indices, sparse_hashes, counts }) |binding| {
            if (binding.offset_bytes % 4 != 0) return recovery.RecoveryError.BindingSizeMismatch;
        }
        if (raw_queries.size_bytes != 70 * 4 or unique_queries.size_bytes < raw_queries.size_bytes or tree_count == 0 or
            mapped_queries.size_bytes < raw_queries.size_bytes or expanded_positions.size_bytes < 560 * 4 or
            walk_queries.size_bytes < 560 * 4 or walk_scratch.size_bytes < walk_queries.size_bytes or sparse_indices.size_bytes < 560 * 4 or counts.size_bytes < 4 * 4 or
            assembly.offset_bytes % 4 != 0 or assembly.size_bytes / 4 > std.math.maxInt(u32))
            return recovery.RecoveryError.BindingSizeMismatch;
        return .{
            .metal = metal,
            .arena = resident_arena,
            .raw_queries = raw_queries,
            .unique_queries = unique_queries,
            .mapped_queries = mapped_queries,
            .expanded_positions = expanded_positions,
            .walk_queries = walk_queries,
            .walk_scratch = walk_scratch,
            .sparse_indices = sparse_indices,
            .sparse_hashes = sparse_hashes,
            .counts = counts,
            .assembly = assembly,
            .tree_count = tree_count,
            .fri_geometry = geometry,
        };
    }

    pub fn normalize(self: *DecommitQueryRecipe) !void {
        if (self.pending_trace_gather != null) return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitNormalizeQueries(
            self.arena.buffer,
            try bindingWordOffset(self.raw_queries),
            70,
            self.fri_geometry.start_log,
            try bindingWordOffset(self.unique_queries),
            count_base,
            self.tree_count,
            try bindingWordOffset(self.assembly),
            @intCast(self.assembly.size_bytes / 4),
        );
    }

    pub fn prepareFri(self: *DecommitQueryRecipe, round: usize) !void {
        if (self.pending_trace_gather != null or round >= self.fri_geometry.roundCount())
            return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitPrepareFriQueries(
            self.arena.buffer,
            try bindingWordOffset(self.unique_queries),
            count_base,
            70,
            try self.fri_geometry.cumulativeFold(round),
            try self.fri_geometry.roundFold(round),
            self.fri_geometry.packedLog(),
            try bindingWordOffset(self.mapped_queries),
            count_base + 1,
            try bindingWordOffset(self.expanded_positions),
            count_base + 3,
            try bindingWordOffset(self.walk_queries),
            count_base + 2,
        );
    }

    /// Encodes query preparation, coordinate gathering, and proof assembly for
    /// one FRI tree into a single command buffer. There is no host dependency
    /// between these kernels; separate encoders preserve their device ordering.
    pub fn executeFriRound(
        self: *DecommitQueryRecipe,
        round: usize,
        tree_index: u32,
        leaf_log: u32,
        coordinate_offsets: arena_plan.Binding,
        retained_offsets: arena_plan.Binding,
        values: arena_plan.Binding,
    ) !void {
        if (self.pending_trace_gather != null) return recovery.RecoveryError.BindingSizeMismatch;
        try validateFriOpeningRound(self.fri_geometry, round, leaf_log);
        if (coordinate_offsets.size_bytes < 8 * @sizeOf(u32) or
            retained_offsets.size_bytes < @as(u64, leaf_log + 1) * 2 * @sizeOf(u32) or
            values.size_bytes < self.expanded_positions.size_bytes * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitFriRound(
            self.arena.buffer,
            .{
                .unique_base = try bindingWordOffset(self.unique_queries),
                .unique_count_base = count_base,
                .tree_queries_base = try bindingWordOffset(self.mapped_queries),
                .tree_count_base = count_base + 1,
                .expanded_base = try bindingWordOffset(self.expanded_positions),
                .expanded_count_base = count_base + 3,
                .walk_base = try bindingWordOffset(self.walk_queries),
                .walk_count_base = count_base + 2,
                .coordinate_bases = try bindingWordOffset(coordinate_offsets),
                .values_base = try bindingWordOffset(values),
                .walk_scratch_base = try bindingWordOffset(self.walk_scratch),
                .retained_offsets = try bindingWordOffset(retained_offsets),
                .assembly_base = try bindingWordOffset(self.assembly),
                .max_queries = 70,
                .cumulative_fold = try self.fri_geometry.cumulativeFold(round),
                .fold_step = try self.fri_geometry.roundFold(round),
                .packed_log = self.fri_geometry.packedLog(),
                .max_positions = @intCast(self.expanded_positions.size_bytes / @sizeOf(u32)),
                .tree_index = tree_index,
                .leaf_log = leaf_log,
                .assembly_capacity = @intCast(self.assembly.size_bytes / @sizeOf(u32)),
            },
        );
    }

    pub fn prepareTrace(
        self: *DecommitQueryRecipe,
        source_log: u32,
        tree_log: u32,
        leaf_log: u32,
        unretained: u32,
    ) !void {
        if (self.pending_trace_gather != null) return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitPrepareTraceQueries(
            self.arena.buffer,
            try bindingWordOffset(self.unique_queries),
            count_base,
            70,
            source_log,
            tree_log,
            leaf_log,
            unretained,
            try bindingWordOffset(self.mapped_queries),
            count_base + 1,
            try bindingWordOffset(self.walk_queries),
            count_base + 2,
            try bindingWordOffset(self.sparse_indices),
            count_base + 4,
        );
    }

    pub fn gatherTraceValues(
        self: *DecommitQueryRecipe,
        column_offsets: arena_plan.Binding,
        column_logs: arena_plan.Binding,
        column_count: u32,
        lifting_log: u32,
        first_column: u32,
        stride: u32,
        values: arena_plan.Binding,
    ) !void {
        if (self.pending_trace_gather != null) return recovery.RecoveryError.BindingSizeMismatch;
        if (column_count == 0 or lifting_log >= 31 or stride < 70 or
            column_offsets.size_bytes < @as(u64, column_count) * 4 or
            column_logs.size_bytes < @as(u64, column_count) * 4 or
            values.size_bytes < (@as(u64, first_column) + column_count) * stride * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        self.pending_trace_gather = .{
            .column_offsets = try bindingWordOffset(column_offsets),
            .column_logs = try bindingWordOffset(column_logs),
            .column_count = column_count,
            .lifting_log = lifting_log,
            .first_column = first_column,
            .stride = stride,
            .values = try bindingWordOffset(values),
        };
    }

    pub fn sparseParent(
        self: *DecommitQueryRecipe,
        distance: u32,
        child_offset: u32,
        child_capacity: u32,
        parent_offset: u32,
        node_seed: [8]u32,
    ) !void {
        if (self.pending_trace_gather != null) return recovery.RecoveryError.BindingSizeMismatch;
        if (distance == 0 or child_capacity < 2 or parent_offset >= self.sparse_indices.size_bytes / 4 or
            @as(u64, child_offset + child_capacity) * 4 > self.sparse_indices.size_bytes or
            @as(u64, child_offset + child_capacity) * 32 > self.sparse_hashes.size_bytes)
            return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitSparseParent(
            self.arena.buffer,
            try bindingWordOffset(self.sparse_indices) + child_offset,
            try bindingWordOffset(self.sparse_hashes) + child_offset * 8,
            count_base + 4 + distance - 1,
            child_capacity,
            try bindingWordOffset(self.sparse_indices) + parent_offset,
            try bindingWordOffset(self.sparse_hashes) + parent_offset * 8,
            count_base + 4 + distance,
            node_seed,
            cairo_domain_prefix_bytes,
        );
    }

    pub fn sparseLeaves(
        self: *DecommitQueryRecipe,
        column_offsets: arena_plan.Binding,
        column_logs: arena_plan.Binding,
        column_count: u32,
        leaf_log: u32,
        max_leaf_count: u32,
        leaf_seed: [8]u32,
    ) !void {
        if (self.pending_trace_gather != null) return recovery.RecoveryError.BindingSizeMismatch;
        if (column_offsets.size_bytes < @as(u64, column_count) * 4 or
            column_logs.size_bytes < @as(u64, column_count) * 4 or
            @as(u64, max_leaf_count) * 4 > self.sparse_indices.size_bytes or
            @as(u64, max_leaf_count) * 32 > self.sparse_hashes.size_bytes)
            return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitSparseLeaves(
            self.arena.buffer,
            try bindingWordOffset(column_offsets),
            try bindingWordOffset(column_logs),
            column_count,
            leaf_log,
            try bindingWordOffset(self.sparse_indices),
            count_base + 4,
            max_leaf_count,
            try bindingWordOffset(self.sparse_hashes),
            leaf_seed,
            cairo_domain_prefix_bytes,
        );
    }

    pub fn sparseLeafGroup(
        self: *DecommitQueryRecipe,
        column_offsets: arena_plan.Binding,
        column_logs: arena_plan.Binding,
        column_count: u32,
        first_column: u32,
        total_columns: u32,
        lifting_log: u32,
        max_leaf_count: u32,
        leaf_seed: [8]u32,
    ) !void {
        if (column_count == 0 or column_count > 16 or first_column >= total_columns or
            column_count > total_columns - first_column or first_column % 16 != 0 or
            (first_column + column_count < total_columns and column_count % 16 != 0) or
            column_offsets.size_bytes < @as(u64, column_count) * 4 or
            column_logs.size_bytes < @as(u64, column_count) * 4 or
            @as(u64, max_leaf_count) * 4 > self.sparse_indices.size_bytes or
            @as(u64, max_leaf_count) * 32 > self.sparse_hashes.size_bytes)
            return recovery.RecoveryError.BindingSizeMismatch;
        const pending = self.pending_trace_gather orelse return recovery.RecoveryError.BindingSizeMismatch;
        const column_offsets_words = try bindingWordOffset(column_offsets);
        const column_logs_words = try bindingWordOffset(column_logs);
        if (pending.column_offsets != column_offsets_words or pending.column_logs != column_logs_words or
            pending.column_count != column_count or pending.first_column != first_column or
            pending.lifting_log != lifting_log)
            return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitTraceGroup(
            self.arena.buffer,
            .{
                .column_offsets = pending.column_offsets,
                .column_logs = pending.column_logs,
                .queries = try bindingWordOffset(self.mapped_queries),
                .query_count_at = count_base + 1,
                .values = pending.values,
                .leaf_indices = try bindingWordOffset(self.sparse_indices),
                .leaf_count_at = count_base + 4,
                .output_hashes = try bindingWordOffset(self.sparse_hashes),
                .column_count = column_count,
                .lifting_log = lifting_log,
                .max_queries = 70,
                .first_column = first_column,
                .stride = pending.stride,
                .total_columns = total_columns,
                .max_leaf_count = max_leaf_count,
                .domain_prefix_bytes = cairo_domain_prefix_bytes,
                .leaf_seed = leaf_seed,
            },
        );
        self.pending_trace_gather = null;
    }

    pub fn assembleTrace(
        self: *DecommitQueryRecipe,
        tree_index: u32,
        role: u32,
        leaf_log: u32,
        unretained: u32,
        column_count: u32,
        retained_offsets: arena_plan.Binding,
        sparse_offsets: arena_plan.Binding,
        values: arena_plan.Binding,
    ) !void {
        if (self.pending_trace_gather != null) return recovery.RecoveryError.BindingSizeMismatch;
        if (unretained > leaf_log or retained_offsets.size_bytes < @as(u64, leaf_log - unretained + 1) * 4 or
            sparse_offsets.size_bytes < @as(u64, unretained) * 4 or values.size_bytes < @as(u64, column_count) * 70 * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitAssembleTrace(
            self.arena.buffer,
            tree_index,
            role,
            leaf_log,
            leaf_log - unretained,
            column_count,
            try bindingWordOffset(self.mapped_queries),
            count_base + 1,
            70,
            try bindingWordOffset(self.walk_queries),
            try bindingWordOffset(self.walk_scratch),
            count_base + 2,
            try bindingWordOffset(values),
            try bindingWordOffset(retained_offsets),
            try bindingWordOffset(self.sparse_indices),
            try bindingWordOffset(self.sparse_hashes),
            try bindingWordOffset(sparse_offsets),
            count_base + 4,
            unretained,
            try bindingWordOffset(self.assembly),
            @intCast(self.assembly.size_bytes / 4),
        );
    }

    pub fn gatherFriValues(
        self: *DecommitQueryRecipe,
        coordinate_offsets: arena_plan.Binding,
        values: arena_plan.Binding,
    ) !void {
        if (coordinate_offsets.size_bytes < 16 or values.size_bytes < self.expanded_positions.size_bytes * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitGatherFriValues(
            self.arena.buffer,
            try bindingWordOffset(coordinate_offsets),
            try bindingWordOffset(self.expanded_positions),
            count_base + 3,
            @intCast(self.expanded_positions.size_bytes / 4),
            try bindingWordOffset(values),
        );
    }

    pub fn assembleFri(
        self: *DecommitQueryRecipe,
        tree_index: u32,
        leaf_log: u32,
        coordinate_offsets: arena_plan.Binding,
        retained_offsets: arena_plan.Binding,
        values: arena_plan.Binding,
    ) !void {
        try self.gatherFriValues(coordinate_offsets, values);
        if (retained_offsets.size_bytes < @as(u64, leaf_log + 1) * 4) return recovery.RecoveryError.BindingSizeMismatch;
        const count_base = try bindingWordOffset(self.counts);
        self.accumulated_gpu_ms += try self.metal.decommitAssembleFri(
            self.arena.buffer,
            tree_index,
            leaf_log,
            try bindingWordOffset(self.mapped_queries),
            count_base + 1,
            try bindingWordOffset(self.expanded_positions),
            count_base + 3,
            try bindingWordOffset(values),
            try bindingWordOffset(self.walk_queries),
            try bindingWordOffset(self.walk_scratch),
            count_base + 2,
            try bindingWordOffset(retained_offsets),
            try bindingWordOffset(self.assembly),
            @intCast(self.assembly.size_bytes / 4),
        );
    }
};

/// Exact Cairo transcript controller. Blake2s absorption and rejection-sampled
/// challenge/query draws execute in the resident arena; the host only orders
/// true protocol dependencies and grinds the two proof-of-work nonces.
pub const PowExecutionMode = enum {
    not_run,
    self_ground,
    fixture_forced,
    mixed,
};

/// CPU-only timing around nonce search or validation. Transcript-state
/// readback, nonce absorption, and subsequent Metal draws are deliberately
/// excluded so diagnostic nonce validation cannot masquerade as search cost.
pub const PowTelemetry = struct {
    mode: PowExecutionMode = .not_run,
    pow_bits: u32 = 0,
    invocations: u32 = 0,
    wall_ns: u64 = 0,

    pub fn wallSeconds(self: PowTelemetry) ?f64 {
        if (self.invocations == 0) return null;
        return @as(f64, @floatFromInt(self.wall_ns)) /
            @as(f64, @floatFromInt(std.time.ns_per_s));
    }

    pub fn modeName(self: PowTelemetry) ?[]const u8 {
        return if (self.mode == .not_run) null else @tagName(self.mode);
    }

    fn record(self: *PowTelemetry, mode: PowExecutionMode, pow_bits: u32, elapsed_ns: u64) void {
        if (self.invocations == 0) {
            self.mode = mode;
            self.pow_bits = pow_bits;
        } else if (self.mode != mode or self.pow_bits != pow_bits) {
            self.mode = .mixed;
        }
        self.invocations += 1;
        self.wall_ns +|= elapsed_ns;
    }
};

test "PoW telemetry separates search from forced validation" {
    var telemetry = PowTelemetry{};
    try std.testing.expectEqual(@as(?f64, null), telemetry.wallSeconds());
    try std.testing.expectEqual(@as(?[]const u8, null), telemetry.modeName());

    telemetry.record(.self_ground, 24, std.time.ns_per_ms * 3);
    try std.testing.expectEqualStrings("self_ground", telemetry.modeName().?);
    try std.testing.expectEqual(@as(u32, 24), telemetry.pow_bits);
    try std.testing.expectEqual(@as(u32, 1), telemetry.invocations);
    try std.testing.expectApproxEqAbs(@as(f64, 0.003), telemetry.wallSeconds().?, 1e-12);

    telemetry.record(.self_ground, 24, std.time.ns_per_ms * 2);
    try std.testing.expectEqual(@as(u32, 2), telemetry.invocations);
    try std.testing.expectApproxEqAbs(@as(f64, 0.005), telemetry.wallSeconds().?, 1e-12);

    telemetry.record(.fixture_forced, 24, 1);
    try std.testing.expectEqualStrings("mixed", telemetry.modeName().?);
}

pub const TranscriptRecipe = struct {
    allocator: std.mem.Allocator,
    metal: *runtime.Runtime,
    arena: *arena_plan.ResidentArena,
    state: arena_plan.Binding,
    query_log: u32,
    inputs: []TranscriptBinding,
    outputs: []TranscriptBinding,
    accumulated_gpu_ms: f64 = 0,
    interaction_pow: PowTelemetry = .{},
    query_pow: PowTelemetry = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        state: arena_plan.Binding,
        query_log: u32,
        inputs: []const TranscriptBinding,
        outputs: []const TranscriptBinding,
    ) !TranscriptRecipe {
        if (state.offset_bytes % 4 != 0 or state.size_bytes < 40 or query_log >= 31 or
            inputs.len == 0 or outputs.len == 0)
            return recovery.RecoveryError.BindingSizeMismatch;
        return .{
            .allocator = allocator,
            .metal = metal,
            .arena = resident_arena,
            .state = state,
            .query_log = query_log,
            .inputs = try allocator.dupe(TranscriptBinding, inputs),
            .outputs = try allocator.dupe(TranscriptBinding, outputs),
        };
    }

    pub fn deinit(self: *TranscriptRecipe) void {
        self.allocator.free(self.inputs);
        self.allocator.free(self.outputs);
        self.* = undefined;
    }

    pub fn initialize(self: *TranscriptRecipe) !void {
        self.accumulated_gpu_ms += try self.metal.transcriptInit(self.arena.buffer, try wordOffset(self.state));
    }

    pub fn publishInput(self: *TranscriptRecipe, ordinal: u32, source: arena_plan.Binding, words: u32) !void {
        const destination = try self.find(self.inputs, ordinal);
        if (source.size_bytes < @as(u64, words) * 4 or destination.size_bytes < @as(u64, words) * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const source_bytes = try self.arena.bytes(source);
        const destination_bytes = try self.arena.bytes(destination);
        @memcpy(destination_bytes[0 .. @as(usize, words) * 4], source_bytes[0 .. @as(usize, words) * 4]);
    }

    /// Loads a parity fixture directly into one transcript input binding.
    pub fn loadInputWords(self: *TranscriptRecipe, ordinal: u32, words: []const u32) !void {
        const destination = try self.find(self.inputs, ordinal);
        if (destination.size_bytes != @as(u64, words.len) * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const destination_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(destination));
        @memcpy(std.mem.bytesAsSlice(u32, destination_bytes), words);
    }

    /// Fails closed when a resident transcript draw differs from the reference.
    pub fn expectOutputWords(self: TranscriptRecipe, ordinal: u32, expected: []const u32) !void {
        const output_binding = try self.find(self.outputs, ordinal);
        if (output_binding.size_bytes < @as(u64, expected.len) * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const output_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(output_binding));
        const actual = std.mem.bytesAsSlice(u32, output_bytes);
        if (!std.mem.eql(u32, actual[0..expected.len], expected)) {
            std.debug.print(
                "transcript output parity mismatch ordinal={} actual={any} expected={any}\n",
                .{ ordinal, actual[0..expected.len], expected },
            );
            return error.TranscriptParityMismatch;
        }
    }

    pub fn expectInputWords(self: TranscriptRecipe, ordinal: u32, expected: []const u32) !void {
        const input_binding = try self.find(self.inputs, ordinal);
        if (input_binding.size_bytes != @as(u64, expected.len) * 4)
            return recovery.RecoveryError.BindingSizeMismatch;
        const input_bytes: []align(4) u8 = @alignCast(try self.arena.bytes(input_binding));
        const actual = std.mem.bytesAsSlice(u32, input_bytes);
        if (!std.mem.eql(u32, actual, expected)) {
            std.debug.print(
                "transcript input parity mismatch ordinal={} actual={any} expected={any}\n",
                .{ ordinal, actual, expected },
            );
            return error.TranscriptParityMismatch;
        }
    }

    pub fn bootstrapThroughBase(self: *TranscriptRecipe) !void {
        for ([_]u32{ 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 20 }) |input| try self.mixInput(input);
    }

    pub fn interactionPowAndLookup(self: *TranscriptRecipe) !u64 {
        const nonce = try self.grindAndMix(21, 24, &self.interaction_pow);
        try self.drawSecure(1, 2);
        return nonce;
    }

    /// Uses and validates the Rust reference nonce for transcript parity. Local
    /// grinding follows the same Stwo SimdBackend nonce order
    /// (`stwo_core.channel.blake2s.pow_order`), so it selects this nonce too;
    /// taking the reference value keeps the recipe independent of grind cost.
    pub fn interactionPowAndLookupNonce(self: *TranscriptRecipe, nonce: u64) !void {
        try self.validateAndMixNonce(21, 24, nonce, &self.interaction_pow);
        try self.drawSecure(1, 2);
    }

    pub fn interactionAndComposition(self: *TranscriptRecipe) !void {
        try self.mixInput(22);
        try self.mixInput(23);
        try self.drawSecure(2, 1);
    }

    pub fn compositionAndOods(self: *TranscriptRecipe) !void {
        try self.mixInput(24);
        try self.drawSecure(3, 1);
    }

    pub fn oodsAndQuotient(self: *TranscriptRecipe) !void {
        try self.mixInput(25);
        try self.drawSecure(4, 1);
    }

    pub fn friLayer(
        self: *TranscriptRecipe,
        layer: u32,
        root: arena_plan.Binding,
        challenge: arena_plan.Binding,
    ) !void {
        const input_ordinal = 65536 + layer * 4;
        const output_ordinal = input_ordinal + 1;
        try self.publishInput(input_ordinal, root, 8);
        try self.mixInput(input_ordinal);
        try self.drawSecure(output_ordinal, 1);
        const drawn = try self.find(self.outputs, output_ordinal);
        const output_bytes = try self.arena.bytes(drawn);
        const challenge_bytes = try self.arena.bytes(challenge);
        if (challenge_bytes.len < 16) return recovery.RecoveryError.BindingSizeMismatch;
        @memcpy(challenge_bytes[0..16], output_bytes[0..16]);
    }

    pub fn lastLayer(self: *TranscriptRecipe, coefficients: arena_plan.Binding) !void {
        try self.publishInput(30, coefficients, 4);
        try self.mixInput(30);
    }

    pub fn queryPowAndPositions(self: *TranscriptRecipe) !u64 {
        const nonce = try self.grindAndMix(31, 26, &self.query_pow);
        try self.drawQueryPositions();
        return nonce;
    }

    pub fn queryPowAndPositionsNonce(self: *TranscriptRecipe, nonce: u64) !void {
        try self.validateAndMixNonce(31, 26, nonce, &self.query_pow);
        try self.drawQueryPositions();
    }

    fn drawQueryPositions(self: *TranscriptRecipe) !void {
        const queries = try self.find(self.outputs, 5);
        self.accumulated_gpu_ms += try self.metal.transcriptDrawQueries(
            self.arena.buffer,
            try wordOffset(self.state),
            try wordOffset(queries),
            self.query_log,
            70,
        );
    }

    pub fn output(self: TranscriptRecipe, ordinal: u32) !arena_plan.Binding {
        return self.find(self.outputs, ordinal);
    }

    fn mixInput(self: *TranscriptRecipe, ordinal: u32) !void {
        const input = try self.find(self.inputs, ordinal);
        if (input.size_bytes == 0 or input.size_bytes % 4 != 0 or input.size_bytes / 4 > std.math.maxInt(u32))
            return recovery.RecoveryError.BindingSizeMismatch;
        self.accumulated_gpu_ms += try self.metal.transcriptMix(
            self.arena.buffer,
            try wordOffset(self.state),
            try wordOffset(input),
            @intCast(input.size_bytes / 4),
        );
    }

    fn drawSecure(self: *TranscriptRecipe, ordinal: u32, felt_count: u32) !void {
        const output_binding = try self.find(self.outputs, ordinal);
        if (output_binding.size_bytes < @as(u64, felt_count) * 16)
            return recovery.RecoveryError.BindingSizeMismatch;
        self.accumulated_gpu_ms += try self.metal.transcriptDrawSecure(
            self.arena.buffer,
            try wordOffset(self.state),
            try wordOffset(output_binding),
            felt_count,
        );
    }

    fn grindAndMix(
        self: *TranscriptRecipe,
        input_ordinal: u32,
        pow_bits: u32,
        telemetry: *PowTelemetry,
    ) !u64 {
        const channel = try self.channelFromState();
        var timer = try std.time.Timer.start();
        const nonce = channel.grind(pow_bits);
        telemetry.record(.self_ground, pow_bits, timer.read());
        try self.writeAndMixNonce(input_ordinal, nonce);
        return nonce;
    }

    fn validateAndMixNonce(
        self: *TranscriptRecipe,
        input_ordinal: u32,
        pow_bits: u32,
        nonce: u64,
        telemetry: *PowTelemetry,
    ) !void {
        const channel = try self.channelFromState();
        var timer = try std.time.Timer.start();
        const valid = channel.verifyPowNonce(pow_bits, nonce);
        telemetry.record(.fixture_forced, pow_bits, timer.read());
        if (!valid) return error.InvalidReferencePowNonce;
        try self.writeAndMixNonce(input_ordinal, nonce);
    }

    fn writeAndMixNonce(self: *TranscriptRecipe, input_ordinal: u32, nonce: u64) !void {
        const destination = try self.find(self.inputs, input_ordinal);
        const destination_bytes = try self.arena.bytes(destination);
        if (destination_bytes.len < 8) return recovery.RecoveryError.BindingSizeMismatch;
        std.mem.writeInt(u64, destination_bytes[0..8], nonce, .little);
        try self.mixInput(input_ordinal);
    }

    fn channelFromState(self: TranscriptRecipe) !blake2s_channel.Blake2sChannel {
        const state_bytes = try self.arena.bytes(self.state);
        if (state_bytes.len < 9 * 4) return recovery.RecoveryError.BindingSizeMismatch;
        const state_words = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(state_bytes)));
        var channel = blake2s_channel.Blake2sChannel{};
        @memcpy(&channel.digest, std.mem.sliceAsBytes(state_words[0..8]));
        channel.n_draws = state_words[8];
        return channel;
    }

    fn find(_: TranscriptRecipe, bindings: []const TranscriptBinding, ordinal: u32) !arena_plan.Binding {
        for (bindings) |binding| if (binding.ordinal == ordinal) return binding.binding;
        return recovery.RecoveryError.MissingRecipe;
    }

    fn wordOffset(binding: arena_plan.Binding) !u32 {
        if (binding.offset_bytes % 4 != 0) return recovery.RecoveryError.BindingSizeMismatch;
        return std.math.cast(u32, binding.offset_bytes / 4) orelse recovery.RecoveryError.BindingSizeMismatch;
    }
};
