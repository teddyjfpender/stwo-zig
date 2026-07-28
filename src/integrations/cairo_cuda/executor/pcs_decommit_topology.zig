//! Authenticated mixed-height opening topology for resident Cairo CUDA.
//!
//! Trace opening values are emitted in canonical tree/column order. Adjacent
//! equal-height columns form direct subviews of compact evaluation arenas and
//! are passed through the common offset-aware `packTraceGroup` API.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("stwo_cuda_backend").abi.field;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const decommit_stage = @import("stwo_cuda_backend").runtime.stages.decommit;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const shared_views = @import("stwo_native_cuda_integration").common.resident_views;
const pcs_types = @import("pcs_hooks_types.zig");

pub const TraceGroup = struct {
    tree_ordinal: u32,
    first_column: u32,
    column_count: u32,
    evaluation_log_rows: u32,
    evaluation_offset_words: u64,
    evaluation_words: u64,
};

pub const TraceOpening = struct {
    tree_index: u32,
    role: proof_ir.CommitmentRole,
    column_count: u32,
    source_log_size: u32,
    tree_log_size: u32,
    leaf_log_size: u32,
    first_group: u32,
    group_count: u32,
};

pub const FriOpening = struct {
    tree_index: u32,
    evaluation_log_size: u32,
    cumulative_fold: u32,
    fold_step: u32,
    log_rows_per_leaf: u32,
    max_expanded_positions: usize,
};

pub const Topology = struct {
    allocator: std.mem.Allocator,
    trace_openings: []TraceOpening,
    trace_groups: []TraceGroup,
    column_log_sizes: []u32,
    fri_openings: []FriOpening,
    query_log_size: u32,
    query_count: usize,
    tree_count: u32,
    assembly_capacity_words: usize,
    identity: proof_ir.Digest,

    pub fn deinit(self: *Topology) void {
        self.allocator.free(self.fri_openings);
        self.allocator.free(self.column_log_sizes);
        self.allocator.free(self.trace_groups);
        self.allocator.free(self.trace_openings);
        self.* = undefined;
    }

    pub fn uploadColumnLogs(
        self: Topology,
        session: anytype,
        decommit: shared_views.Decommit,
    ) !void {
        var cursor: usize = 0;
        for (self.trace_openings) |opening| {
            const count: usize = opening.column_count;
            const end = try add(cursor, count);
            if (end > self.column_log_sizes.len)
                return error.InvalidKernelDescriptor;
            const destination = decommit.columnLogSizes(
                role(opening.role) orelse
                    return error.InvalidKernelDescriptor,
            );
            if (destination.len != count)
                return error.InvalidKernelDescriptor;
            try session.context.uploadSlice(
                u32,
                destination,
                self.column_log_sizes[cursor..end],
            );
            cursor = end;
        }
        if (cursor != self.column_log_sizes.len)
            return error.InvalidKernelDescriptor;
    }
};

pub fn derive(
    allocator: std.mem.Allocator,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !Topology {
    try validateInputs(program, protocol);
    const openings = try allocator.alloc(
        TraceOpening,
        program.commitments.len,
    );
    errdefer allocator.free(openings);
    const column_logs = try allocator.alloc(
        u32,
        program.trace_columns.len,
    );
    errdefer allocator.free(column_logs);
    const group_storage = try allocator.alloc(
        TraceGroup,
        program.trace_columns.len,
    );
    errdefer allocator.free(group_storage);

    const query_log = maximumCommitmentLog(program);
    var group_count: usize = 0;
    var column_cursor: usize = 0;
    for (program.commitments, openings, 0..) |tree, *opening, ordinal| {
        const first_group = group_count;
        var evaluation_offset: u64 = 0;
        const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
        var first: usize = 0;
        while (first < columns.len) {
            const evaluation_log = std.math.add(
                u32,
                columns[first].log_rows,
                protocol.log_blowup_factor,
            ) catch return error.SizeOverflow;
            var end = first + 1;
            while (end < columns.len and
                columns[end].log_rows == columns[first].log_rows)
            {
                end += 1;
            }
            const count = end - first;
            const stride = try pow2u64(evaluation_log);
            const words = try mulU64(count, stride);
            group_storage[group_count] = .{
                .tree_ordinal = @intCast(ordinal),
                .first_column = @intCast(first),
                .column_count = @intCast(count),
                .evaluation_log_rows = evaluation_log,
                .evaluation_offset_words = evaluation_offset,
                .evaluation_words = words,
            };
            for (column_logs[column_cursor..][0..count]) |*log_size| {
                log_size.* = evaluation_log;
            }
            column_cursor += count;
            evaluation_offset = std.math.add(
                u64,
                evaluation_offset,
                words,
            ) catch return error.SizeOverflow;
            group_count += 1;
            first = end;
        }
        if (tree.evaluation_log_rows > query_log or
            tree.log_rows_per_leaf != tree.evaluation_log_rows or
            evaluation_offset == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        opening.* = .{
            .tree_index = @intCast(ordinal),
            .role = tree.role,
            .column_count = tree.column_count,
            .source_log_size = query_log,
            .tree_log_size = tree.evaluation_log_rows,
            .leaf_log_size = tree.log_rows_per_leaf,
            .first_group = @intCast(first_group),
            .group_count = @intCast(group_count - first_group),
        };
    }
    if (column_cursor != column_logs.len)
        return error.InvalidKernelDescriptor;
    const groups = try allocator.dupe(
        TraceGroup,
        group_storage[0..group_count],
    );
    errdefer allocator.free(groups);
    allocator.free(group_storage);

    const fri = try allocator.alloc(
        FriOpening,
        program.fri_layers.len,
    );
    errdefer allocator.free(fri);
    for (program.fri_layers, fri, 0..) |layer, *opening, ordinal| {
        const expanded = try mul(
            protocol.query_count,
            try pow2usize(layer.fold_step),
        );
        opening.* = .{
            .tree_index = std.math.add(
                u32,
                protocol.commitment_count,
                @intCast(ordinal),
            ) catch return error.SizeOverflow,
            .evaluation_log_size = layer.evaluation_log_rows,
            .cumulative_fold = layer.cumulative_fold,
            .fold_step = layer.fold_step,
            .log_rows_per_leaf = layer.log_rows_per_leaf,
            .max_expanded_positions = expanded,
        };
    }
    const tree_count = std.math.add(
        u32,
        protocol.commitment_count,
        protocol.fri_tree_count,
    ) catch return error.SizeOverflow;
    if (tree_count != protocol.decommitment_record_count)
        return error.InvalidKernelDescriptor;
    const identity = topologyIdentity(
        program,
        protocol,
        openings,
        groups,
        column_logs,
        fri,
        query_log,
    );
    return .{
        .allocator = allocator,
        .trace_openings = openings,
        .trace_groups = groups,
        .column_log_sizes = column_logs,
        .fri_openings = fri,
        .query_log_size = query_log,
        .query_count = protocol.query_count,
        .tree_count = tree_count,
        .assembly_capacity_words = protocol.decommitment_capacity_words,
        .identity = identity,
    };
}

pub fn normalizeWith(
    comptime Decommit: type,
    session: anytype,
    topology: Topology,
    decommit: shared_views.Decommit,
    assembly: common.Words,
) !void {
    try validateRuntime(topology, decommit, assembly);
    try Decommit.normalizeQueries(
        session,
        decommit.raw_queries,
        topology.query_log_size,
        topology.tree_count,
        decommit.unique_queries,
        decommit.counts.unique,
        assembly,
    );
}

pub fn openAllWith(
    comptime Decommit: type,
    session: anytype,
    topology: Topology,
    trees: pcs_types.TraceTrees,
    fri: shared_views.Fri,
    decommit: shared_views.Decommit,
    assembly: common.Words,
) !void {
    try validateRuntime(topology, decommit, assembly);
    if (trees.len != topology.trace_openings.len or
        fri.layer_count != topology.fri_openings.len)
    {
        return error.InvalidKernelDescriptor;
    }
    for (topology.trace_openings) |opening| try openTrace(
        Decommit,
        session,
        topology,
        trees,
        decommit,
        assembly,
        opening,
    );
    for (topology.fri_openings, 0..) |opening, ordinal| {
        try openFri(
            Decommit,
            session,
            fri.layers[ordinal],
            decommit,
            assembly,
            opening,
        );
    }
}

fn openTrace(
    comptime Decommit: type,
    session: anytype,
    topology: Topology,
    trees: pcs_types.TraceTrees,
    decommit: shared_views.Decommit,
    assembly: common.Words,
    opening: TraceOpening,
) !void {
    const queries = decommit.traceQueries();
    try Decommit.prepareTraceQueries(
        session,
        decommit.unique_queries,
        decommit.counts.unique,
        opening.source_log_size,
        opening.tree_log_size,
        opening.leaf_log_size,
        0,
        queries,
    );
    const tree = try treeAt(trees, opening.tree_index);
    if (tree.role != opening.role or
        tree.column_count != opening.column_count)
    {
        return error.InvalidKernelDescriptor;
    }
    const logs = decommit.columnLogSizes(
        role(opening.role) orelse return error.InvalidKernelDescriptor,
    );
    const first_group: usize = opening.first_group;
    const end_group = try add(first_group, opening.group_count);
    if (end_group > topology.trace_groups.len)
        return error.InvalidKernelDescriptor;
    const final_group = topology.trace_groups[end_group - 1];
    const expected_tree_words = std.math.add(
        u64,
        final_group.evaluation_offset_words,
        final_group.evaluation_words,
    ) catch return error.SizeOverflow;
    if (tree.evaluations.len != expected_tree_words)
        return error.InvalidKernelDescriptor;
    for (topology.trace_groups[first_group..end_group]) |group| {
        if (group.tree_ordinal != opening.tree_index)
            return error.InvalidKernelDescriptor;
        const first = std.math.cast(
            usize,
            group.evaluation_offset_words,
        ) orelse return error.SizeOverflow;
        const words = std.math.cast(
            usize,
            group.evaluation_words,
        ) orelse return error.SizeOverflow;
        try Decommit.packTraceGroup(
            session,
            opening.tree_index,
            opening.column_count,
            group.first_column,
            .{
                .storage = try tree.evaluations.sub(first, words),
                .column_stride_words = try pow2usize(
                    group.evaluation_log_rows,
                ),
            },
            try logs.sub(group.first_column, group.column_count),
            opening.tree_log_size,
            queries.mapped,
            queries.mapped_count,
            assembly,
        );
    }
    const empty_words = try decommit.sparse_indices.sub(0, 0);
    const empty_hashes = try decommit.sparse_hashes.sub(0, 0);
    try Decommit.assembleTrace(
        session,
        opening.tree_index,
        @intFromEnum(opening.role),
        opening.leaf_log_size,
        opening.leaf_log_size,
        opening.column_count,
        @intCast(topology.query_count),
        .{
            .mapped_count = queries.mapped_count,
            .walk_queries = decommit.walk_queries,
            .walk_scratch = decommit.walk_scratch,
            .walk_count = decommit.counts.walk,
            .retained = .{
                .hashes = tree.merkle_hashes,
                .layers = tree.merkle_layers,
            },
            .sparse_indices = empty_words,
            .sparse_hashes = empty_hashes,
            .sparse_level_offsets = empty_words,
            .sparse_level_counts = empty_words,
            .assembly = assembly,
        },
    );
}

fn openFri(
    comptime Decommit: type,
    session: anytype,
    layer: shared_views.FriLayer,
    decommit: shared_views.Decommit,
    assembly: common.Words,
    opening: FriOpening,
) !void {
    const queries = decommit.friQueries();
    try Decommit.prepareFriQueries(
        session,
        decommit.unique_queries,
        decommit.counts.unique,
        opening.cumulative_fold,
        opening.fold_step,
        opening.log_rows_per_leaf,
        queries,
    );
    try Decommit.assembleFri(
        session,
        opening.tree_index,
        opening.evaluation_log_size - opening.log_rows_per_leaf,
        decommit.friAssembly(layer, assembly),
    );
}

fn validateRuntime(
    topology: Topology,
    decommit: shared_views.Decommit,
    assembly: common.Words,
) !void {
    if (std.mem.allEqual(u8, &topology.identity, 0) or
        decommit.raw_queries.len != topology.query_count or
        decommit.unique_queries.len != topology.query_count or
        assembly.len != topology.assembly_capacity_words)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn validateInputs(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !void {
    try program.validate();
    try protocol.validate();
    if (program.identity.frontend != .cairo or
        program.commitments.len != protocol.commitment_count or
        program.fri_layers.len != protocol.fri_tree_count or
        program.commitments.len != 4 or
        protocol.query_count == 0 or
        protocol.query_count > decommit_stage.max_protocol_queries)
    {
        return error.InvalidKernelDescriptor;
    }
    var first_column: u32 = 0;
    for (program.commitments, 0..) |tree, ordinal| {
        if (tree.id != ordinal or
            tree.role != @as(proof_ir.CommitmentRole, @enumFromInt(ordinal)) or
            tree.first_column != first_column or
            tree.column_count != protocol.trace_columns[ordinal] or
            !tree.retain_openings)
        {
            return error.InvalidKernelDescriptor;
        }
        first_column = std.math.add(
            u32,
            first_column,
            tree.column_count,
        ) catch return error.SizeOverflow;
    }
    if (first_column != program.trace_columns.len)
        return error.InvalidKernelDescriptor;
}

fn maximumCommitmentLog(program: proof_ir.ProofProgram) u32 {
    var result: u32 = 0;
    for (program.commitments) |tree| {
        result = @max(result, tree.evaluation_log_rows);
    }
    return result;
}

fn treeAt(
    trees: pcs_types.TraceTrees,
    ordinal: u32,
) !pcs_types.CompactTree {
    for (trees.active()) |tree| {
        if (tree.ordinal == ordinal) return tree;
    }
    return error.InvalidKernelDescriptor;
}

fn role(value: proof_ir.CommitmentRole) ?@import("stwo_native_cuda_integration").common.uniform_layout.TraceRole {
    return switch (value) {
        .preprocessed => .preprocessed,
        .main => .main,
        .interaction => .interaction,
        .composition => .composition,
        .fri => null,
    };
}

fn topologyIdentity(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    openings: []const TraceOpening,
    groups: []const TraceGroup,
    logs: []const u32,
    fri: []const FriOpening,
    query_log: u32,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/decommit-topology/v1\x00");
    hash.update(&program.semantic_digest);
    hash.update(&program.program_digest);
    const encoded = protocol.encode() catch unreachable;
    hash.update(&encoded);
    hashInt(&hash, u32, query_log);
    hashInt(&hash, u64, openings.len);
    for (openings) |opening| {
        hashInt(&hash, u32, opening.tree_index);
        hashInt(&hash, u8, @intFromEnum(opening.role));
        hashInt(&hash, u32, opening.column_count);
        hashInt(&hash, u32, opening.source_log_size);
        hashInt(&hash, u32, opening.tree_log_size);
        hashInt(&hash, u32, opening.leaf_log_size);
        hashInt(&hash, u32, opening.first_group);
        hashInt(&hash, u32, opening.group_count);
    }
    hashInt(&hash, u64, groups.len);
    for (groups) |group| {
        hashInt(&hash, u32, group.tree_ordinal);
        hashInt(&hash, u32, group.first_column);
        hashInt(&hash, u32, group.column_count);
        hashInt(&hash, u32, group.evaluation_log_rows);
        hashInt(&hash, u64, group.evaluation_offset_words);
        hashInt(&hash, u64, group.evaluation_words);
    }
    hashSlice(&hash, u32, logs);
    hashInt(&hash, u64, fri.len);
    for (fri) |opening| {
        hashInt(&hash, u32, opening.tree_index);
        hashInt(&hash, u32, opening.evaluation_log_size);
        hashInt(&hash, u32, opening.cumulative_fold);
        hashInt(&hash, u32, opening.fold_step);
        hashInt(&hash, u32, opening.log_rows_per_leaf);
        hashInt(&hash, u64, opening.max_expanded_positions);
    }
    return hash.finalResult();
}

fn hashSlice(
    hash: anytype,
    comptime T: type,
    values: []const T,
) void {
    hashInt(hash, u64, values.len);
    for (values) |value| hashInt(hash, T, value);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn pow2u64(log_size: u32) !u64 {
    if (log_size >= 64) return error.SizeOverflow;
    return @as(u64, 1) << @intCast(log_size);
}

fn pow2usize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn add(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.add(usize, lhs, rhs) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}

fn mulU64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.SizeOverflow;
    return std.math.mul(u64, lhs, rhs) catch error.SizeOverflow;
}
