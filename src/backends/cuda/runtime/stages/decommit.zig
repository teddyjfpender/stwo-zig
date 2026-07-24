//! Checked resident trace and FRI opening assembly dispatch.

const abi = @import("../../abi/stages/decommit.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const std = @import("std");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
const stage = telemetry.Stage.decommit;
pub const max_protocol_queries: usize = 256;

/// Authenticates the compact resident result after the proof transaction's
/// sole final read. A poisoned device result (`used_words == 0`) is never a
/// decodable empty proof.
pub fn validateAssemblyHeader(
    words: []const u32,
    expected_tree_count: u32,
) runtime_error.Error![]const u32 {
    if (words.len < 8 or expected_tree_count == 0 or
        words[0] != 0x4457_5453 or words[1] != 1 or
        words[2] != expected_tree_count)
        return error.InvalidDecommitmentAssembly;
    const metadata_words = std.math.mul(
        usize,
        expected_tree_count,
        16,
    ) catch return error.InvalidDecommitmentAssembly;
    const minimum_words = std.math.add(
        usize,
        8,
        metadata_words,
    ) catch return error.InvalidDecommitmentAssembly;
    const used_words = std.math.cast(usize, words[7]) orelse
        return error.InvalidDecommitmentAssembly;
    if (used_words < minimum_words or used_words > words.len)
        return error.InvalidDecommitmentAssembly;
    for (0..expected_tree_count) |tree_index| {
        const meta = 8 + tree_index * 16;
        if (words[meta] > 1 or words[meta + 15] == 0)
            return error.InvalidDecommitmentAssembly;
    }
    return words[0..used_words];
}

pub const TraceQueries = struct {
    mapped: common.Words,
    mapped_count: common.Words,
    walk: common.Words,
    walk_count: common.Words,
    leaf_indices: common.Words,
    leaf_count: common.Words,
};

pub const FriQueries = struct {
    tree: common.Words,
    tree_count: common.Words,
    expanded: common.Words,
    expanded_count: common.Words,
    walk: common.Words,
    walk_count: common.Words,
};

pub const RetainedTree = struct {
    hashes: common.Hashes,
    layers: common.MerkleLayers,
};

pub const TraceAssembly = struct {
    mapped_count: common.Words,
    walk_queries: common.Words,
    walk_scratch: common.Words,
    walk_count: common.Words,
    retained: RetainedTree,
    sparse_indices: common.Words,
    sparse_hashes: common.Hashes,
    sparse_level_offsets: common.Words,
    sparse_level_counts: common.Words,
    assembly: common.Words,
};

pub const FriAssembly = struct {
    tree_queries: common.Words,
    tree_query_count: common.Words,
    expanded_positions: common.Words,
    expanded_count: common.Words,
    coordinates: common.WordMatrix,
    walk_queries: common.Words,
    walk_scratch: common.Words,
    walk_count: common.Words,
    retained: RetainedTree,
    assembly: common.Words,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn normalizeQueries(
            session: anytype,
            raw_queries: common.Words,
            query_log_size: u32,
            tree_count: u32,
            unique_queries: common.Words,
            unique_count: common.Words,
            assembly: common.Words,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const raw_count = try common.count(raw_queries.len);
            try common.requireNonZero(&.{ raw_count, tree_count });
            const metadata_words = std.math.mul(
                usize,
                tree_count,
                16,
            ) catch return error.SizeOverflow;
            const query_words = std.math.mul(
                usize,
                raw_queries.len,
                2,
            ) catch return error.SizeOverflow;
            const minimum_assembly = std.math.add(
                usize,
                8 + metadata_words,
                query_words,
            ) catch return error.SizeOverflow;
            if (raw_queries.len > max_protocol_queries or query_log_size == 0 or
                query_log_size >= 31 or assembly.len < minimum_assembly)
                return error.InvalidKernelDescriptor;
            const status = Api.stwo_decommit_normalize_queries_on(
                try common.words(session, raw_queries, raw_count),
                raw_count,
                query_log_size,
                tree_count,
                try common.words(session, unique_queries, raw_count),
                try common.words(session, unique_count, 1),
                try common.words(session, assembly, minimum_assembly),
                try common.count(assembly.len),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn prepareTraceQueries(
            session: anytype,
            unique_queries: common.Words,
            unique_count: common.Words,
            source_log_size: u32,
            tree_log_size: u32,
            leaf_log_size: u32,
            unretained_bottom_layers: u32,
            output: TraceQueries,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const max_queries = try common.count(unique_queries.len);
            if (max_queries == 0 or max_queries > max_protocol_queries or
                source_log_size >= 31 or tree_log_size >= 31 or
                leaf_log_size >= 31 or
                unretained_bottom_layers > leaf_log_size or
                unretained_bottom_layers >= 31)
                return error.InvalidKernelDescriptor;
            const leaf_requirement = if (unretained_bottom_layers == 0)
                @as(usize, 1)
            else
                std.math.mul(
                    usize,
                    unique_queries.len,
                    @as(usize, 1) << @intCast(unretained_bottom_layers),
                ) catch return error.SizeOverflow;
            if (output.leaf_indices.len < leaf_requirement)
                return error.SizeOverflow;
            const leaf_capacity = try common.count(output.leaf_indices.len);
            const status = Api.stwo_decommit_prepare_trace_queries_on(
                try common.words(session, unique_queries, 1),
                try common.words(session, unique_count, 1),
                max_queries,
                source_log_size,
                tree_log_size,
                leaf_log_size,
                unretained_bottom_layers,
                try common.words(session, output.mapped, max_queries),
                try common.words(session, output.mapped_count, 1),
                try common.words(session, output.walk, max_queries),
                try common.words(session, output.walk_count, 1),
                try common.words(session, output.leaf_indices, leaf_requirement),
                leaf_capacity,
                try common.words(session, output.leaf_count, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn packTraceGroup(
            session: anytype,
            tree_index: u32,
            total_column_count: u32,
            first_column: u32,
            columns: common.WordMatrix,
            column_log_sizes: common.Words,
            lifting_log_size: u32,
            mapped_queries: common.Words,
            mapped_count: common.Words,
            assembly: common.Words,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = try common.count(column_log_sizes.len);
            const max_queries = try common.count(mapped_queries.len);
            try common.requireNonZero(&.{ group_count, max_queries });
            if (total_column_count == 0 or
                first_column > total_column_count or
                group_count > total_column_count - first_column or
                lifting_log_size >= 31)
                return error.InvalidKernelDescriptor;
            const required_words = std.math.mul(
                usize,
                column_log_sizes.len,
                columns.column_stride_words,
            ) catch return error.SizeOverflow;
            if (columns.column_stride_words == 0 or
                columns.storage.len < required_words)
                return error.SizeOverflow;
            const status = Api.stwo_decommit_pack_trace_group_on(
                tree_index,
                total_column_count,
                first_column,
                group_count,
                try common.words(session, columns.storage, required_words),
                columns.column_stride_words,
                columns.storage.len,
                try common.words(session, column_log_sizes, group_count),
                lifting_log_size,
                try common.words(session, mapped_queries, max_queries),
                try common.words(session, mapped_count, 1),
                max_queries,
                try common.words(session, assembly, 1),
                try common.count(assembly.len),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn sparseParents(
            session: anytype,
            child_indices: common.Words,
            child_hashes: common.Hashes,
            child_count: common.Words,
            parent_indices: common.Words,
            parent_hashes: common.Hashes,
            parent_count: common.Words,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const max_children = try common.count(child_indices.len);
            if (child_hashes.len < max_children or
                parent_indices.len < max_children / 2 or
                parent_hashes.len < parent_indices.len)
            {
                return error.SizeOverflow;
            }
            const status = Api.stwo_decommit_sparse_parent_on(
                try common.words(session, child_indices, max_children),
                try common.hashes(session, child_hashes, max_children),
                try common.words(session, child_count, 1),
                max_children,
                try common.words(session, parent_indices, 1),
                try common.hashes(session, parent_hashes, parent_indices.len),
                try common.count(parent_indices.len),
                try common.words(session, parent_count, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn prepareFriQueries(
            session: anytype,
            unique_queries: common.Words,
            unique_count: common.Words,
            cumulative_fold: u32,
            fold_step: u32,
            log_rows_per_leaf: u32,
            output: FriQueries,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const max_queries = try common.count(unique_queries.len);
            if (max_queries == 0 or max_queries > max_protocol_queries or
                cumulative_fold >= 31 or fold_step >= 31 or
                log_rows_per_leaf >= 31)
                return error.InvalidKernelDescriptor;
            const expansion = @as(usize, 1) << @intCast(fold_step);
            const expanded_capacity = std.math.mul(
                usize,
                max_queries,
                expansion,
            ) catch return error.SizeOverflow;
            if (output.tree.len < max_queries or
                output.expanded.len < expanded_capacity or
                output.walk.len < expanded_capacity)
                return error.SizeOverflow;
            const status = Api.stwo_decommit_prepare_fri_queries_on(
                try common.words(session, unique_queries, max_queries),
                try common.words(session, unique_count, 1),
                max_queries,
                cumulative_fold,
                fold_step,
                log_rows_per_leaf,
                try common.words(session, output.tree, max_queries),
                try common.words(session, output.tree_count, 1),
                try common.words(session, output.expanded, expanded_capacity),
                try common.count(output.expanded.len),
                try common.words(session, output.expanded_count, 1),
                try common.words(session, output.walk, expanded_capacity),
                try common.count(output.walk.len),
                try common.words(session, output.walk_count, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn assembleTrace(
            session: anytype,
            tree_index: u32,
            tree_role: u32,
            leaf_log_size: u32,
            first_retained_log_size: u32,
            column_count: u32,
            max_queries: u32,
            data: TraceAssembly,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const sparse_level_count = try common.count(data.sparse_level_counts.len);
            try common.requireNonZero(&.{
                column_count,
                max_queries,
            });
            if (max_queries > max_protocol_queries or leaf_log_size >= 31 or
                first_retained_log_size > leaf_log_size)
                return error.InvalidKernelDescriptor;
            if (data.sparse_level_offsets.len != sparse_level_count or
                data.sparse_hashes.len < data.sparse_indices.len or
                data.walk_queries.len < max_queries or
                data.walk_scratch.len < data.walk_queries.len or
                data.retained.layers.len <= first_retained_log_size)
                return error.SizeOverflow;
            const walk_capacity = try common.count(data.walk_queries.len);
            const retained_count = try common.count(data.retained.layers.len);
            const sparse_capacity = try common.count(data.sparse_indices.len);
            const status = Api.stwo_decommit_assemble_trace_on(
                tree_index,
                tree_role,
                leaf_log_size,
                first_retained_log_size,
                column_count,
                try common.words(session, data.mapped_count, 1),
                max_queries,
                try common.words(session, data.walk_queries, max_queries),
                try common.words(session, data.walk_scratch, max_queries),
                try common.words(session, data.walk_count, 1),
                walk_capacity,
                try common.hashes(
                    session,
                    data.retained.hashes,
                    data.retained.hashes.len,
                ),
                std.math.cast(u64, data.retained.hashes.len) orelse
                    return error.SizeOverflow,
                try common.merkleLayers(
                    session,
                    data.retained.layers,
                    retained_count,
                ),
                retained_count,
                try common.optionalWords(session, data.sparse_indices),
                try common.optionalHashes(session, data.sparse_hashes),
                sparse_capacity,
                try common.optionalWords(session, data.sparse_level_offsets),
                try common.optionalWords(session, data.sparse_level_counts),
                sparse_level_count,
                try common.words(session, data.assembly, 1),
                try common.count(data.assembly.len),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn assembleFri(
            session: anytype,
            tree_index: u32,
            leaf_log_size: u32,
            data: FriAssembly,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const query_capacity = try common.count(data.tree_queries.len);
            const expanded_capacity = try common.count(
                data.expanded_positions.len,
            );
            const workspace_capacity = try common.count(data.walk_queries.len);
            const retained_count = try common.count(data.retained.layers.len);
            const coordinate_words = std.math.mul(
                usize,
                data.coordinates.column_stride_words,
                4,
            ) catch return error.SizeOverflow;
            if (leaf_log_size >= 31 or query_capacity > max_protocol_queries)
                return error.InvalidKernelDescriptor;
            if (query_capacity == 0 or expanded_capacity == 0 or
                data.walk_scratch.len < data.walk_queries.len or
                workspace_capacity < expanded_capacity or
                data.coordinates.column_stride_words == 0 or
                data.coordinates.storage.len < coordinate_words or
                retained_count <= leaf_log_size)
                return error.SizeOverflow;
            const status = Api.stwo_decommit_assemble_fri_on(
                tree_index,
                leaf_log_size,
                try common.words(session, data.tree_queries, query_capacity),
                try common.words(session, data.tree_query_count, 1),
                query_capacity,
                try common.words(
                    session,
                    data.expanded_positions,
                    data.expanded_positions.len,
                ),
                try common.words(session, data.expanded_count, 1),
                expanded_capacity,
                try common.words(
                    session,
                    data.coordinates.storage,
                    coordinate_words,
                ),
                data.coordinates.column_stride_words,
                data.coordinates.storage.len,
                try common.words(
                    session,
                    data.walk_queries,
                    workspace_capacity,
                ),
                try common.words(
                    session,
                    data.walk_scratch,
                    workspace_capacity,
                ),
                try common.words(session, data.walk_count, 1),
                workspace_capacity,
                try common.hashes(
                    session,
                    data.retained.hashes,
                    data.retained.hashes.len,
                ),
                std.math.cast(u64, data.retained.hashes.len) orelse
                    return error.SizeOverflow,
                try common.merkleLayers(
                    session,
                    data.retained.layers,
                    retained_count,
                ),
                retained_count,
                try common.words(session, data.assembly, 1),
                try common.count(data.assembly.len),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

test "final decommitment boundary rejects poisoned assembly" {
    var words = [_]u32{0} ** 24;
    words[0] = 0x4457_5453;
    words[1] = 1;
    words[2] = 1;
    words[7] = words.len;
    words[8] = 0;
    words[23] = 1;
    try std.testing.expectEqualSlices(
        u32,
        &words,
        try validateAssemblyHeader(&words, 1),
    );

    words[7] = 0;
    try std.testing.expectError(
        error.InvalidDecommitmentAssembly,
        validateAssemblyHeader(&words, 1),
    );
}
