//! Checked resident trace and FRI opening assembly dispatch.

const abi = @import("../../abi/stages/decommit.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
const stage = telemetry.Stage.decommit;

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

pub const TraceAssembly = struct {
    mapped_count: common.Words,
    walk_queries: common.Words,
    walk_scratch: common.Words,
    walk_count: common.Words,
    retained_layers: common.PointerTable,
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
    coordinate_columns: common.PointerTable,
    walk_queries: common.Words,
    walk_scratch: common.Words,
    walk_count: common.Words,
    retained_layers: common.PointerTable,
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
            const status = Api.stwo_decommit_normalize_queries_on(
                try common.words(session, raw_queries, raw_count),
                raw_count,
                query_log_size,
                tree_count,
                try common.words(session, unique_queries, raw_count),
                try common.words(session, unique_count, 1),
                try common.words(session, assembly, 1),
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
                try common.words(session, output.leaf_indices, max_queries),
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
            columns: common.PointerTable,
            column_log_sizes: common.Words,
            lifting_log_size: u32,
            mapped_queries: common.Words,
            mapped_count: common.Words,
            assembly: common.Words,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = try common.count(columns.len);
            const max_queries = try common.count(mapped_queries.len);
            try common.requireNonZero(&.{ group_count, max_queries });
            const status = Api.stwo_decommit_pack_trace_group_on(
                tree_index,
                total_column_count,
                first_column,
                group_count,
                try common.constWordTable(session, columns, group_count),
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
            if (child_hashes.len < max_children or parent_indices.len == 0 or
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
            if (max_queries == 0 or fold_step >= 32)
                return error.InvalidKernelDescriptor;
            const expansion = @as(usize, 1) << @intCast(fold_step);
            const expanded_capacity = @import("std").math.mul(
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
                try common.words(session, output.expanded_count, 1),
                try common.words(session, output.walk, expanded_capacity),
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
                sparse_level_count,
            });
            if (data.sparse_level_offsets.len < sparse_level_count)
                return error.SizeOverflow;
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
                try common.hashTable(session, data.retained_layers, 1),
                try common.words(session, data.sparse_indices, 1),
                try common.hashes(session, data.sparse_hashes, 1),
                try common.words(
                    session,
                    data.sparse_level_offsets,
                    sparse_level_count,
                ),
                try common.words(
                    session,
                    data.sparse_level_counts,
                    sparse_level_count,
                ),
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
            if (query_capacity == 0 or data.expanded_positions.len == 0)
                return error.SizeOverflow;
            const status = Api.stwo_decommit_assemble_fri_on(
                tree_index,
                leaf_log_size,
                try common.words(session, data.tree_queries, query_capacity),
                try common.words(session, data.tree_query_count, 1),
                try common.words(
                    session,
                    data.expanded_positions,
                    data.expanded_positions.len,
                ),
                try common.words(session, data.expanded_count, 1),
                try common.constWordTable(session, data.coordinate_columns, 4),
                try common.words(session, data.walk_queries, query_capacity),
                try common.words(session, data.walk_scratch, query_capacity),
                try common.words(session, data.walk_count, 1),
                try common.hashTable(session, data.retained_layers, 1),
                try common.words(session, data.assembly, 1),
                try common.count(data.assembly.len),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}
