//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_6 = @import("binary_fri_outer_source_retain_non_path_poseidon_calls.zig");
const dependency_8 = @import("binary_fri_outer_source_composition_source_value.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const air_digest = dependency_0.air_digest;
const captured_fri = dependency_0.captured_fri;
const protocol = dependency_0.protocol;
const composition = dependency_0.composition;
const merkle_root_witness = dependency_0.merkle_root_witness;
const trace_merkle_witness = dependency_0.trace_merkle_witness;
const multiply_witness = dependency_0.multiply_witness;
const inverse_witness = dependency_0.inverse_witness;
const linear_witness = dependency_0.linear_witness;
const merkle_path_witness = dependency_0.merkle_path_witness;
const merkle_path_poseidon = dependency_0.merkle_path_poseidon;
const LEFT_CHILD = dependency_0.LEFT_CHILD;
const RIGHT_CHILD = dependency_0.RIGHT_CHILD;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const MERKLE_PATH_MAIN_COLUMN_COUNT = dependency_0.MERKLE_PATH_MAIN_COLUMN_COUNT;
const Error = dependency_0.Error;
const childLeafBase = dependency_6.childLeafBase;
const typedSlicesOverlap = dependency_8.typedSlicesOverlap;
const bytesOverlap = dependency_8.bytesOverlap;
const hashInt = dependency_9.hashInt;

pub fn materializeChildPaths(
    source: anytype,
    capture: *const captured_fri.Owned,
    child_index: usize,
    workspace: anytype,
    path_poseidon_base: usize,
    cursor: *usize,
) !void {
    const verifier_id: u32 = if (child_index == LEFT_CHILD)
        trace_merkle_witness.LEFT_RECURSION_VERIFIER_ID
    else
        trace_merkle_witness.RIGHT_RECURSION_VERIFIER_ID;
    const query_count = capture.raw_queries.len;
    const leaf_base = try childLeafBase(source, child_index);
    for (capture.trace_tree_heights, 0..) |height_u32, tree| {
        const height: usize = @intCast(height_u32);
        const siblings = capture.trace_siblings[tree];
        if (siblings.len != query_count * height)
            return error.CaptureWireMismatch;
        const tree_id = try merkle_root_witness.traceTreeId(verifier_id, tree);
        for (capture.raw_queries, 0..) |raw_query, query| {
            const position = mapTreeQueryPosition(
                raw_query.toU32(),
                capture.circuit.lifting_log_size,
                height_u32,
            );
            const start = cursor.*;
            for (0..height) |depth| {
                if (cursor.* >= workspace.invocations.len)
                    return error.WorkspaceAuthorityMismatch;
                const leaf_layer = height - depth - 1;
                const direction: u32 = @intCast(
                    (position >> @intCast(leaf_layer)) & 1,
                );
                workspace.invocations[cursor.*] = .{
                    .tree_id = tree_id,
                    .depth = @intCast(depth),
                    .index = @intCast(position >> @intCast(height - depth)),
                    .child = [_]u32{0} ** merkle_path_witness.DIGEST_WORD_COUNT,
                    .step = .{
                        .direction = direction,
                        .sibling = siblings[query * height + leaf_layer],
                    },
                    .is_leaf = depth + 1 == height,
                };
                cursor.* += 1;
            }
            const leaf_index = leaf_base + tree * query_count + query;
            try cachePathReverse(
                workspace,
                start,
                cursor.*,
                path_poseidon_base,
                workspace.leaf_digests[leaf_index],
                capture.trace_roots[tree],
            );
        }
    }

    var folded_bits: u32 = 0;
    for (
        capture.fri_siblings,
        capture.fri_roots,
        capture.fold_widths,
        0..,
    ) |siblings, root, fold_width, layer| {
        if (!std.math.isPowerOfTwo(fold_width) or query_count == 0 or
            siblings.len % query_count != 0)
        {
            return error.CaptureWireMismatch;
        }
        folded_bits = std.math.add(
            u32,
            folded_bits,
            std.math.log2_int(u32, fold_width),
        ) catch return error.ArithmeticOverflow;
        const path_depth = siblings.len / query_count;
        if (folded_bits >= capture.circuit.lifting_log_size or
            path_depth == 0 or
            path_depth != capture.circuit.lifting_log_size - folded_bits)
        {
            return error.CaptureWireMismatch;
        }
        const tree_id = try merkle_root_witness.friTreeId(verifier_id, layer);
        for (capture.raw_queries, 0..) |raw_query, query| {
            const position = raw_query.toU32() >> @intCast(folded_bits);
            const start = cursor.*;
            for (0..path_depth) |depth| {
                if (cursor.* >= workspace.invocations.len)
                    return error.WorkspaceAuthorityMismatch;
                const leaf_layer = path_depth - depth - 1;
                const direction: u32 = @intCast(
                    (position >> @intCast(leaf_layer)) & 1,
                );
                workspace.invocations[cursor.*] = .{
                    .tree_id = tree_id,
                    .depth = @intCast(depth),
                    .index = @intCast(
                        position >> @intCast(path_depth - depth),
                    ),
                    .child = [_]u32{0} ** merkle_path_witness.DIGEST_WORD_COUNT,
                    .step = .{
                        .direction = direction,
                        .sibling = siblings[query * path_depth + leaf_layer],
                    },
                    .is_leaf = depth + 1 == path_depth,
                };
                cursor.* += 1;
            }
            const leaf_index = leaf_base +
                capture.trace_tree_heights.len * query_count +
                layer * query_count + query;
            try cachePathReverse(
                workspace,
                start,
                cursor.*,
                path_poseidon_base,
                workspace.leaf_digests[leaf_index],
                root,
            );
        }
    }
}

pub fn cachePathReverse(
    workspace: anytype,
    start: usize,
    end: usize,
    path_poseidon_base: usize,
    leaf: [merkle_path_witness.DIGEST_WORD_COUNT]u32,
    expected_root: protocol.Digest,
) !void {
    var current = leaf;
    var reverse = end;
    while (reverse > start) {
        reverse -= 1;
        workspace.invocations[reverse].child = current;
        const logical = try merkle_path_witness.logicalRow(
            workspace.invocations[reverse],
        );
        workspace.logical_rows[reverse] = logical;
        const provider_index = path_poseidon_base + reverse;
        if (provider_index >= workspace.poseidon_calls.len)
            return error.WorkspaceAuthorityMismatch;
        workspace.poseidon_calls[provider_index] = try merkle_path_poseidon.call(
            workspace.invocations[reverse],
        );
        const parent_start = @intFromEnum(merkle_path_witness.MainSource.parent_0);
        const tail_start = parent_start + merkle_path_witness.DIGEST_WORD_COUNT;
        for (&workspace.poseidon_outputs[provider_index], 0..) |*word, index| {
            const source_index = if (index < merkle_path_witness.DIGEST_WORD_COUNT)
                parent_start + index
            else
                tail_start + index - merkle_path_witness.DIGEST_WORD_COUNT;
            word.* = logical[source_index].toU32();
        }
        for (&current, 0..) |*word, index|
            word.* = logical[parent_start + index].toU32();
    }
    if (!std.mem.eql(u32, &current, &expected_root))
        return error.CaptureWireMismatch;
}

pub fn childIndexForVerifier(verifier_id: u32) !usize {
    return switch (verifier_id) {
        trace_merkle_witness.LEFT_RECURSION_VERIFIER_ID => LEFT_CHILD,
        trace_merkle_witness.RIGHT_RECURSION_VERIFIER_ID => RIGHT_CHILD,
        else => error.ChildOrderMismatch,
    };
}

pub fn mapTreeQueryPosition(position: u32, max_log_size: u32, tree_log_size: u32) u32 {
    if (tree_log_size == 0) return 0;
    if (max_log_size < tree_log_size) {
        return (position >> 1 << @intCast(tree_log_size - max_log_size + 1)) +
            (position & 1);
    }
    return (position >> @intCast(max_log_size - tree_log_size + 1) << 1) +
        (position & 1);
}

pub fn merkleWorkspaceDigest(workspace: anytype) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-shared-poseidon-workspace/v2\x00");
    hash.update(&workspace.source_authority_digest);
    hash.update(&workspace.fri_path_leaf_digest);
    hashInt(&hash, u32, workspace.log_size);
    hashInt(&hash, u32, workspace.provider_log_size);
    hashInt(&hash, u64, workspace.leaf_digests.len);
    for (workspace.leaf_digests) |value| for (value) |word|
        hashInt(&hash, u32, word);
    hashInt(&hash, u64, workspace.invocations.len);
    for (workspace.invocations) |invocation| {
        hashInt(&hash, u32, invocation.tree_id);
        hashInt(&hash, u32, invocation.depth);
        hashInt(&hash, u32, invocation.index);
        for (invocation.child) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u32, invocation.step.direction);
        for (invocation.step.sibling) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u8, @intFromBool(invocation.is_leaf));
    }
    for (workspace.logical_rows) |row| for (row) |word|
        hashInt(&hash, u32, word.toU32());
    for (workspace.poseidon_calls) |call| {
        for (call.input) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
        hashInt(&hash, u8, @intFromBool(call.narrow_output != null));
        if (call.narrow_output) |word| hashInt(&hash, u32, word);
    }
    for (workspace.poseidon_outputs) |output| for (output) |word|
        hashInt(&hash, u32, word);
    return hash.finalResult();
}

pub fn validateMerkleWorkspaceAliases(workspace: anytype) Error!void {
    if (typedSlicesOverlap(
        [merkle_path_witness.DIGEST_WORD_COUNT]u32,
        workspace.leaf_digests,
        merkle_path_witness.Invocation,
        workspace.invocations,
    ) or typedSlicesOverlap(
        [merkle_path_witness.DIGEST_WORD_COUNT]u32,
        workspace.leaf_digests,
        [MERKLE_PATH_MAIN_COLUMN_COUNT]M31,
        workspace.logical_rows,
    ) or typedSlicesOverlap(
        [merkle_path_witness.DIGEST_WORD_COUNT]u32,
        workspace.leaf_digests,
        merkle_path_poseidon.Call,
        workspace.poseidon_calls,
    ) or typedSlicesOverlap(
        [merkle_path_witness.DIGEST_WORD_COUNT]u32,
        workspace.leaf_digests,
        [merkle_path_poseidon.WIDTH]u32,
        workspace.poseidon_outputs,
    ) or typedSlicesOverlap(
        merkle_path_witness.Invocation,
        workspace.invocations,
        [MERKLE_PATH_MAIN_COLUMN_COUNT]M31,
        workspace.logical_rows,
    ) or typedSlicesOverlap(
        merkle_path_witness.Invocation,
        workspace.invocations,
        merkle_path_poseidon.Call,
        workspace.poseidon_calls,
    ) or typedSlicesOverlap(
        merkle_path_witness.Invocation,
        workspace.invocations,
        [merkle_path_poseidon.WIDTH]u32,
        workspace.poseidon_outputs,
    ) or typedSlicesOverlap(
        [MERKLE_PATH_MAIN_COLUMN_COUNT]M31,
        workspace.logical_rows,
        merkle_path_poseidon.Call,
        workspace.poseidon_calls,
    ) or typedSlicesOverlap(
        [MERKLE_PATH_MAIN_COLUMN_COUNT]M31,
        workspace.logical_rows,
        [merkle_path_poseidon.WIDTH]u32,
        workspace.poseidon_outputs,
    ) or typedSlicesOverlap(
        merkle_path_poseidon.Call,
        workspace.poseidon_calls,
        [merkle_path_poseidon.WIDTH]u32,
        workspace.poseidon_outputs,
    )) return error.WorkspaceAuthorityMismatch;
}

pub fn validateMerkleDestination(destination: [][]M31, workspace: anytype) Error!void {
    for (destination) |column| if (typedSlicesOverlap(
        M31,
        column,
        [merkle_path_witness.DIGEST_WORD_COUNT]u32,
        workspace.leaf_digests,
    ) or typedSlicesOverlap(
        M31,
        column,
        merkle_path_witness.Invocation,
        workspace.invocations,
    ) or typedSlicesOverlap(
        M31,
        column,
        [MERKLE_PATH_MAIN_COLUMN_COUNT]M31,
        workspace.logical_rows,
    ) or typedSlicesOverlap(
        M31,
        column,
        merkle_path_poseidon.Call,
        workspace.poseidon_calls,
    ) or typedSlicesOverlap(
        M31,
        column,
        [merkle_path_poseidon.WIDTH]u32,
        workspace.poseidon_outputs,
    )) return error.DestinationAlias;
}

pub fn columnStorageCount(
    log_sizes: anytype,
    column_counts: anytype,
) Error!usize {
    var result: usize = 0;
    for (log_sizes, column_counts) |log_size, column_count| {
        const row_count = try rowCount(log_size);
        const component_count = std.math.mul(
            usize,
            row_count,
            column_count,
        ) catch return error.ArithmeticOverflow;
        result = std.math.add(usize, result, component_count) catch
            return error.ArithmeticOverflow;
    }
    return result;
}

pub fn rowCount(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn carveColumnViews(
    views: anytype,
    storage: []M31,
    storage_at: *usize,
    log_sizes: anytype,
    column_counts: anytype,
) Error!void {
    var column_at: usize = 0;
    for (log_sizes, column_counts) |log_size, column_count| {
        const rows = try rowCount(log_size);
        for (0..column_count) |_| {
            if (column_at >= views.len or storage_at.* > storage.len or
                rows > storage.len - storage_at.*)
            {
                return error.WorkspaceAuthorityMismatch;
            }
            views[column_at] = storage[storage_at.*..][0..rows];
            column_at += 1;
            storage_at.* += rows;
        }
    }
    if (column_at != views.len) return error.WorkspaceAuthorityMismatch;
}

pub fn validateColumnViews(
    views: anytype,
    storage: []const M31,
    storage_at: *usize,
    log_sizes: anytype,
    column_counts: anytype,
) Error!void {
    var column_at: usize = 0;
    for (log_sizes, column_counts) |log_size, column_count| {
        const rows = try rowCount(log_size);
        for (0..column_count) |_| {
            if (column_at >= views.len or storage_at.* > storage.len or
                rows > storage.len - storage_at.*)
            {
                return error.WorkspaceAuthorityMismatch;
            }
            const expected = storage[storage_at.*..][0..rows];
            const actual = views[column_at];
            if (actual.ptr != expected.ptr or actual.len != expected.len)
                return error.WorkspaceAuthorityMismatch;
            column_at += 1;
            storage_at.* += rows;
        }
    }
    if (column_at != views.len) return error.WorkspaceAuthorityMismatch;
}

pub fn validateDestination(
    destination: [][]M31,
    log_sizes: anytype,
    column_counts: anytype,
    workspace_storage: []const M31,
    source: anytype,
) Error!void {
    var expected_columns: usize = 0;
    for (column_counts) |count| expected_columns += count;
    if (destination.len != expected_columns)
        return error.DestinationShapeMismatch;
    var column_at: usize = 0;
    for (log_sizes, column_counts) |log_size, column_count| {
        const rows = try rowCount(log_size);
        for (0..column_count) |_| {
            if (destination[column_at].len != rows)
                return error.DestinationShapeMismatch;
            column_at += 1;
        }
    }
    for (destination, 0..) |column, index| {
        if (typedSlicesOverlap(M31, column, M31, workspace_storage) or
            bytesOverlap(std.mem.sliceAsBytes(column), std.mem.asBytes(source)) or
            typedSlicesOverlap(M31, column, M31, source.query_word_storage) or
            bytesOverlap(std.mem.sliceAsBytes(column), std.mem.asBytes(source.pair)))
        {
            return error.DestinationAlias;
        }
        for (source.children) |child| {
            if (bytesOverlap(
                std.mem.sliceAsBytes(column),
                std.mem.asBytes(child.wire),
            ) or bytesOverlap(
                std.mem.sliceAsBytes(column),
                std.mem.asBytes(child.capture),
            ) or typedSlicesOverlap(
                M31,
                column,
                QM31,
                child.capture.evaluation.values,
            ) or typedSlicesOverlap(
                M31,
                column,
                QM31,
                child.capture.pcs_evaluation.values,
            ) or typedSlicesOverlap(
                M31,
                column,
                M31,
                child.capture.m31_storage,
            ) or typedSlicesOverlap(
                M31,
                column,
                QM31,
                child.capture.qm31_storage,
            )) return error.DestinationAlias;
            if (child.composition) |composition_authority| if (typedSlicesOverlap(
                M31,
                column,
                QM31,
                composition_authority.evaluation.values,
            )) return error.DestinationAlias;
        }
        for (destination[0..index]) |previous| if (typedSlicesOverlap(
            M31,
            column,
            M31,
            previous,
        )) return error.DestinationAlias;
    }
}

pub fn validateArithmeticDestination(destination: [][]M31, workspace: anytype) Error!void {
    for (destination) |column| {
        if (typedSlicesOverlap(
            M31,
            column,
            multiply_witness.Invocation,
            workspace.multiply_invocations,
        ) or typedSlicesOverlap(
            M31,
            column,
            inverse_witness.Invocation,
            workspace.inverse_invocations,
        ) or typedSlicesOverlap(
            M31,
            column,
            linear_witness.Invocation,
            workspace.linear_invocations,
        )) return error.DestinationAlias;
    }
}

pub fn copyColumns(destination: [][]M31, source: anytype) void {
    std.debug.assert(destination.len == source.len);
    for (destination, source) |target, values| {
        std.debug.assert(target.len == values.len);
        @memcpy(target, values);
    }
}
