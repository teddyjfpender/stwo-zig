//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_5 = @import("binary_fri_outer_source_source_for_boundary.zig");
const dependency_7 = @import("binary_fri_outer_source_materialize_child_paths.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const air_digest = dependency_0.air_digest;
const relation = dependency_0.relation;
const fixed_wire = dependency_0.fixed_wire;
const trace_merkle_witness = dependency_0.trace_merkle_witness;
const fri_leaf_witness = dependency_0.fri_leaf_witness;
const fri_node_witness = dependency_0.fri_node_witness;
const fri_anchor_witness = dependency_0.fri_anchor_witness;
const merkle_path_witness = dependency_0.merkle_path_witness;
const merkle_path_poseidon = dependency_0.merkle_path_poseidon;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const ColumnOffset = dependency_0.ColumnOffset;
const Error = dependency_0.Error;
const SourceForBoundary = dependency_5.SourceForBoundary;
const materializeChildPaths = dependency_7.materializeChildPaths;
const childIndexForVerifier = dependency_7.childIndexForVerifier;
const sourceAuthorityDigest = dependency_9.sourceAuthorityDigest;
const hashInt = dependency_9.hashInt;

/// Version-neutral, monomorphized source seam for an integration-owned
/// authenticated child profile. `Boundary` must expose `PairPrepared`,
/// `RootPin`, `Wire`, and `Child` types plus allocation-free
/// `validateSource`, `fillQueryWords`, and `sourceAuthorityDigest` methods.
/// No function pointers or runtime proof-kind branches enter hot writers.
pub fn AuthenticatedSource(
    comptime dimensions: fixed_wire.Dimensions,
    comptime Boundary: type,
) type {
    if (Boundary.IS_LEGACY or Boundary.INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS)
        @compileError("authenticated source boundary must exclude prefix transcript calls");
    return SourceForBoundary(dimensions, Boundary);
}

pub fn typedRowWidth(comptime Row: type) usize {
    return switch (@typeInfo(Row)) {
        .array => |array| if (array.child == M31)
            array.len
        else
            @compileError("relation row must contain M31"),
        else => @compileError("relation row must be an M31 array"),
    };
}

pub fn addTypedRowStorage(
    comptime Row: type,
    total: *usize,
    row_count: usize,
) Error!void {
    const elements = std.math.mul(
        usize,
        typedRowWidth(Row),
        row_count,
    ) catch return error.ArithmeticOverflow;
    total.* = std.math.add(usize, total.*, elements) catch
        return error.ArithmeticOverflow;
}

pub fn carveTypedRows(
    comptime Row: type,
    storage: []M31,
    at: *usize,
    row_count: usize,
) []Row {
    const element_count = typedRowWidth(Row) * row_count;
    std.debug.assert(at.* <= storage.len and element_count <= storage.len - at.*);
    const words = storage[at.*..][0..element_count];
    at.* += element_count;
    return std.mem.bytesAsSlice(Row, std.mem.sliceAsBytes(words));
}

pub fn validateTypedRowsInStorage(
    comptime Row: type,
    rows: []const Row,
    storage: []const M31,
    at: *usize,
) Error!void {
    const element_count = std.math.mul(
        usize,
        typedRowWidth(Row),
        rows.len,
    ) catch return error.ArithmeticOverflow;
    if (at.* > storage.len or element_count > storage.len - at.*)
        return error.WorkspaceAuthorityMismatch;
    const expected = storage[at.*..][0..element_count];
    if (@intFromPtr(rows.ptr) != @intFromPtr(expected.ptr) or
        @sizeOf(Row) * rows.len != @sizeOf(M31) * expected.len)
    {
        return error.WorkspaceAuthorityMismatch;
    }
    at.* += element_count;
}

pub fn columnLogicalRow(
    comptime count: usize,
    columns: anytype,
    offset: usize,
    row: usize,
) [count]M31 {
    var result: [count]M31 = undefined;
    inline for (0..count) |column| result[column] = columns[offset + column][row];
    return result;
}

pub fn relationRowsDigest(rows: anytype) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-fri-retained-relation-rows/v1\x00");
    hash.update(&rows.source_authority_digest);
    hashInt(&hash, u64, rows.storage.len);
    for (rows.storage) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

pub fn friPathLeafDigest(source: anytype, columns: *const [MAIN_COLUMN_COUNT][]M31) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-fri-path-leaves/v1\x00");
    var trace_count: usize = 0;
    const trace_output_start = ColumnOffset.trace_merkle_main +
        @intFromEnum(trace_merkle_witness.MainSource.output_0);
    for (source.fri_rows.trace_merkle_preprocessing.rows, 0..) |row, row_index| {
        if (row.binary_mask != 1 or row.last != 1) continue;
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.tree);
        hashInt(&hash, u32, row.query);
        for (0..merkle_path_witness.DIGEST_WORD_COUNT) |word| hashInt(
            &hash,
            u32,
            columns[trace_output_start + word][row_index].toU32(),
        );
        trace_count += 1;
    }
    hashInt(&hash, u64, trace_count);

    var fri_count: usize = 0;
    const fri_digest_start = ColumnOffset.fri_anchor_main +
        @intFromEnum(fri_anchor_witness.MainSource.digest_0);
    for (source.fri_rows.fri_anchor_preprocessing.rows, 0..) |row, row_index| {
        if (row.binary_mask != 1) continue;
        hashInt(&hash, u32, row.verifier_id);
        hashInt(&hash, u32, row.layer);
        hashInt(&hash, u32, row.query);
        for (0..merkle_path_witness.DIGEST_WORD_COUNT) |word| hashInt(
            &hash,
            u32,
            columns[fri_digest_start + word][row_index].toU32(),
        );
        fri_count += 1;
    }
    hashInt(&hash, u64, fri_count);
    return hash.finalResult();
}

pub fn merkleLeafCount(source: anytype) !usize {
    var result: usize = 0;
    for (source.children) |child| {
        const capture = child.capture;
        const trees = std.math.add(
            usize,
            capture.trace_tree_heights.len,
            capture.fri_siblings.len,
        ) catch return error.ArithmeticOverflow;
        result = std.math.add(
            usize,
            result,
            std.math.mul(usize, trees, capture.raw_queries.len) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
    }
    return result;
}

pub fn childLeafBase(source: anytype, child_index: usize) !usize {
    var result: usize = 0;
    for (source.children[0..child_index]) |child| {
        const capture = child.capture;
        const trees = std.math.add(
            usize,
            capture.trace_tree_heights.len,
            capture.fri_siblings.len,
        ) catch return error.ArithmeticOverflow;
        result = std.math.add(
            usize,
            result,
            std.math.mul(usize, trees, capture.raw_queries.len) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
    }
    return result;
}

pub fn merkleInvocationCount(source: anytype) !usize {
    var result: usize = 0;
    for (source.children) |child| {
        const capture = child.capture;
        var trace_depth: usize = 0;
        for (capture.trace_tree_heights) |height| trace_depth = std.math.add(
            usize,
            trace_depth,
            @as(usize, height),
        ) catch return error.ArithmeticOverflow;
        result = std.math.add(
            usize,
            result,
            std.math.mul(usize, trace_depth, capture.raw_queries.len) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        for (capture.fri_siblings) |siblings| result = std.math.add(
            usize,
            result,
            siblings.len,
        ) catch return error.ArithmeticOverflow;
    }
    return result;
}

pub fn activeBinaryRowCount(rows: anytype) !usize {
    var result: usize = 0;
    for (rows) |row| if (row.binary_mask == 1) {
        result = std.math.add(usize, result, 1) catch
            return error.ArithmeticOverflow;
    };
    return result;
}

pub fn nonPathPoseidonCallCount(source: anytype) !usize {
    var result: usize = 0;
    if (comptime @TypeOf(source.*).INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS) {
        for (source.pair.executions) |execution| {
            result = std.math.add(
                usize,
                result,
                execution.poseidon_calls.len,
            ) catch return error.ArithmeticOverflow;
        }
    }
    inline for (.{
        source.fri_rows.trace_merkle_preprocessing.rows,
        source.fri_rows.fri_leaf_preprocessing.rows,
        source.fri_rows.fri_node_preprocessing.rows,
    }) |rows| {
        result = std.math.add(
            usize,
            result,
            try activeBinaryRowCount(rows),
        ) catch return error.ArithmeticOverflow;
    }
    return result;
}

pub fn sharedPoseidonCallCount(source: anytype) !usize {
    return std.math.add(
        usize,
        try nonPathPoseidonCallCount(source),
        try merkleInvocationCount(source),
    ) catch return error.ArithmeticOverflow;
}

pub fn retainPoseidonCall(
    calls: []merkle_path_poseidon.Call,
    outputs: [][merkle_path_poseidon.WIDTH]u32,
    cursor: *usize,
    input: [merkle_path_poseidon.WIDTH]M31,
    output: [merkle_path_poseidon.WIDTH]M31,
) !void {
    if (cursor.* >= calls.len or cursor.* >= outputs.len)
        return error.WorkspaceAuthorityMismatch;
    var call_input: [merkle_path_poseidon.WIDTH]u32 = undefined;
    var retained_output: [merkle_path_poseidon.WIDTH]u32 = undefined;
    for (&call_input, input) |*target, word| target.* = word.toU32();
    for (&retained_output, output) |*target, word| target.* = word.toU32();
    calls[cursor.*] = .{
        .input = call_input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
    outputs[cursor.*] = retained_output;
    cursor.* += 1;
}

pub fn retainNonPathPoseidonCalls(
    source: anytype,
    fri_workspace: anytype,
    workspace: anytype,
) !usize {
    const width = merkle_path_poseidon.WIDTH;
    const rate = merkle_path_witness.DIGEST_WORD_COUNT;
    var cursor: usize = 0;

    // Row 1: exact calls and outputs retained by the admitted transcript
    // execution. No transcript material is reparsed or replayed here.
    if (comptime @TypeOf(source.*).INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS) {
        for (source.pair.executions) |execution| {
            for (execution.poseidon_calls) |call| {
                try retainPoseidonCall(
                    workspace.poseidon_calls,
                    workspace.poseidon_outputs,
                    &cursor,
                    call.input,
                    call.output,
                );
            }
        }
    }

    // Row 23: trace-leaf sponge permutations.
    const trace_previous = ColumnOffset.trace_merkle_main +
        @intFromEnum(trace_merkle_witness.MainSource.previous_0);
    const trace_chunk = ColumnOffset.trace_merkle_main +
        @intFromEnum(trace_merkle_witness.MainSource.chunk_0);
    const trace_output = ColumnOffset.trace_merkle_main +
        @intFromEnum(trace_merkle_witness.MainSource.output_0);
    for (source.fri_rows.trace_merkle_preprocessing.rows, 0..) |row, row_index| {
        if (row.binary_mask != 1) continue;
        var input: [width]M31 = undefined;
        var output: [width]M31 = undefined;
        for (0..width) |word| {
            input[word] = fri_workspace.main_columns[
                trace_previous + word
            ][row_index];
            if (word < rate) input[word] = input[word].add(
                fri_workspace.main_columns[trace_chunk + word][row_index],
            );
            output[word] = fri_workspace.main_columns[
                trace_output + word
            ][row_index];
        }
        try retainPoseidonCall(
            workspace.poseidon_calls,
            workspace.poseidon_outputs,
            &cursor,
            input,
            output,
        );
    }

    // Row 25: packed FRI-leaf sponge permutations.
    const leaf_previous = ColumnOffset.fri_leaf_main +
        @intFromEnum(fri_leaf_witness.MainSource.previous_0);
    const leaf_chunk = ColumnOffset.fri_leaf_main +
        @intFromEnum(fri_leaf_witness.MainSource.chunk_0);
    const leaf_output = ColumnOffset.fri_leaf_main +
        @intFromEnum(fri_leaf_witness.MainSource.output_0);
    for (source.fri_rows.fri_leaf_preprocessing.rows, 0..) |row, row_index| {
        if (row.binary_mask != 1) continue;
        var input: [width]M31 = undefined;
        var output: [width]M31 = undefined;
        for (0..width) |word| {
            input[word] = fri_workspace.main_columns[
                leaf_previous + word
            ][row_index];
            if (word < rate) input[word] = input[word].add(
                fri_workspace.main_columns[leaf_chunk + word][row_index],
            );
            output[word] = fri_workspace.main_columns[
                leaf_output + word
            ][row_index];
        }
        try retainPoseidonCall(
            workspace.poseidon_calls,
            workspace.poseidon_outputs,
            &cursor,
            input,
            output,
        );
    }

    // Row 26: local FRI Merkle-node permutations.
    const node_left = ColumnOffset.fri_node_main +
        @intFromEnum(fri_node_witness.MainSource.left_0);
    const node_right = ColumnOffset.fri_node_main +
        @intFromEnum(fri_node_witness.MainSource.right_0);
    const node_parent = ColumnOffset.fri_node_main +
        @intFromEnum(fri_node_witness.MainSource.parent_0);
    const node_tail = ColumnOffset.fri_node_main +
        @intFromEnum(fri_node_witness.MainSource.output_8);
    for (source.fri_rows.fri_node_preprocessing.rows, 0..) |row, row_index| {
        if (row.binary_mask != 1) continue;
        var input: [width]M31 = undefined;
        var output: [width]M31 = undefined;
        for (0..rate) |word| {
            input[word] = fri_workspace.main_columns[
                node_left + word
            ][row_index];
            input[rate + word] = fri_workspace.main_columns[
                node_right + word
            ][row_index];
            output[word] = fri_workspace.main_columns[
                node_parent + word
            ][row_index];
            output[rate + word] = fri_workspace.main_columns[
                node_tail + word
            ][row_index];
        }
        try retainPoseidonCall(
            workspace.poseidon_calls,
            workspace.poseidon_outputs,
            &cursor,
            input,
            output,
        );
    }
    if (cursor != try nonPathPoseidonCallCount(source))
        return error.WorkspaceAuthorityMismatch;
    return cursor;
}

pub fn materializeMerkleWorkspace(
    source: anytype,
    fri_workspace: anytype,
    workspace: anytype,
) !void {
    @memset(workspace.leaf_digests, [_]u32{0} ** merkle_path_witness.DIGEST_WORD_COUNT);
    var captured_leaves: usize = 0;
    const trace_output_start = ColumnOffset.trace_merkle_main +
        @intFromEnum(trace_merkle_witness.MainSource.output_0);
    for (source.fri_rows.trace_merkle_preprocessing.rows, 0..) |row, row_index| {
        if (row.binary_mask != 1 or row.last != 1) continue;
        const child_index = try childIndexForVerifier(row.verifier_id);
        const capture = source.children[child_index].capture;
        const leaf_index = try childLeafBase(source, child_index) +
            @as(usize, row.tree) * capture.raw_queries.len +
            @as(usize, row.query);
        if (leaf_index >= workspace.leaf_digests.len)
            return error.WorkspaceAuthorityMismatch;
        for (&workspace.leaf_digests[leaf_index], 0..) |*word, index|
            word.* = fri_workspace.main_columns[
                trace_output_start + index
            ][row_index].toU32();
        captured_leaves += 1;
    }
    const fri_digest_start = ColumnOffset.fri_anchor_main +
        @intFromEnum(fri_anchor_witness.MainSource.digest_0);
    for (source.fri_rows.fri_anchor_preprocessing.rows, 0..) |row, row_index| {
        if (row.binary_mask != 1) continue;
        const child_index = try childIndexForVerifier(row.verifier_id);
        const capture = source.children[child_index].capture;
        const leaf_index = try childLeafBase(source, child_index) +
            capture.trace_tree_heights.len * capture.raw_queries.len +
            @as(usize, row.layer) * capture.raw_queries.len +
            @as(usize, row.query);
        if (leaf_index >= workspace.leaf_digests.len)
            return error.WorkspaceAuthorityMismatch;
        for (&workspace.leaf_digests[leaf_index], 0..) |*word, index|
            word.* = fri_workspace.main_columns[
                fri_digest_start + index
            ][row_index].toU32();
        captured_leaves += 1;
    }
    if (captured_leaves != workspace.leaf_digests.len)
        return error.WorkspaceAuthorityMismatch;

    const path_poseidon_base = try retainNonPathPoseidonCalls(
        source,
        fri_workspace,
        workspace,
    );
    var cursor: usize = 0;
    for (source.children, 0..) |child, child_index| try materializeChildPaths(
        source,
        child.capture,
        child_index,
        workspace,
        path_poseidon_base,
        &cursor,
    );
    if (cursor != workspace.invocations.len or
        path_poseidon_base + cursor != workspace.poseidon_calls.len)
    {
        return error.WorkspaceAuthorityMismatch;
    }
}
