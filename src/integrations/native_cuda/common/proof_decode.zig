//! Descriptor-driven canonical host reconstruction from a resident SWPC result.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const proof_wire = @import("../../../interop/proof_wire.zig");
const decommit_bundle =
    @import("stwo_cuda_backend").runtime.proof_assembly.decommit_bundle;
const stark_bundle =
    @import("stwo_cuda_backend").runtime.proof_assembly.stark_bundle;
const uniform_layout = @import("uniform_layout.zig");

pub const Error = error{
    InvalidCommitmentLayout,
    InvalidFieldElement,
    InvalidFriOpening,
    InvalidMerkleArtifacts,
    InvalidSampleLayout,
    InvalidTraceOpening,
    SizeOverflow,
};

/// `Descriptor.geometry(protocol)` admits the statement encoded in the SWPC
/// fixed header. Tree shape comes exclusively from `Layout`.
pub fn DecoderFor(
    comptime Layout: type,
    comptime Descriptor: type,
) type {
    comptime {
        if (!@hasDecl(Descriptor, "geometry"))
            @compileError("proof decoder descriptor requires geometry");
    }
    return struct {
        pub const OwnedProofWire = struct {
            arena: std.heap.ArenaAllocator,
            value: proof_wire.ProofWire,

            pub fn init(
                allocator: std.mem.Allocator,
                bundle: stark_bundle.Bundle,
            ) !OwnedProofWire {
                var arena = std.heap.ArenaAllocator.init(allocator);
                errdefer arena.deinit();
                const value = try decodeWire(arena.allocator(), bundle);
                return .{ .arena = arena, .value = value };
            }

            pub fn deinit(self: *OwnedProofWire) void {
                self.arena.deinit();
                self.* = undefined;
            }
        };

        pub fn decodeProof(
            allocator: std.mem.Allocator,
            bundle: stark_bundle.Bundle,
        ) !proof_wire.Proof {
            var wire = try OwnedProofWire.init(allocator, bundle);
            defer wire.deinit();
            return proof_wire.wireToProof(allocator, wire.value);
        }

        fn decodeWire(
            allocator: std.mem.Allocator,
            bundle: stark_bundle.Bundle,
        ) !proof_wire.ProofWire {
            const protocol = bundle.protocol;
            const geometry = try Descriptor.geometry(protocol);
            var logical = try Layout.init(allocator, geometry);
            defer logical.deinit(allocator);
            try logical.validate();

            var opened_tree_count: usize = 0;
            for (logical.trace_trees) |tree| {
                opened_tree_count += @intFromBool(tree.decommitted);
            }
            if (@as(usize, protocol.commitment_root_count) !=
                logical.trace_trees.len or
                @as(usize, protocol.fri_root_count) !=
                    logical.fri_trees.len or
                @as(usize, protocol.decommit_tree_count) !=
                    opened_tree_count + logical.fri_trees.len)
            {
                return error.InvalidCommitmentLayout;
            }

            const commitments = try decodeHashes(
                allocator,
                bundle.commitmentRoots(),
                logical.trace_trees.len,
            );
            const samples = try decodeSamples(
                Descriptor,
                allocator,
                bundle.sampledValues(),
                &logical.trace_trees,
            );
            const trace = try decodeTraceOpenings(
                allocator,
                bundle.decommitment,
                &logical.trace_trees,
                logical.fri_trees.len,
            );
            const fri_proof = try decodeFri(
                allocator,
                bundle,
                logical.fri_trees,
                protocol.log_last_layer_degree_bound,
            );
            return .{
                .config = .{
                    .pow_bits = protocol.pow_bits,
                    .fri_config = .{
                        .log_blowup_factor = protocol.log_blowup_factor,
                        .log_last_layer_degree_bound = protocol.log_last_layer_degree_bound,
                        .n_queries = protocol.n_queries,
                        .fold_step = protocol.fold_step,
                    },
                    .lifting_log_size = protocol.lifting_log_size,
                },
                .commitments = commitments,
                .sampled_values = samples,
                .decommitments = trace.decommitments,
                .queried_values = trace.queried_values,
                .proof_of_work = bundle.powNonce(),
                .fri_proof = fri_proof,
            };
        }
    };
}

const TraceProof = struct {
    decommitments: []proof_wire.MerkleDecommitmentWire,
    queried_values: [][][]u32,
};

fn decodeSamples(
    comptime Descriptor: type,
    allocator: std.mem.Allocator,
    words: []const u32,
    trace_trees: []const uniform_layout.TraceTree,
) ![][][]proof_wire.Qm31Wire {
    var sampled_value_count: usize = 0;
    for (trace_trees) |tree| {
        if (!tree.sampled) continue;
        for (0..tree.column_count) |column_index| {
            sampled_value_count = std.math.add(
                usize,
                sampled_value_count,
                try sampleCount(Descriptor, tree, column_index),
            ) catch return error.SizeOverflow;
        }
    }
    const sampled_words = std.math.mul(
        usize,
        sampled_value_count,
        stark_bundle.secure_words,
    ) catch return error.SizeOverflow;
    if (words.len != sampled_words)
        return error.InvalidSampleLayout;
    const trees = try allocator.alloc(
        [][]proof_wire.Qm31Wire,
        trace_trees.len,
    );
    for (trace_trees, 0..) |tree, index| {
        trees[index] = try allocator.alloc(
            []proof_wire.Qm31Wire,
            tree.column_count,
        );
    }
    var word_cursor: usize = 0;
    for (trace_trees, trees) |tree, columns| {
        for (columns, 0..) |*column, column_index| {
            const count = if (tree.sampled)
                try sampleCount(Descriptor, tree, column_index)
            else
                0;
            const word_count = std.math.mul(
                usize,
                count,
                stark_bundle.secure_words,
            ) catch return error.SizeOverflow;
            const end = std.math.add(
                usize,
                word_cursor,
                word_count,
            ) catch return error.SizeOverflow;
            if (end > words.len) return error.InvalidSampleLayout;
            column.* = try decodeSecureValues(
                allocator,
                words[word_cursor..end],
                count,
            );
            word_cursor = end;
        }
    }
    if (word_cursor != words.len) return error.InvalidSampleLayout;
    return trees;
}

fn sampleCount(
    comptime Descriptor: type,
    tree: uniform_layout.TraceTree,
    column_index: usize,
) !usize {
    const count = if (@hasDecl(Descriptor, "sampleCount"))
        try Descriptor.sampleCount(tree, column_index)
    else
        1;
    if (count == 0) return error.InvalidSampleLayout;
    return count;
}

fn decodeTraceOpenings(
    allocator: std.mem.Allocator,
    bundle: decommit_bundle.Bundle,
    trace_trees: []const uniform_layout.TraceTree,
    fri_tree_count: usize,
) !TraceProof {
    var opened_tree_count: usize = 0;
    for (trace_trees) |tree| {
        opened_tree_count += @intFromBool(tree.decommitted);
    }
    if (bundle.trees.len != opened_tree_count + fri_tree_count)
        return error.InvalidTraceOpening;
    const decommitments = try allocator.alloc(
        proof_wire.MerkleDecommitmentWire,
        trace_trees.len,
    );
    const queried_values = try allocator.alloc(
        [][]u32,
        trace_trees.len,
    );
    for (trace_trees, 0..) |_, role_index| {
        decommitments[role_index] = .{
            .hash_witness = try allocator.alloc(proof_wire.HashWire, 0),
        };
        queried_values[role_index] = try allocator.alloc([]u32, 0);
    }

    var opening_index: usize = 0;
    for (trace_trees, 0..) |trace_tree, role_index| {
        if (!trace_tree.decommitted) continue;
        if (trace_tree.column_count == 0)
            return error.InvalidTraceOpening;
        const tree = bundle.trees[opening_index];
        const values_count = std.math.mul(
            usize,
            trace_tree.column_count,
            tree.query_count,
        ) catch return error.SizeOverflow;
        if (tree.kind != .trace or
            tree.role != @intFromEnum(trace_tree.role) or
            tree.leaf_log_size != trace_tree.commitment_log_size or
            tree.query_count != bundle.unique_query_count or
            tree.values_count != values_count or
            tree.fri_witness_count != 0 or tree.all_values_count != 0)
        {
            return error.InvalidTraceOpening;
        }
        const queries = try bundle.section(tree.query_offset, tree.query_count);
        if (!std.mem.eql(u32, queries, bundle.uniqueQueries()))
            return error.InvalidTraceOpening;
        const values = try bundle.section(tree.values_offset, tree.values_count);
        queried_values[role_index] = try decodeQueriedColumns(
            allocator,
            values,
            trace_tree.column_count,
            queries,
            bundle.rawQueries(),
        );
        decommitments[role_index] = .{
            .hash_witness = try treeHashes(allocator, bundle, tree),
        };
        try validateMerkleArtifacts(bundle, tree, queries);
        opening_index += 1;
    }
    if (opening_index != opened_tree_count)
        return error.InvalidTraceOpening;
    return .{
        .decommitments = decommitments,
        .queried_values = queried_values,
    };
}

fn decodeQueriedColumns(
    allocator: std.mem.Allocator,
    values: []const u32,
    column_count: usize,
    unique_queries: []const u32,
    raw_queries: []const u32,
) ![][]u32 {
    for (raw_queries) |query| {
        if (findSorted(unique_queries, query) == null)
            return error.InvalidTraceOpening;
    }
    const columns = try allocator.alloc([]u32, column_count);
    for (columns, 0..) |*column, column_index| {
        column.* = try allocator.alloc(u32, unique_queries.len);
        const unique_values = values[column_index * unique_queries.len .. (column_index + 1) * unique_queries.len];
        for (unique_values, 0..) |value, unique_index| {
            try requireM31(value);
            column.*[unique_index] = value;
        }
    }
    return columns;
}

fn decodeFri(
    allocator: std.mem.Allocator,
    outer: stark_bundle.Bundle,
    fri_trees: []const uniform_layout.FriTree,
    last_layer_degree_log: u32,
) !proof_wire.FriProofWire {
    const roots = try decodeHashes(
        allocator,
        outer.friRoots(),
        fri_trees.len,
    );
    const layers = try allocator.alloc(
        proof_wire.FriLayerWire,
        fri_trees.len,
    );
    for (layers, fri_trees, 0..) |*layer, fri_tree, index| {
        layer.* = try decodeFriLayer(
            allocator,
            outer.decommitment,
            fri_tree,
            roots[index],
        );
    }
    return .{
        .first_layer = layers[0],
        .inner_layers = layers[1..],
        .last_layer_poly = try decodeSecureValues(
            allocator,
            outer.lastLayerPolynomial(),
            try pow2(last_layer_degree_log),
        ),
    };
}

fn decodeFriLayer(
    allocator: std.mem.Allocator,
    bundle: decommit_bundle.Bundle,
    fri_tree: uniform_layout.FriTree,
    commitment: proof_wire.HashWire,
) !proof_wire.FriLayerWire {
    if (fri_tree.tree_index >= bundle.trees.len or
        fri_tree.fold_step != 1 or
        fri_tree.log_rows_per_leaf != 0)
    {
        return error.InvalidFriOpening;
    }
    const tree = bundle.trees[fri_tree.tree_index];
    const expected_queries = try foldedQueries(
        allocator,
        bundle.uniqueQueries(),
        @intCast(fri_tree.cumulative_fold),
    );
    const queries = try bundle.section(tree.query_offset, tree.query_count);
    if (tree.kind != .fri or tree.role != fri_tree.tree_index or
        tree.leaf_log_size != fri_tree.evaluation_log_size or
        !std.mem.eql(u32, queries, expected_queries) or
        tree.values_count != 0)
    {
        return error.InvalidFriOpening;
    }
    const expanded = try expandedQueries(allocator, expected_queries);
    const all_words = try scaledSection(
        bundle,
        tree.all_values_offset,
        tree.all_values_count,
        decommit_bundle.indexed_secure_words,
    );
    if (tree.all_values_count != expanded.len)
        return error.InvalidFriOpening;
    const witness_words = try scaledSection(
        bundle,
        tree.fri_witness_offset,
        tree.fri_witness_count,
        stark_bundle.secure_words,
    );
    const witness = try decodeSecureValues(
        allocator,
        witness_words,
        tree.fri_witness_count,
    );
    var witness_index: usize = 0;
    for (expanded, 0..) |position, index| {
        const base = index * decommit_bundle.indexed_secure_words;
        if (all_words[base] != position) return error.InvalidFriOpening;
        const value_words = all_words[base + 1 .. base + decommit_bundle.indexed_secure_words];
        const value = try decodeSecureValue(value_words);
        if (findSorted(expected_queries, position) == null) {
            if (witness_index >= witness.len or
                !std.mem.eql(
                    u32,
                    &witness[witness_index],
                    &value,
                ))
            {
                return error.InvalidFriOpening;
            }
            witness_index += 1;
        }
    }
    if (witness_index != witness.len) return error.InvalidFriOpening;
    try validateMerkleArtifacts(bundle, tree, expanded);
    return .{
        .fri_witness = witness,
        .decommitment = .{
            .hash_witness = try treeHashes(allocator, bundle, tree),
        },
        .commitment = commitment,
    };
}

fn validateMerkleArtifacts(
    bundle: decommit_bundle.Bundle,
    tree: decommit_bundle.TreeMeta,
    queries: []const u32,
) !void {
    var current: [decommit_bundle.max_protocol_queries * 2]u32 = undefined;
    if (queries.len == 0 or queries.len > current.len)
        return error.InvalidMerkleArtifacts;
    @memcpy(current[0..queries.len], queries);
    var current_len = queries.len;
    var expected_hashes: usize = 0;
    var expected_aux: usize = 0;
    const aux = try scaledSection(
        bundle,
        tree.aux_offset,
        tree.aux_count,
        decommit_bundle.aux_node_words,
    );
    var aux_index: usize = 0;
    var level = tree.leaf_log_size;
    while (level != 0) : (level -= 1) {
        var read: usize = 0;
        var write: usize = 0;
        while (read < current_len) {
            const position = current[read];
            const paired = read + 1 < current_len and
                current[read + 1] == (position ^ 1);
            if (!paired) expected_hashes += 1;
            const parent = position >> 1;
            current[write] = parent;
            write += 1;
            for (0..2) |child| {
                if (aux_index >= tree.aux_count)
                    return error.InvalidMerkleArtifacts;
                const base = aux_index * decommit_bundle.aux_node_words;
                if (aux[base] != level or
                    aux[base + 1] != 2 * parent + child)
                {
                    return error.InvalidMerkleArtifacts;
                }
                aux_index += 1;
            }
            read += if (paired) 2 else 1;
        }
        current_len = write;
        expected_aux += 2 * write;
    }
    if (current_len != 1 or tree.hash_witness_count != expected_hashes or
        tree.aux_count != expected_aux or aux_index != tree.aux_count)
    {
        return error.InvalidMerkleArtifacts;
    }
}

fn treeHashes(
    allocator: std.mem.Allocator,
    bundle: decommit_bundle.Bundle,
    tree: decommit_bundle.TreeMeta,
) ![]proof_wire.HashWire {
    return decodeHashes(
        allocator,
        try scaledSection(
            bundle,
            tree.hash_witness_offset,
            tree.hash_witness_count,
            stark_bundle.hash_words,
        ),
        tree.hash_witness_count,
    );
}

fn decodeHashes(
    allocator: std.mem.Allocator,
    words: []const u32,
    count: usize,
) ![]proof_wire.HashWire {
    if (words.len != count * stark_bundle.hash_words)
        return error.InvalidCommitmentLayout;
    const hashes = try allocator.alloc(proof_wire.HashWire, count);
    for (hashes, 0..) |*hash, hash_index| {
        for (0..stark_bundle.hash_words) |word_index| {
            const value = words[hash_index * stark_bundle.hash_words + word_index];
            inline for (0..4) |byte_index| {
                hash[word_index * 4 + byte_index] =
                    @truncate(value >> (8 * byte_index));
            }
        }
    }
    return hashes;
}

fn decodeSecureValues(
    allocator: std.mem.Allocator,
    words: []const u32,
    count: usize,
) ![]proof_wire.Qm31Wire {
    if (words.len != count * stark_bundle.secure_words)
        return error.InvalidFieldElement;
    const values = try allocator.alloc(proof_wire.Qm31Wire, count);
    for (values, 0..) |*value, index| {
        value.* = try decodeSecureValue(
            words[index * stark_bundle.secure_words ..][0..stark_bundle.secure_words],
        );
    }
    return values;
}

fn decodeSecureValue(words: []const u32) !proof_wire.Qm31Wire {
    if (words.len != stark_bundle.secure_words)
        return error.InvalidFieldElement;
    var value: proof_wire.Qm31Wire = undefined;
    for (words, 0..) |word, index| {
        try requireM31(word);
        value[index] = word;
    }
    return value;
}

fn scaledSection(
    bundle: decommit_bundle.Bundle,
    offset: usize,
    count: usize,
    words_per_item: usize,
) ![]const u32 {
    const words = std.math.mul(usize, count, words_per_item) catch
        return error.SizeOverflow;
    return bundle.section(offset, words);
}

fn pow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn foldedQueries(
    allocator: std.mem.Allocator,
    queries: []const u32,
    folds: usize,
) ![]u32 {
    const output = try allocator.alloc(u32, queries.len);
    var count: usize = 0;
    for (queries) |query| {
        const folded = query >> @intCast(folds);
        if (count == 0 or output[count - 1] != folded) {
            output[count] = folded;
            count += 1;
        }
    }
    return output[0..count];
}

fn expandedQueries(
    allocator: std.mem.Allocator,
    queries: []const u32,
) ![]u32 {
    const output = try allocator.alloc(u32, queries.len * 2);
    var count: usize = 0;
    var previous_coset: ?u32 = null;
    for (queries) |query| {
        const coset = query >> 1;
        if (previous_coset != null and previous_coset.? == coset) continue;
        output[count] = 2 * coset;
        output[count + 1] = 2 * coset + 1;
        count += 2;
        previous_coset = coset;
    }
    return output[0..count];
}

fn findSorted(values: []const u32, needle: u32) ?usize {
    var low: usize = 0;
    var high = values.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (values[middle] < needle) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return if (low < values.len and values[low] == needle) low else null;
}

fn requireM31(value: u32) Error!void {
    if (value >= m31.Modulus) return error.InvalidFieldElement;
}

test "sample reconstruction follows role descriptors" {
    const trees = [_]uniform_layout.TraceTree{
        .{
            .role = .preprocessed,
            .column_count = 2,
            .column_log_size = 4,
            .commitment_log_size = 5,
            .sampled = true,
            .decommitted = true,
        },
        .{
            .role = .main,
            .column_count = 1,
            .column_log_size = 4,
            .commitment_log_size = 5,
            .sampled = true,
            .decommitted = true,
        },
        .{
            .role = .composition,
            .column_count = 8,
            .column_log_size = 4,
            .commitment_log_size = 5,
            .sampled = true,
            .decommitted = true,
        },
    };
    var words: [11 * stark_bundle.secure_words]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = @intCast(index + 1);
    const sampled = try decodeSamples(
        std.testing.allocator,
        &words,
        trees,
    );
    defer {
        for (sampled) |columns| {
            for (columns) |column_values| {
                std.testing.allocator.free(column_values);
            }
            std.testing.allocator.free(columns);
        }
        std.testing.allocator.free(sampled);
    }
    try std.testing.expectEqual(@as(usize, 2), sampled[0].len);
    try std.testing.expectEqual(@as(usize, 1), sampled[1].len);
    try std.testing.expectEqual(@as(usize, 8), sampled[2].len);
    try std.testing.expectEqual(@as(u32, 1), sampled[0][0][0][0]);
    try std.testing.expectEqual(@as(u32, 5), sampled[0][1][0][0]);
    try std.testing.expectEqual(@as(u32, 9), sampled[1][0][0][0]);
    try std.testing.expectEqual(@as(u32, 13), sampled[2][0][0][0]);
    try std.testing.expectEqual(@as(u32, 37), sampled[2][6][0][0]);
}

test "sample reconstruction preserves unsampled tree columns" {
    const trees = [_]uniform_layout.TraceTree{
        .{
            .role = .preprocessed,
            .column_count = 1,
            .column_log_size = 4,
            .commitment_log_size = 5,
            .sampled = false,
            .decommitted = true,
        },
        .{
            .role = .main,
            .column_count = 2,
            .column_log_size = 4,
            .commitment_log_size = 5,
            .sampled = true,
            .decommitted = true,
        },
        .{
            .role = .composition,
            .column_count = 8,
            .column_log_size = 4,
            .commitment_log_size = 5,
            .sampled = true,
            .decommitted = true,
        },
    };
    var words: [10 * stark_bundle.secure_words]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = @intCast(index + 1);
    const sampled = try decodeSamples(
        std.testing.allocator,
        &words,
        trees,
    );
    defer {
        for (sampled) |columns| {
            for (columns) |column_values| {
                std.testing.allocator.free(column_values);
            }
            std.testing.allocator.free(columns);
        }
        std.testing.allocator.free(sampled);
    }

    try std.testing.expectEqual(@as(usize, 1), sampled[0].len);
    try std.testing.expectEqual(@as(usize, 0), sampled[0][0].len);
    try std.testing.expectEqual(@as(usize, 2), sampled[1].len);
    try std.testing.expectEqual(@as(usize, 8), sampled[2].len);
    try std.testing.expectEqual(@as(u32, 1), sampled[1][0][0][0]);
    try std.testing.expectEqual(@as(u32, 9), sampled[2][0][0][0]);
}
