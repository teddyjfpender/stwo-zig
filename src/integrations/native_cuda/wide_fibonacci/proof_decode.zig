//! Canonical host reconstruction from the sole resident SWPC result.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const proof_wire = @import("../../../interop/proof_wire.zig");
const decommit_bundle =
    @import("../../../backends/cuda/runtime/proof_assembly/decommit_bundle.zig");
const stark_bundle =
    @import("../../../backends/cuda/runtime/proof_assembly/stark_bundle.zig");
const request_mod = @import("request.zig");

pub const Error = error{
    InvalidCommitmentLayout,
    InvalidFieldElement,
    InvalidFriOpening,
    InvalidMerkleArtifacts,
    InvalidSampleLayout,
    InvalidTraceOpening,
    SizeOverflow,
};

/// Owns every slice reachable from `value`.
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

/// Produces an independently owned canonical `StarkProof`.
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
    const geometry = try request_mod.admit(.{
        .statement = .{
            .log_n_rows = protocol.log_n_rows,
            .sequence_len = protocol.sequence_len,
        },
        .protocol = .{
            .pow_bits = protocol.pow_bits,
            .log_blowup_factor = protocol.log_blowup_factor,
            .log_last_layer_degree_bound = protocol.log_last_layer_degree_bound,
            .n_queries = protocol.n_queries,
            .fold_step = protocol.fold_step,
            .lifting_log_size = protocol.lifting_log_size,
        },
    });
    if (protocol.commitment_root_count != geometry.committed_tree_count or
        protocol.fri_root_count != geometry.fri_tree_count or
        protocol.decommit_tree_count != geometry.decommit_tree_count)
    {
        return error.InvalidCommitmentLayout;
    }

    const commitments = try decodeHashes(
        allocator,
        bundle.commitmentRoots(),
        geometry.committed_tree_count,
    );
    const samples = try decodeSamples(
        allocator,
        bundle.sampledValues(),
        geometry,
    );
    const trace = try decodeTraceOpenings(
        allocator,
        bundle.decommitment,
        geometry,
    );
    const fri_proof = try decodeFri(
        allocator,
        bundle,
        geometry,
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

const TraceProof = struct {
    decommitments: []proof_wire.MerkleDecommitmentWire,
    queried_values: [][][]u32,
};

fn decodeSamples(
    allocator: std.mem.Allocator,
    words: []const u32,
    geometry: request_mod.Geometry,
) ![][][]proof_wire.Qm31Wire {
    if (words.len != geometry.sampled_value_count * stark_bundle.secure_words)
        return error.InvalidSampleLayout;
    const values = try decodeSecureValues(
        allocator,
        words,
        geometry.sampled_value_count,
    );
    const trees = try allocator.alloc([][]proof_wire.Qm31Wire, 3);
    trees[0] = try allocator.alloc([]proof_wire.Qm31Wire, 0);
    trees[1] = try singletonColumns(
        allocator,
        values[0..geometry.main_columns],
    );
    trees[2] = try singletonColumns(
        allocator,
        values[geometry.main_columns..],
    );
    return trees;
}

fn singletonColumns(
    allocator: std.mem.Allocator,
    values: []const proof_wire.Qm31Wire,
) ![][]proof_wire.Qm31Wire {
    const columns = try allocator.alloc([]proof_wire.Qm31Wire, values.len);
    for (columns, values) |*column, value| {
        column.* = try allocator.dupe(proof_wire.Qm31Wire, &.{value});
    }
    return columns;
}

fn decodeTraceOpenings(
    allocator: std.mem.Allocator,
    bundle: decommit_bundle.Bundle,
    geometry: request_mod.Geometry,
) !TraceProof {
    if (bundle.trees.len != geometry.decommit_tree_count)
        return error.InvalidTraceOpening;
    const decommitments = try allocator.alloc(
        proof_wire.MerkleDecommitmentWire,
        3,
    );
    const queried_values = try allocator.alloc([][]u32, 3);
    decommitments[0] = .{
        .hash_witness = try allocator.alloc(proof_wire.HashWire, 0),
    };
    queried_values[0] = try allocator.alloc([]u32, 0);

    const column_counts = [_]usize{
        geometry.main_columns,
        request_mod.composition_column_count,
    };
    for (column_counts, 0..) |column_count, tree_index| {
        const tree = bundle.trees[tree_index];
        if (tree.kind != .trace or tree.role != tree_index + 1 or
            tree.leaf_log_size != geometry.queryLogSize() or
            tree.query_count != bundle.unique_query_count or
            tree.values_count != column_count * tree.query_count or
            tree.fri_witness_count != 0 or tree.all_values_count != 0)
        {
            return error.InvalidTraceOpening;
        }
        const queries = try bundle.section(tree.query_offset, tree.query_count);
        if (!std.mem.eql(u32, queries, bundle.uniqueQueries()))
            return error.InvalidTraceOpening;
        const values = try bundle.section(tree.values_offset, tree.values_count);
        queried_values[tree_index + 1] = try decodeQueriedColumns(
            allocator,
            values,
            column_count,
            queries,
            bundle.rawQueries(),
        );
        decommitments[tree_index + 1] = .{
            .hash_witness = try treeHashes(allocator, bundle, tree),
        };
        try validateMerkleArtifacts(bundle, tree, queries);
    }
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
    geometry: request_mod.Geometry,
) !proof_wire.FriProofWire {
    const roots = try decodeHashes(
        allocator,
        outer.friRoots(),
        geometry.fri_tree_count,
    );
    const layers = try allocator.alloc(
        proof_wire.FriLayerWire,
        geometry.fri_tree_count,
    );
    for (layers, 0..) |*layer, index| {
        layer.* = try decodeFriLayer(
            allocator,
            outer.decommitment,
            2 + index,
            index,
            geometry,
            roots[index],
        );
    }
    return .{
        .first_layer = layers[0],
        .inner_layers = layers[1..],
        .last_layer_poly = try decodeSecureValues(
            allocator,
            outer.lastLayerPolynomial(),
            geometry.last_layer_domain_rows /
                (@as(usize, 1) << @intCast(
                    geometry.protocol.log_blowup_factor,
                )),
        ),
    };
}

fn decodeFriLayer(
    allocator: std.mem.Allocator,
    bundle: decommit_bundle.Bundle,
    tree_index: usize,
    layer_index: usize,
    geometry: request_mod.Geometry,
    commitment: proof_wire.HashWire,
) !proof_wire.FriLayerWire {
    const tree = bundle.trees[tree_index];
    const expected_queries = try foldedQueries(
        allocator,
        bundle.uniqueQueries(),
        layer_index,
    );
    const queries = try bundle.section(tree.query_offset, tree.query_count);
    if (tree.kind != .fri or tree.role != tree_index or
        tree.leaf_log_size != geometry.queryLogSize() - layer_index or
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
