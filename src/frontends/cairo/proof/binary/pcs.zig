//! Official bincode layout for the Stwo commitment scheme proof.

const std = @import("std");
const binary = @import("writer.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn write(output: anytype, proof: anytype) !void {
    try writeConfig(output, proof);
    try writeHashes(output, proof.commitments.items);
    try writeQm31Trees(output, proof.sampled_values.items);
    try writeDecommitments(output, proof.decommitments.items);
    try writeM31Trees(output, proof.queried_values.items);
    try binary.int(output, u64, proof.proof_of_work);
    try writeFriProof(output, proof.fri_proof);
}

/// `PcsConfig`. The existing lane's (stwo 7b211ed) ends in its optional fork
/// lifting word; a `proving_5a7c5ed` proof (`revision_config`) carries the
/// same FRI prefix, PoW bits first, then both explicit lifting heights.
fn writeConfig(output: anytype, proof: anytype) !void {
    if (proof.revision_config) |config| {
        const fri = config.fri_config;
        try binary.int(output, u32, fri.pow_bits);
        try binary.int(output, u32, fri.log_blowup_factor);
        try binary.int(output, u32, fri.log_last_layer_degree_bound);
        try binary.length(output, fri.n_queries);
        try binary.int(output, u32, fri.fold_step);
        try binary.int(output, u32, config.trace_lifting_log_size);
        try binary.int(output, u32, config.preprocessed_lifting_log_size);
        return;
    }
    try binary.int(output, u32, proof.config.pow_bits);
    try binary.int(output, u32, proof.config.fri_config.log_blowup_factor);
    try binary.int(
        output,
        u32,
        proof.config.fri_config.log_last_layer_degree_bound,
    );
    try binary.length(output, proof.config.fri_config.n_queries);
    try binary.int(output, u32, proof.config.fri_config.fold_step);
    try binary.int(output, u32, proof.config.lifting_log_size orelse 0);
}

/// `CommitmentSchemeProofAux`, the auxiliary half of `ExtendedStarkProof`.
///
/// Upstream's maps are `hashbrown::HashMap`s, which bincode writes as a length
/// and then `(key, value)` pairs in iteration order; that order depends on a
/// per-process random seed, so upstream's own bytes are not reproducible. Every
/// map here is written in ascending key order, the canonical encoding the R10
/// oracle (`stwo-circuit-oracle prove-cairo`) also emits; lengths and entries
/// are upstream's. Duplicate keys are not a map and are refused.
pub fn writeAux(allocator: std.mem.Allocator, output: anytype, aux: anytype) !void {
    try binary.length(output, aux.unsorted_query_locations.len);
    for (aux.unsorted_query_locations) |location| try binary.length(output, location);
    try binary.length(output, aux.trace_decommitment.items.len);
    for (aux.trace_decommitment.items) |tree| try writeMerkleAux(allocator, output, tree);
    try writeFriLayerAux(allocator, output, aux.fri.first_layer);
    try binary.length(output, aux.fri.inner_layers.len);
    for (aux.fri.inner_layers) |layer| try writeFriLayerAux(allocator, output, layer);
}

fn writeMerkleAux(allocator: std.mem.Allocator, output: anytype, aux: anytype) !void {
    try binary.length(output, aux.all_node_values.len);
    for (aux.all_node_values) |layer| {
        const sorted = try sortedByIndex(allocator, @TypeOf(layer[0]), layer);
        defer allocator.free(sorted);
        try binary.length(output, sorted.len);
        for (sorted) |node| {
            try binary.length(output, node.index);
            try output.writeAll(&node.hash);
        }
    }
}

fn writeFriLayerAux(allocator: std.mem.Allocator, output: anytype, aux: anytype) !void {
    try binary.length(output, aux.all_values.len);
    for (aux.all_values) |layer| {
        const sorted = try sortedByIndex(allocator, @TypeOf(layer[0]), layer);
        defer allocator.free(sorted);
        try binary.length(output, sorted.len);
        for (sorted) |entry| {
            try binary.length(output, entry.index);
            for (entry.value.toM31Array()) |coordinate| try binary.int(output, u32, coordinate.toU32());
        }
    }
    try writeMerkleAux(allocator, output, aux.decommitment);
}

fn sortedByIndex(allocator: std.mem.Allocator, comptime Entry: type, entries: []const Entry) ![]Entry {
    const sorted = try allocator.dupe(Entry, entries);
    errdefer allocator.free(sorted);
    std.mem.sort(Entry, sorted, {}, struct {
        fn lessThan(_: void, a: Entry, b: Entry) bool {
            return a.index < b.index;
        }
    }.lessThan);
    if (sorted.len > 1) for (sorted[1..], sorted[0 .. sorted.len - 1]) |current, previous| {
        if (current.index == previous.index) return error.DuplicateAuxIndex;
    };
    return sorted;
}

fn writeHashes(output: anytype, hashes: anytype) !void {
    try binary.length(output, hashes.len);
    for (hashes) |hash| try output.writeAll(&hash);
}

fn writeQm31Trees(output: anytype, trees: anytype) !void {
    try binary.length(output, trees.len);
    for (trees) |columns| {
        try binary.length(output, columns.len);
        for (columns) |column| try writeQm31Slice(output, column);
    }
}

fn writeM31Trees(output: anytype, trees: anytype) !void {
    try binary.length(output, trees.len);
    for (trees) |columns| {
        try binary.length(output, columns.len);
        for (columns) |column| try writeM31Slice(output, column);
    }
}

fn writeDecommitments(output: anytype, decommitments: anytype) !void {
    try binary.length(output, decommitments.len);
    for (decommitments) |decommitment|
        try writeHashes(output, decommitment.hash_witness);
}

fn writeFriProof(output: anytype, proof: anytype) !void {
    try writeFriLayer(output, proof.first_layer);
    try binary.length(output, proof.inner_layers.len);
    for (proof.inner_layers) |layer| try writeFriLayer(output, layer);

    const coefficients = proof.last_layer_poly.coefficients();
    if (coefficients.len == 0 or !std.math.isPowerOfTwo(coefficients.len))
        return error.InvalidLastLayerPolynomial;
    try writeQm31Slice(output, coefficients);
    try binary.int(
        output,
        u32,
        std.math.log2_int(usize, coefficients.len),
    );
}

fn writeFriLayer(output: anytype, layer: anytype) !void {
    try writeQm31Slice(output, layer.fri_witness);
    try writeHashes(output, layer.decommitment.hash_witness);
    try output.writeAll(&layer.commitment);
}

fn writeQm31Slice(output: anytype, values: []const QM31) !void {
    try binary.length(output, values.len);
    for (values) |value|
        for (value.toM31Array()) |coordinate|
            try binary.int(output, u32, coordinate.toU32());
}

fn writeM31Slice(output: anytype, values: []const M31) !void {
    try binary.length(output, values.len);
    for (values) |value| try binary.int(output, u32, value.toU32());
}
