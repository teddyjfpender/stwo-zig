//! Cairo serialization of the Stwo commitment scheme proof.

const std = @import("std");
const composition = @import("../../witness/composition_bundle.zig");
const felt_json = @import("felt_json.zig");
const queries = @import("queries.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn write(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *felt_json.State,
    proof: anytype,
    bundle: *const composition.Bundle,
) !void {
    const lifting = proof.config.lifting_log_size orelse 0;
    if (lifting != 0) return error.UnsupportedCairoSerdeLifting;
    try felt_json.write(writer, state, proof.config.pow_bits);
    try felt_json.write(writer, state, proof.config.fri_config.log_blowup_factor);
    try felt_json.write(
        writer,
        state,
        proof.config.fri_config.log_last_layer_degree_bound,
    );
    try felt_json.write(writer, state, proof.config.fri_config.n_queries);
    try felt_json.write(writer, state, proof.config.fri_config.fold_step);

    try writeHashes(writer, state, proof.commitments.items);
    try writeSampledValues(writer, state, proof.sampled_values.items);
    try writeDecommitments(writer, state, proof.decommitments.items);
    try queries.write(
        allocator,
        writer,
        state,
        proof.queried_values,
        bundle,
    );
    try felt_json.write(writer, state, proof.proof_of_work);
    try writeFriProof(writer, state, proof.fri_proof);
}

fn writeHashes(writer: anytype, state: *felt_json.State, hashes: anytype) !void {
    try felt_json.write(writer, state, hashes.len);
    for (hashes) |hash| try writeHash(writer, state, hash);
}

fn writeSampledValues(
    writer: anytype,
    state: *felt_json.State,
    trees: anytype,
) !void {
    try felt_json.write(writer, state, trees.len);
    for (trees) |columns| {
        try felt_json.write(writer, state, columns.len);
        for (columns) |column| try writeQm31Slice(writer, state, column);
    }
}

fn writeDecommitments(
    writer: anytype,
    state: *felt_json.State,
    decommitments: anytype,
) !void {
    try felt_json.write(writer, state, decommitments.len);
    for (decommitments) |decommitment|
        try writeHashes(writer, state, decommitment.hash_witness);
}

fn writeFriProof(writer: anytype, state: *felt_json.State, proof: anytype) !void {
    try writeFriLayer(writer, state, proof.first_layer);
    try felt_json.write(writer, state, proof.inner_layers.len);
    for (proof.inner_layers) |layer| try writeFriLayer(writer, state, layer);

    const coefficients = proof.last_layer_poly.coefficients();
    if (coefficients.len == 0 or !std.math.isPowerOfTwo(coefficients.len))
        return error.InvalidLastLayerPolynomial;
    try writeQm31Slice(writer, state, coefficients);
    try felt_json.write(
        writer,
        state,
        std.math.log2_int(usize, coefficients.len),
    );
}

fn writeFriLayer(writer: anytype, state: *felt_json.State, layer: anytype) !void {
    try writeQm31Slice(writer, state, layer.fri_witness);
    try writeHashes(writer, state, layer.decommitment.hash_witness);
    try writeHash(writer, state, layer.commitment);
}

fn writeQm31Slice(
    writer: anytype,
    state: *felt_json.State,
    values: []const QM31,
) !void {
    try felt_json.write(writer, state, values.len);
    for (values) |value| {
        for (value.toM31Array()) |coordinate|
            try felt_json.write(writer, state, coordinate.toU32());
    }
}

fn writeHash(writer: anytype, state: *felt_json.State, hash: [32]u8) !void {
    var offset: usize = 0;
    while (offset < hash.len) : (offset += 4) {
        try felt_json.write(
            writer,
            state,
            std.mem.readInt(u32, hash[offset..][0..4], .little),
        );
    }
}
