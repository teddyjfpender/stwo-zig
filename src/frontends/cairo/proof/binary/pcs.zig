//! Official bincode layout for the Stwo commitment scheme proof.

const std = @import("std");
const binary = @import("writer.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn write(output: anytype, proof: anytype) !void {
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

    try writeHashes(output, proof.commitments.items);
    try writeQm31Trees(output, proof.sampled_values.items);
    try writeDecommitments(output, proof.decommitments.items);
    try writeM31Trees(output, proof.queried_values.items);
    try binary.int(output, u64, proof.proof_of_work);
    try writeFriProof(output, proof.fri_proof);
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
