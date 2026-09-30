//! Cairo serialization of the Stwo commitment scheme proof
//! (`CairoSerialize for CommitmentSchemeProof`), on the shared CairoSerde
//! primitives of `interop_felt_json` (`FeltWriter`), which also encode the
//! circuit-recursion root proof.

const std = @import("std");
const composition = @import("../../witness/composition_bundle.zig");
const felt_json = @import("interop_felt_json");
const queries = @import("queries.zig");

/// A `FeltWriter` sink over the streaming felt JSON writer.
pub fn Sink(comptime Writer: type) type {
    return struct {
        writer: Writer,
        state: *felt_json.State,

        pub fn felt(self: @This(), value: u64) !void {
            try felt_json.write(self.writer, self.state, value);
        }
    };
}

pub fn write(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *felt_json.State,
    proof: anytype,
    bundle: *const composition.Bundle,
) !void {
    const lifting = proof.config.lifting_log_size orelse 0;
    if (lifting != 0) return error.UnsupportedCairoSerdeLifting;
    var felts: felt_json.FeltWriter(Sink(@TypeOf(writer))) = .{ .sink = .{ .writer = writer, .state = state } };
    try felts.friConfig(.{
        .pow_bits = proof.config.pow_bits,
        .log_blowup_factor = proof.config.fri_config.log_blowup_factor,
        .log_last_layer_degree_bound = proof.config.fri_config.log_last_layer_degree_bound,
        .n_queries = std.math.cast(u32, proof.config.fri_config.n_queries) orelse return error.QueriedValueCountOverflow,
        .fold_step = proof.config.fri_config.fold_step,
    });

    try felts.hashVec(proof.commitments.items);
    const sampled_values = proof.sampled_values.items;
    try felts.felt(sampled_values.len);
    for (sampled_values) |columns| {
        try felts.felt(columns.len);
        for (columns) |column| try felts.qm31Vec(column);
    }
    try felts.felt(proof.decommitments.items.len);
    for (proof.decommitments.items) |decommitment| try felts.hashVec(decommitment.hash_witness);
    try queries.write(allocator, &felts, proof.queried_values, bundle);
    try felts.felt(proof.proof_of_work);
    try writeFriProof(&felts, proof.fri_proof);
}

fn writeFriProof(felts: anytype, proof: anytype) !void {
    try writeFriLayer(felts, proof.first_layer);
    try felts.felt(proof.inner_layers.len);
    for (proof.inner_layers) |layer| try writeFriLayer(felts, layer);
    try felts.linePoly(proof.last_layer_poly.coefficients());
}

fn writeFriLayer(felts: anytype, layer: anytype) !void {
    try felts.qm31Vec(layer.fri_witness);
    try felts.hashVec(layer.decommitment.hash_witness);
    try felts.blake2sHash(&layer.commitment);
}
