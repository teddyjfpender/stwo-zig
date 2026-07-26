//! Serde-compatible JSON encoding for current upstream Stwo proofs.
//!
//! This module writes directly to an `std.json.Stringify` writer so large
//! proofs do not require a second, equally large in-memory wire model.

const std = @import("std");
const core = @import("stwo_core");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub fn ProofView(comptime Proof: type) type {
    return struct {
        proof: *const Proof,

        pub fn jsonStringify(self: @This(), writer: anytype) !void {
            try writeStarkProof(writer, self.proof);
        }
    };
}

pub fn writeStarkProof(writer: anytype, stark_proof: anytype) !void {
    const proof = stark_proof.commitment_scheme_proof;
    try writer.beginObject();

    try writer.objectField("config");
    try writeConfig(writer, proof.config);

    try writer.objectField("commitments");
    try writer.write(proof.commitments.items);

    try writer.objectField("sampled_values");
    try writeQm31Tree(writer, proof.sampled_values.items);

    try writer.objectField("decommitments");
    try writeDecommitments(writer, proof.decommitments.items);

    try writer.objectField("queried_values");
    try writeM31Tree(writer, proof.queried_values.items);

    try writer.objectField("proof_of_work");
    try writer.write(proof.proof_of_work);

    try writer.objectField("fri_proof");
    try writeFriProof(writer, proof.fri_proof);

    try writer.endObject();
}

pub fn writeQm31(writer: anytype, value: QM31) !void {
    try writer.beginArray();
    try writeCm31(writer, value.c0.a, value.c0.b);
    try writeCm31(writer, value.c1.a, value.c1.b);
    try writer.endArray();
}

fn writeCm31(writer: anytype, real: M31, imaginary: M31) !void {
    try writer.beginArray();
    try writer.write(real.toU32());
    try writer.write(imaginary.toU32());
    try writer.endArray();
}

fn writeConfig(writer: anytype, config: anytype) !void {
    try writer.beginObject();
    try writer.objectField("pow_bits");
    try writer.write(config.pow_bits);
    try writer.objectField("fri_config");
    try writer.beginObject();
    try writer.objectField("log_blowup_factor");
    try writer.write(config.fri_config.log_blowup_factor);
    try writer.objectField("log_last_layer_degree_bound");
    try writer.write(config.fri_config.log_last_layer_degree_bound);
    try writer.objectField("n_queries");
    try writer.write(config.fri_config.n_queries);
    try writer.objectField("fold_step");
    try writer.write(config.fri_config.fold_step);
    try writer.endObject();
    try writer.objectField("min_lifting_log_size");
    try writer.write(config.lifting_log_size orelse 0);
    try writer.endObject();
}

fn writeQm31Tree(writer: anytype, trees: anytype) !void {
    try writer.beginArray();
    for (trees) |columns| {
        try writer.beginArray();
        for (columns) |column| {
            try writer.beginArray();
            for (column) |value| try writeQm31(writer, value);
            try writer.endArray();
        }
        try writer.endArray();
    }
    try writer.endArray();
}

fn writeM31Tree(writer: anytype, trees: anytype) !void {
    try writer.beginArray();
    for (trees) |columns| {
        try writer.beginArray();
        for (columns) |column| {
            try writer.beginArray();
            for (column) |value| try writer.write(value.toU32());
            try writer.endArray();
        }
        try writer.endArray();
    }
    try writer.endArray();
}

fn writeDecommitments(writer: anytype, decommitments: anytype) !void {
    try writer.beginArray();
    for (decommitments) |decommitment| try writeDecommitment(writer, decommitment);
    try writer.endArray();
}

fn writeDecommitment(writer: anytype, decommitment: anytype) !void {
    try writer.beginObject();
    try writer.objectField("hash_witness");
    try writer.write(decommitment.hash_witness);
    try writer.endObject();
}

fn writeFriProof(writer: anytype, proof: anytype) !void {
    try writer.beginObject();
    try writer.objectField("first_layer");
    try writeFriLayer(writer, proof.first_layer);
    try writer.objectField("inner_layers");
    try writer.beginArray();
    for (proof.inner_layers) |layer| try writeFriLayer(writer, layer);
    try writer.endArray();
    try writer.objectField("last_layer_poly");
    try writer.beginObject();
    try writer.objectField("coeffs");
    try writer.beginArray();
    for (proof.last_layer_poly.coefficients()) |coefficient|
        try writeQm31(writer, coefficient);
    try writer.endArray();
    try writer.objectField("log_size");
    try writer.write(std.math.log2_int(usize, proof.last_layer_poly.len()));
    try writer.endObject();
    try writer.endObject();
}

fn writeFriLayer(writer: anytype, layer: anytype) !void {
    try writer.beginObject();
    try writer.objectField("fri_witness");
    try writer.beginArray();
    for (layer.fri_witness) |value| try writeQm31(writer, value);
    try writer.endArray();
    try writer.objectField("decommitment");
    try writeDecommitment(writer, layer.decommitment);
    try writer.objectField("commitment");
    try writer.write(layer.commitment);
    try writer.endObject();
}

test "Stwo JSON: QM31 follows Rust nested extension-field shape" {
    var encoded: [128]u8 = undefined;
    var output = std.Io.Writer.fixed(&encoded);
    const Value = struct {
        value: QM31,

        pub fn jsonStringify(self: @This(), writer: anytype) !void {
            try writeQm31(writer, self.value);
        }
    };
    try std.json.Stringify.value(
        Value{ .value = QM31.fromU32Unchecked(1, 2, 3, 4) },
        .{},
        &output,
    );
    try std.testing.expectEqualStrings("[[1,2],[3,4]]", output.buffered());
}
