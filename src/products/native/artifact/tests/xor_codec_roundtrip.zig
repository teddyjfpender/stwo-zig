//! Native XOR integration coverage for the shared proof codecs.

const std = @import("std");
const core = @import("stwo_core");
const fri = core.fri;
const pcs = core.pcs;
const xor = @import("stwo_native_examples").xor;
const postcard = @import("interop_postcard");
const proof_wire = @import("stwo_proof_wire");

fn config() !pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn statement() xor.Statement {
    return .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    };
}

test "postcard proof serialize and deserialize roundtrip" {
    const allocator = std.testing.allocator;
    const pcs_config = try config();
    var output = try xor.prove(allocator, pcs_config, statement());
    defer output.proof.deinit(allocator);

    var encoded = std.ArrayList(u8).empty;
    defer encoded.deinit(allocator);
    try postcard.serializeProof(
        proof_wire.Hasher,
        encoded.writer(allocator),
        output.proof,
    );

    var input = std.io.fixedBufferStream(@as([]const u8, encoded.items));
    const decoded = try postcard.deserializeProof(
        proof_wire.Hasher,
        allocator,
        input.reader(),
    );

    var reencoded = std.ArrayList(u8).empty;
    defer reencoded.deinit(allocator);
    try postcard.serializeProof(
        proof_wire.Hasher,
        reencoded.writer(allocator),
        decoded,
    );
    try std.testing.expectEqualSlices(u8, encoded.items, reencoded.items);
    try xor.verify(allocator, pcs_config, output.statement, decoded);
}

test "JSON proof wire roundtrip verifies" {
    const allocator = std.testing.allocator;
    const pcs_config = try config();
    var output = try xor.prove(allocator, pcs_config, statement());
    defer output.proof.deinit(allocator);
    const encoded = try proof_wire.encodeProofBytes(allocator, output.proof);
    defer allocator.free(encoded);

    const decoded = try proof_wire.decodeProofBytes(allocator, encoded);
    try xor.verify(allocator, pcs_config, output.statement, decoded);
}

test "binary proof wire roundtrip verifies" {
    const allocator = std.testing.allocator;
    const pcs_config = try config();
    var output = try xor.prove(allocator, pcs_config, statement());
    defer output.proof.deinit(allocator);
    const encoded = try proof_wire.encodeProofBytesBinary(allocator, output.proof);
    defer allocator.free(encoded);

    const decoded = try proof_wire.decodeProofBytesBinary(allocator, encoded);
    try xor.verify(allocator, pcs_config, output.statement, decoded);
}

test "binary and JSON proof wire codecs are proof-equivalent" {
    const allocator = std.testing.allocator;
    const pcs_config = try config();
    var output = try xor.prove(allocator, pcs_config, statement());
    defer output.proof.deinit(allocator);

    const json_bytes = try proof_wire.encodeProofBytes(allocator, output.proof);
    defer allocator.free(json_bytes);
    const binary_bytes = try proof_wire.encodeProofBytesBinary(allocator, output.proof);
    defer allocator.free(binary_bytes);

    var decoded = try proof_wire.decodeProofBytesBinary(allocator, binary_bytes);
    defer decoded.deinit(allocator);
    const reencoded = try proof_wire.encodeProofBytes(allocator, decoded);
    defer allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, json_bytes, reencoded);
}
