//! Wire formats of StarkWare's circuit recursion stage
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), byte-identical to the Rust
//! producers. See README.md for the format map.

const std = @import("std");

/// `CircuitSerialize`: binary circuit proofs, sized by a `ProofConfig`.
pub const circuit_serialize = @import("circuit_serialize.zig");
/// `stwo-cairo-serialize` felt primitives, the felt JSON text and the
/// verifier's queried-value layout: the CairoSerde transport
/// (`src/interop/felt_json.zig`) the Cairo frontend's `proof.cairo_serde`
/// shares, injected as `interop_felt_json`.
pub const cairo_serialize = @import("interop_felt_json");
/// The root `CairoCircuitProof` felt stream and its query-value layout.
pub const circuit_felt_stream = @import("circuit_felt_stream.zig");
/// `SerializedLeafProof`, `DigestHex`, `LeafInput`, the leaves manifest.
pub const leaf_proof_json = @import("leaf_proof_json.zig");
/// `PackedNode` and the root output digest file.
pub const packed_node = @import("packed_node.zig");
/// The circuit registry JSON and its queries.
pub const registry = @import("registry.zig");
/// `RegistryDefinition`: the input of `circuit-params`.
pub const registry_definition = @import("registry_definition.zig");
/// The inputs of `verify_circuit` besides the proof (`verify-circuit --request`).
pub const verify_request = @import("verify_request.zig");
/// Leaf output digests from decimal felt preimages.
pub const blake2_felt252 = @import("blake2_felt252.zig");
/// The serde_json text surface shared by the JSON formats.
pub const json_text = @import("json_text.zig");

fn expectParams(comptime function: anytype, comptime params: []const type) !void {
    const info = @typeInfo(@TypeOf(function)).@"fn";
    try std.testing.expectEqual(params.len, info.params.len);
    inline for (params, info.params) |want, got| try std.testing.expect(want == got.type.?);
}

test "api signature: circuit recursion wire formats expose their codecs" {
    const Allocator = std.mem.Allocator;
    const Writer = *std.Io.Writer;
    const Config = circuit_serialize.ProofConfig;
    try expectParams(circuit_serialize.deserializeProof, &.{ Allocator, []const u8, Config });
    try expectParams(circuit_serialize.serializeProof, &.{ Writer, *const circuit_serialize.Proof, Config });
    try expectParams(cairo_serialize.parseFeltJson, &.{ Allocator, []const u8 });
    try expectParams(circuit_felt_stream.decode, &.{ Allocator, []const u64 });
    try expectParams(circuit_felt_stream.writeJson, &.{ Writer, *const circuit_felt_stream.CairoCircuitProof });
    try expectParams(registry.parseRegistry, &.{ Allocator, []const u8 });
    try expectParams(registry.writeRegistry, &.{ Writer, registry.CircuitRegistry });
    try expectParams(registry.parseProverParameters, &.{ Allocator, []const u8 });
    try expectParams(registry.parseFriConfig, &.{ Allocator, []const u8 });
    try expectParams(registry_definition.parseRegistryDefinition, &.{ Allocator, []const u8 });
    try expectParams(leaf_proof_json.parseLeafInput, &.{ Allocator, []const u8 });
    try expectParams(leaf_proof_json.writeLeafInput, &.{ Writer, leaf_proof_json.LeafInput });
    try expectParams(packed_node.parsePackedNode, &.{ Allocator, []const u8 });
    try expectParams(packed_node.writePackedNode, &.{ Writer, packed_node.PackedNode });
}

test {
    std.testing.refAllDecls(@This());
}
