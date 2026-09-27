//! Bounded serialized proof inputs. Wrapper claims have no authority until the
//! receiving STARK verifier mixes and verifies them under the pinned seal.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const bus = @import("block_memory_relation_v2.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");
const execution_wire = @import("block_execution_batch_receiver_v2.zig");
const external = @import("block_execution_external_batch_v2.zig");

pub const MAX_STARK_BYTES: usize = 64 * 1024 * 1024;
pub const SerializedMemoryProof = struct {
    stark_bytes: []const u8,
    interaction_claim: bus.ComponentClaim,
    range_claims: range.Claims,
};
pub const SerializedTableProof = struct { stark_bytes: []const u8, claim: core.fields.qm31.QM31 };
/// Sparse extension sidecars are indexed by their actual execution instance.
/// The native artifact comes from the matching opcode execution wire.
pub const SerializedExternalProof = struct {
    instance_index: u32,
    stark_bytes: []const u8,
    claims: []const external.Claim,
};
pub const SerializedBatch = struct {
    memory: []const SerializedMemoryProof,
    range_tables: []const SerializedTableProof,
    execution_range_tables: []const SerializedTableProof = &.{},
    execution: []const execution_wire.Wire,
    execution_extensions: []const SerializedExternalProof = &.{},
    execution_extension_range_tables: []const SerializedTableProof = &.{},
    initial_sources: []const []const u8,
};

pub fn decodeStark(a: std.mem.Allocator, bytes: []const u8) !suite.Proof {
    if (bytes.len == 0 or bytes.len > MAX_STARK_BYTES) return error.InvalidSerializedStarkSize;
    var stream = std.io.fixedBufferStream(bytes);
    var proof = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer proof.deinit(a);
    if (stream.pos != bytes.len) return error.TrailingSerializedStarkBytes;
    return proof;
}
