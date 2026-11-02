//! Read-only measurements of the actual serialized proof and legacy native
//! source allocations. This module defines no proving/transcript authority.
const std = @import("std");
const wire = @import("stwo_proof_wire");
const Opcode = @import("stwo_riscv_frontend").rv64.decode.Opcode;
pub const OPCODE_NAMES = std.meta.fieldNames(Opcode);
pub const Samples = struct {
    oods_samples: usize = 0,
    queried_base_values: usize = 0,
    authenticated_hashes: usize = 0,
};
pub fn inspect(proof: *const wire.Proof) Samples {
    var out = Samples{};
    for (proof.commitment_scheme_proof.sampled_values.items) |tree| for (tree) |column| {
        out.oods_samples += column.len;
    };
    for (proof.commitment_scheme_proof.queried_values.items) |tree| for (tree) |column| {
        out.queried_base_values += column.len;
    };
    for (proof.commitment_scheme_proof.decommitments.items) |tree| {
        out.authenticated_hashes += tree.hash_witness.len;
    }
    return out;
}
pub fn encoded(a: std.mem.Allocator, bytes: []const u8) !Samples {
    var proof = try wire.decodeProofBytesBinary(a, bytes);
    defer proof.deinit(a);
    return inspect(&proof);
}
