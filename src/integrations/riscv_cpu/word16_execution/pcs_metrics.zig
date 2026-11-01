//! Serialized work counts only. These diagnostics grant no proof authority.
const std = @import("std");
const wire = @import("stwo_proof_wire");
pub const Report = struct {
    scope: []const u8 = "serialized native PCS/FRI work counts; not acceptance or a security estimate",
    physical_proof_verified: bool = false,
    proof_bytes: usize,
    fold_step: u32,
    queries: usize,
    pow_bits: u32,
    pcs_commitment_roots: usize,
    pcs_sampled_qm31: usize = 0,
    pcs_queried_m31: usize = 0,
    pcs_hash_witnesses: usize = 0,
    fri_inner_layers: usize,
    fri_witness_qm31: usize = 0,
    fri_hash_witnesses: usize = 0,
    last_layer_qm31: usize,
    // A compressed multiproof's witness size is not its hash-operation count.
    receiver_hash_operations_measured: bool = false,
};
pub fn inspectFile(a: std.mem.Allocator, path: []const u8) !Report {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 64 * 1024 * 1024);
    defer a.free(bytes);
    return inspect(a, bytes);
}
pub fn inspect(a: std.mem.Allocator, bytes: []const u8) !Report {
    var proof = try wire.decodeProofBytesBinary(a, bytes);
    defer proof.deinit(a);
    const p = &proof.commitment_scheme_proof;
    var report = Report{ .proof_bytes = bytes.len, .fold_step = p.config.fri_config.fold_step, .queries = p.config.fri_config.n_queries, .pow_bits = p.config.pow_bits, .pcs_commitment_roots = p.commitments.items.len, .fri_inner_layers = p.fri_proof.inner_layers.len, .last_layer_qm31 = p.fri_proof.last_layer_poly.coeffs.len };
    for (p.sampled_values.items) |tree| for (tree) |column| {
        report.pcs_sampled_qm31 += column.len;
    };
    for (p.queried_values.items) |tree| for (tree) |column| {
        report.pcs_queried_m31 += column.len;
    };
    for (p.decommitments.items) |tree| report.pcs_hash_witnesses += tree.hash_witness.len;
    report.fri_witness_qm31 = p.fri_proof.first_layer.fri_witness.len;
    report.fri_hash_witnesses = p.fri_proof.first_layer.decommitment.hash_witness.len;
    for (p.fri_proof.inner_layers) |layer| {
        report.fri_witness_qm31 += layer.fri_witness.len;
        report.fri_hash_witnesses += layer.decommitment.hash_witness.len;
    }
    return report;
}
