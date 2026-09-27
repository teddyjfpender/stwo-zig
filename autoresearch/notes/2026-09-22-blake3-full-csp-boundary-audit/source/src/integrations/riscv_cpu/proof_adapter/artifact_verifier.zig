const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const artifact_validation = @import("artifact_validation.zig");
const pcs_profile = @import("pcs_profile.zig");
const transcript_state = @import("transcript_state.zig");
const verify_receipt = @import("verify_receipt.zig");
const wire_reconstruct = @import("wire_reconstruct.zig");

const Protocol = pcs_profile.Protocol;
const stagedPcsConfig = pcs_profile.select;

pub fn verify(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    artifact: stwo.interop.riscv_artifact.Artifact,
    requested_policy: Protocol,
    expected_statement_digest: [32]u8,
    elf_path: []const u8,
) !void {
    const artifact_mod = stwo.interop.riscv_artifact;
    const prover = stwo.frontends.riscv.prover_mod;

    try artifact_mod.validateForPolicy(artifact, switch (requested_policy) {
        .secure => .secure,
        .functional => .functional,
        .smoke => .smoke,
    });
    try artifact_validation.validateLocalProvenance(artifact.provenance);
    try artifact_validation.validateElfBinding(allocator, artifact, elf_path);
    const actual_statement_digest = artifact_mod.statementDigest(
        artifact.protocol,
        artifact.pcs_config,
        artifact.source,
        artifact.statement,
    );
    if (!std.mem.eql(u8, &expected_statement_digest, &actual_statement_digest))
        return error.StatementDigestMismatch;

    var reconstructed = try wire_reconstruct.Reconstruction.init(allocator, artifact);
    defer reconstructed.deinit(allocator);

    if (artifact.proof_bytes_hex.len % 2 != 0) return error.InvalidArtifact;
    const proof_raw = try allocator.alloc(u8, artifact.proof_bytes_hex.len / 2);
    defer allocator.free(proof_raw);
    _ = std.fmt.hexToBytes(proof_raw, artifact.proof_bytes_hex) catch
        return error.InvalidArtifact;
    try stwo.interop.postcard.proof_preflight.validate(
        proof_raw,
        try artifact_validation.proofPreflightShape(artifact),
    );
    var stream = std.io.fixedBufferStream(proof_raw);
    var proof = try stwo.interop.postcard.deserializeProof(
        prover.Hasher,
        allocator,
        stream.reader(),
    );
    if (stream.pos != proof_raw.len) {
        proof.deinit(allocator);
        return error.InvalidArtifact;
    }

    const config = @TypeOf(stagedPcsConfig(.secure)){
        .pow_bits = artifact.pcs_config.pow_bits,
        .fri_config = .{
            .log_blowup_factor = artifact.pcs_config.fri_config.log_blowup_factor,
            .log_last_layer_degree_bound = artifact.pcs_config.fri_config.log_last_layer_degree_bound,
            .n_queries = artifact.pcs_config.fri_config.n_queries,
        },
    };
    if (!artifact_validation.pcsConfigsEqual(config, proof.commitment_scheme_proof.config)) {
        proof.deinit(allocator);
        return error.ProofConfigMismatch;
    }
    var verify_channel = Engine.Channel{};
    try prover.verifyRiscVWithEngineUsingChannel(
        Engine,
        allocator,
        config,
        reconstructed.statement,
        proof,
        &reconstructed.claim,
        &verify_channel,
    );

    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(proof_raw, &proof_digest, .{});
    const process_identity = try artifact_validation.measureProcessIdentity(allocator);
    const receipt = try verify_receipt.encode(allocator, .{
        .artifact_kind = artifact.artifact_kind,
        .artifact_schema_version = artifact.schema_version,
        .release_status = artifact.release_status,
        .security_policy = @tagName(requested_policy),
        .statement_sha256 = actual_statement_digest,
        .proof_bytes = proof_raw.len,
        .proof_sha256 = proof_digest,
        .transcript_state_blake2s = transcript_state.receiptDigest(
            verify_channel.digestBytes(),
            verify_channel.n_draws,
        ),
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = process_identity.executable_sha256,
    });
    defer allocator.free(receipt);
    try std.fs.File.stdout().writeAll(receipt);
    try std.fs.File.stdout().writeAll("\n");
}
