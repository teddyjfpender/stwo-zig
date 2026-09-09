//! Shared proof, verification, and file-custody helpers for streamed leaves.

const std = @import("std");
const core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const contract = @import("ethereum_block_leaf_contract.zig");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const proof_security = @import("recursive_temporal_proof_security_v1.zig");
const leaf_descriptor =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const lookup_physical_v2 = frontend.air.lookup_physical_manifest_v2;
const program_v2 = frontend.recursion.ethereum_vm_composition_program_v2;
const verified_program_descriptor =
    frontend.recursion.ethereum_vm_verified_program_descriptor_v1;

pub const prover = frontend.prover_mod;
pub const Engine = prover.ProverEngineForBackend(CpuBackend);
pub const RecursiveEngine = frontend.recursion.engine.ProverEngineForBackend(
    CpuBackend,
);
pub const artifact = prover.guest_precompile.ethereum_segment_proof_artifact;
pub const recursive_artifact =
    prover.guest_precompile.ethereum_segment_poseidon2_proof_artifact;
pub const source_wire = prover.guest_precompile.ethereum_segment_source_wire;
pub const pcs_config = prover.SECURE_PCS_CONFIG;
pub const recursive_pcs_config = frontend.recursion.protocol.PCS_CONFIG;
pub const recursive_security_identity = identity: {
    @setEvalBranchQuota(10_000);
    break :identity proof_security.ProofSecurityV1
        .ethereumSegmentV3Poseidon2().identity;
};
pub const worker_count: usize = 8;
/// Explicit proof-wide product policy. This leaves 16 GiB of a 64 GiB host
/// outside the PCS lower bound for witnesses, Merkle nodes, twiddles, worker
/// stacks, allocator overhead, and the operating system.
pub const product_host_byte_budget: usize = 48 * 1024 * 1024 * 1024;
pub const artifact_limits: artifact.Limits = .{
    .max_artifact_bytes = 256 * 1024 * 1024,
    .max_proof_bytes = 128 * 1024 * 1024,
    .max_input_bytes = 16 * 1024 * 1024,
    .max_output_bytes = 16 * 1024 * 1024,
    .max_queries = 1024,
    .max_pow_bits = 128,
};

pub const Verified = struct {
    segment_index: u32,
    segment_count: u32,
    statement_sha256: [32]u8,
    root_sha256: [32]u8,
    transcript_state_blake2s: [32]u8,
    verified_link_id: frontend.recursion.poseidon2_channel.Digest,
};

/// Process-local capability minted only after the complete Poseidon leaf proof
/// and its cold-recomputed Tree0 commitment have verified. Its transport
/// projection is published only after this value is rechecked against the
/// verifier-owned capture in the same transaction.
pub const FreshVerifiedEthereumVmProgramV2 = struct {
    program: program_v2.EthereumVmCompositionProgramV2,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    preprocessed_commitment_root: frontend.recursion.poseidon2_channel.Digest,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
    instance_sha256: [32]u8,

    pub fn deinit(self: *FreshVerifiedEthereumVmProgramV2) void {
        self.program.deinit();
        self.* = undefined;
    }

    /// Cold re-admission is valid only while the fresh verifier-owned capture
    /// remains in the same transaction. This does not turn the SHA seal into a
    /// transport or proof authority.
    pub fn validateAgainstCapture(
        self: *const FreshVerifiedEthereumVmProgramV2,
        capture: *const prover.VerifiedEthereumSegmentV3CaptureForEngine(
            RecursiveEngine,
        ),
    ) !void {
        try capture.validate();
        var manifest = lookup_physical_v2.Manifest.native();
        const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
            &capture.core_statement.core,
            &manifest,
        );
        try self.program.validateAgainst(.{
            .core_statement = &capture.core_statement.core,
            .extension_statement = &capture.extension_statement,
            .lookup_manifest = &manifest,
            .authenticated_lookup = &authenticated,
            .base_profile = &capture.base.vm_air.profile,
        });
        try self.validateBinding(capture);
    }

    pub fn descriptorAgainstCapture(
        self: *const FreshVerifiedEthereumVmProgramV2,
        capture: *const prover.VerifiedEthereumSegmentV3CaptureForEngine(
            RecursiveEngine,
        ),
    ) !verified_program_descriptor.DescriptorV1 {
        try self.validateAgainstCapture(capture);
        const result = verified_program_descriptor.project(
            &self.program,
            self.preprocessed_commitment_root,
            self.proof_capture_sha256,
            self.capture_identity,
        );
        try result.validateAgainstProgram(&self.program);
        if (!std.mem.eql(
            u8,
            &result.instance_sha256,
            &self.instance_sha256,
        )) return error.InvalidFreshVerifierProgramAuthority;
        return result;
    }

    fn validateBinding(
        self: *const FreshVerifiedEthereumVmProgramV2,
        capture: *const prover.VerifiedEthereumSegmentV3CaptureForEngine(
            RecursiveEngine,
        ),
    ) !void {
        try self.program.validate();
        if (capture.base.proof.commitments.len != 4 or
            !std.mem.eql(
                u8,
                &self.air_program_identity,
                &self.program.air_program_identity,
            ) or !std.mem.eql(
            u8,
            &self.verifier_program_authority,
            &self.program.verifier_program_authority,
        ) or !std.meta.eql(
            self.preprocessed_commitment_root,
            capture.base.proof.commitments[0],
        ) or !std.mem.eql(
            u8,
            &self.proof_capture_sha256,
            &capture.proof_capture_sha256,
        ) or !std.mem.eql(
            u8,
            &self.capture_identity,
            &capture.identity_digest,
        ) or !std.mem.eql(
            u8,
            &self.instance_sha256,
            &verified_program_descriptor.instanceSha256(.{
                .air_program_identity = self.air_program_identity,
                .verifier_program_authority = self.verifier_program_authority,
                .preprocessed_commitment_root = self.preprocessed_commitment_root,
                .proof_capture_sha256 = self.proof_capture_sha256,
                .capture_identity = self.capture_identity,
            }),
        )) return error.InvalidFreshVerifierProgramAuthority;
    }
};

/// Owned, verifier-minted v4 authority. The complete dynamic capture remains
/// available beside the pointer-free recursive leaf descriptor, so cold
/// re-admission can reopen the exact proof rather than trust transport seals.
pub const VerifiedPoseidonV4 = struct {
    capture: prover.VerifiedEthereumSegmentV3CaptureForEngine(RecursiveEngine),
    verifier_program: FreshVerifiedEthereumVmProgramV2,
    leaf_descriptor: leaf_descriptor.DescriptorV1,
    proof_artifact_byte_count: u64,
    proof_artifact_sha256: [32]u8,
    recursive_statement_sha256: [32]u8,
    root_sha256: [32]u8,
    source_public_statement_sha256: [32]u8,
    transcript_state_sha256: [32]u8,

    pub fn deinit(self: *VerifiedPoseidonV4, allocator: std.mem.Allocator) void {
        self.verifier_program.deinit();
        self.capture.deinit(allocator);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const VerifiedPoseidonV4,
        expected: *const source_wire.Source,
    ) !void {
        try self.verifier_program.validateAgainstCapture(&self.capture);
        try self.validateExpectedSource(expected);
        const expected_program = try self.verifier_program
            .descriptorAgainstCapture(&self.capture);
        if (!std.meta.eql(self.leaf_descriptor.program, expected_program) or
            self.leaf_descriptor.proof_artifact_byte_count !=
                self.proof_artifact_byte_count or
            !std.mem.eql(
                u8,
                &self.leaf_descriptor.proof_artifact_sha256,
                &self.proof_artifact_sha256,
            ) or !std.mem.eql(
            u8,
            &self.leaf_descriptor.recursive_statement_sha256,
            &self.recursive_statement_sha256,
        ) or !std.mem.eql(
            u8,
            &self.leaf_descriptor.proof_root_sha256,
            &self.root_sha256,
        ) or !std.mem.eql(
            u8,
            &self.leaf_descriptor.source_public_statement_sha256,
            &self.source_public_statement_sha256,
        ) or !std.mem.eql(
            u8,
            &self.leaf_descriptor.transcript_state_sha256,
            &self.transcript_state_sha256,
        )) return error.InvalidFreshVerifierProgramAuthority;
        try self.leaf_descriptor.validateAgainst(
            expected,
            &self.verifier_program.program,
        );
    }

    fn validateExpectedSource(
        self: *const VerifiedPoseidonV4,
        expected: *const source_wire.Source,
    ) !void {
        try expected.metadata.validate();
        if (!std.meta.eql(self.capture.global_metadata, expected.metadata) or
            !std.meta.eql(
                self.source_public_statement_sha256,
                try expected.statementSha256(),
            ) or !std.meta.eql(
            self.recursive_statement_sha256,
            statement_plan.statementSha256(
                &expected.metadata.base_statement_words,
            ),
        )) return error.VerifiedPoseidonSourceMismatch;
        try self.capture.verified_link.validateAgainst(
            &expected.metadata,
            &self.capture.base.public_data.data,
            &self.capture.base.receipt,
        );
    }
};

pub fn verifyArtifact(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) !Verified {
    var decoded = try artifact.decodeAllocForConfig(
        allocator,
        encoded,
        pcs_config,
        artifact_limits,
    );
    var proof_moved = false;
    defer if (proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);
    const root = rootsSha256(&decoded.proof);
    const statement = try source_wire.publicStatementSha256(&decoded.global);
    var channel = Engine.Channel{};
    var capture: prover.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
    proof_moved = true;
    try prover.verifyEthereumSegmentWithEngineAndCaptureUsingChannel(
        Engine,
        allocator,
        pcs_config,
        decoded.statement,
        decoded.extension,
        decoded.proof,
        decoded.base_claim,
        &decoded.extension_claim,
        &channel,
        &capture,
    );
    defer capture.deinit(allocator);
    try capture.validate();
    const link = try frontend.recursion.segment_leaf_local_verified_link_v3
        .VerifiedLinkV3.init(
        &decoded.global,
        &capture.public_data.data,
        &capture.receipt,
    );
    try link.validateAgainst(
        &decoded.global,
        &capture.public_data.data,
        &capture.receipt,
    );
    return .{
        .segment_index = decoded.global.segment_index,
        .segment_count = decoded.global.segment_count,
        .statement_sha256 = statement,
        .root_sha256 = root,
        .transcript_state_blake2s = artifact_io.transcriptReceiptDigest(
            channel.digestBytes(),
            channel.n_draws,
        ),
        .verified_link_id = link.identity,
    };
}

pub fn verifyPoseidonArtifactWithCapture(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    expected: *const source_wire.Source,
) !VerifiedPoseidonV4 {
    try expected.metadata.validate();
    const proof_artifact_byte_count = std.math.cast(u64, encoded.len) orelse
        return error.FileResourceLimitExceeded;
    const proof_artifact_sha256 = sha256(encoded);
    var decoded = try recursive_artifact.decodeAlloc(
        allocator,
        encoded,
        recursive_security_identity,
        artifact_limits,
    );
    var proof_moved = false;
    defer if (proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);
    if (!std.meta.eql(decoded.global, expected.metadata))
        return error.VerifiedPoseidonSourceMismatch;
    const root = recursiveRootsSha256(&decoded.proof);
    var channel = RecursiveEngine.Channel{};
    var capture: prover.VerifiedEthereumSegmentV3CaptureForEngine(
        RecursiveEngine,
    ) = undefined;
    proof_moved = true;
    try prover.verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannel(
        RecursiveEngine,
        allocator,
        recursive_pcs_config,
        decoded.statement,
        decoded.extension,
        decoded.proof,
        decoded.base_claim,
        &decoded.extension_claim,
        &decoded.global,
        &channel,
        &capture,
    );
    errdefer capture.deinit(allocator);
    var verifier_program = try mintFreshVerifiedProgramV2(allocator, &capture);
    errdefer verifier_program.deinit();
    try capture.verified_link.validateAgainst(
        &expected.metadata,
        &capture.base.public_data.data,
        &capture.base.receipt,
    );
    const projected_program = try verifier_program.descriptorAgainstCapture(
        &capture,
    );
    const recursive_statement_sha256 = statement_plan.statementSha256(
        &expected.metadata.base_statement_words,
    );
    const source_public_statement_sha256 = try expected.statementSha256();
    const transcript_state_sha256 = artifact_io.transcriptReceiptDigest(
        channel.digestBytes(),
        channel.n_draws,
    );
    const verified_leaf_descriptor = try leaf_descriptor
        .initFromFreshVerifier(.{
        .program = projected_program,
        .source = expected,
        .verified_link = capture.verified_link,
        .proof_artifact_byte_count = proof_artifact_byte_count,
        .proof_artifact_sha256 = proof_artifact_sha256,
        .proof_root_sha256 = root,
        .transcript_state_sha256 = transcript_state_sha256,
    });
    var result = VerifiedPoseidonV4{
        .capture = capture,
        .verifier_program = verifier_program,
        .leaf_descriptor = verified_leaf_descriptor,
        .proof_artifact_byte_count = proof_artifact_byte_count,
        .proof_artifact_sha256 = proof_artifact_sha256,
        .recursive_statement_sha256 = recursive_statement_sha256,
        .root_sha256 = root,
        .source_public_statement_sha256 = source_public_statement_sha256,
        .transcript_state_sha256 = transcript_state_sha256,
    };
    try result.validateAgainst(expected);
    return result;
}

fn mintFreshVerifiedProgramV2(
    allocator: std.mem.Allocator,
    capture: *const prover.VerifiedEthereumSegmentV3CaptureForEngine(
        RecursiveEngine,
    ),
) !FreshVerifiedEthereumVmProgramV2 {
    // This private constructor is called only on the direct success edge of
    // the fresh verifier above. Re-admission deliberately has no public mint.
    try capture.validate();
    if (capture.base.proof.commitments.len != 4)
        return error.InvalidFreshVerifierProgramAuthority;
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &capture.core_statement.core,
        &manifest,
    );
    var program = try program_v2.compile(allocator, .{
        .core_statement = &capture.core_statement.core,
        .extension_statement = &capture.extension_statement,
        .lookup_manifest = &manifest,
        .authenticated_lookup = &authenticated,
        .base_profile = &capture.base.vm_air.profile,
    });
    errdefer program.deinit();
    var result = FreshVerifiedEthereumVmProgramV2{
        .air_program_identity = program.air_program_identity,
        .verifier_program_authority = program.verifier_program_authority,
        .preprocessed_commitment_root = capture.base.proof.commitments[0],
        .proof_capture_sha256 = capture.proof_capture_sha256,
        .capture_identity = capture.identity_digest,
        .instance_sha256 = undefined,
        .program = program,
    };
    result.instance_sha256 = verified_program_descriptor.instanceSha256(.{
        .air_program_identity = result.air_program_identity,
        .verifier_program_authority = result.verifier_program_authority,
        .preprocessed_commitment_root = result.preprocessed_commitment_root,
        .proof_capture_sha256 = result.proof_capture_sha256,
        .capture_identity = result.capture_identity,
    });
    try result.validateBinding(capture);
    return result;
}

pub const testing = struct {
    pub fn freshProgramInstanceSha256(
        air_program_identity: [32]u8,
        verifier_program_authority: [32]u8,
        preprocessed_commitment_root: frontend.recursion.poseidon2_channel.Digest,
        proof_capture_sha256: [32]u8,
        capture_identity: [32]u8,
    ) [32]u8 {
        return verified_program_descriptor.instanceSha256(.{
            .air_program_identity = air_program_identity,
            .verifier_program_authority = verifier_program_authority,
            .preprocessed_commitment_root = preprocessed_commitment_root,
            .proof_capture_sha256 = proof_capture_sha256,
            .capture_identity = capture_identity,
        });
    }
};

pub fn sessionDigest(session_id: [32]u8) frontend.recursion.span_statement.Digest {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u16, session_id[2 * index ..][0..2], .little);
    return frontend.recursion.poseidon2_channel.hashCanonicalU32s(
        &words,
        0x4553_5633, // "ESV3"
    );
}

pub fn encodeLocalPublicData(
    allocator: std.mem.Allocator,
    source: *const frontend.recursion.segment_statement_v2.SourceV2,
) !struct {
    words: []core.fields.m31.M31,
    value: frontend.air.public_data_v2.PublicDataV2,
} {
    const words = try allocator.alloc(
        core.fields.m31.M31,
        try source.canonicalWordCount(),
    );
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return .{
        .words = words,
        .value = try frontend.air.public_data_v2.PublicDataV2.authenticate(words),
    };
}

/// Byte-identical restart encoder for a SourceV2 projected from an already
/// cold-authenticated STWESG31 leaf. Sparse tuple identities/counts are
/// recomputed from `source`; only the retained continuation roots are reused.
pub fn encodeLocalPublicDataReusingRoots(
    allocator: std.mem.Allocator,
    source: *const frontend.recursion.segment_statement_v2.SourceV2,
    retained: *const frontend.recursion.segment_leaf_local_authority_v3.MetadataV3,
) !struct {
    words: []core.fields.m31.M31,
    value: frontend.air.public_data_v2.PublicDataV2,
} {
    try retained.validate();
    const words = try allocator.alloc(
        core.fields.m31.M31,
        try source.canonicalWordCount(),
    );
    errdefer allocator.free(words);
    _ = try source.encodeCanonicalReusingRoots(
        words,
        .{
            .id = retained.entry.snapshot_id,
            .count = retained.entry.snapshot_count,
            .root = retained.entry.continuation_root,
        },
        .{
            .id = retained.exit.snapshot_id,
            .count = retained.exit.snapshot_count,
            .root = retained.exit.continuation_root,
        },
    );
    return .{
        .words = words,
        .value = try frontend.air.public_data_v2.PublicDataV2
            .authenticateReusingRoots(words, .{
            .entry = .{
                .id = retained.entry.snapshot_id,
                .count = retained.entry.snapshot_count,
                .root = retained.entry.continuation_root,
            },
            .exit = .{
                .id = retained.exit.snapshot_id,
                .count = retained.exit.snapshot_count,
                .root = retained.exit.continuation_root,
            },
        }),
    };
}

pub fn readIdentity(
    allocator: std.mem.Allocator,
    identity: contract.Identity,
    max_bytes: usize,
) ![]u8 {
    try identity.validate(true);
    if (identity.bytes > max_bytes) return error.FileResourceLimitExceeded;
    const bytes = try artifact_io.readFileBounded(
        allocator,
        identity.path,
        max_bytes,
    );
    errdefer allocator.free(bytes);
    if (bytes.len != identity.bytes) return error.FileIdentityMismatch;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.meta.eql(digest, try contract.parseSha256(identity.sha256)))
        return error.FileIdentityMismatch;
    return bytes;
}

pub fn rootsSha256(proof: *const prover.Proof) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-segment.commitment-roots.v1\x00");
    for (proof.commitment_scheme_proof.commitments.items) |root|
        hash.update(std.mem.asBytes(&root));
    return hash.finalResult();
}

pub fn recursiveRootsSha256(
    proof: *const recursive_artifact.Proof,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-segment.poseidon2-roots.v1\x00");
    var encoded: [4]u8 = undefined;
    for (proof.commitment_scheme_proof.commitments.items) |root|
        for (root) |word| {
            std.mem.writeInt(u32, &encoded, word, .little);
            hash.update(&encoded);
        };
    return hash.finalResult();
}

pub fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

pub fn executableSha256(allocator: std.mem.Allocator) ![32]u8 {
    return artifact_io.executableSha256(allocator);
}

pub fn executionOptions() prover.EthereumExecutionOptions {
    return .{ .cpu = .{
        .worker_count = worker_count,
        .host_byte_budget = product_host_byte_budget,
        .contention_policy = .strict,
    } };
}

comptime {
    if (pcs_config.pow_bits != 26 or pcs_config.fri_config.n_queries != 70 or
        pcs_config.fri_config.log_blowup_factor != 1 or worker_count != 8 or
        product_host_byte_budget != 48 * 1024 * 1024 * 1024 or
        product_host_byte_budget == std.math.maxInt(usize) or
        frontend.recursion.segment_leaf_local_authority_v3.PRODUCTION_PROOF_ACTIVATION or
        recursive_pcs_config.pow_bits != 16 or
        recursive_pcs_config.fri_config.n_queries != 193)
    {
        @compileError("pre-activation Ethereum streamed-leaf product drifted");
    }
}
