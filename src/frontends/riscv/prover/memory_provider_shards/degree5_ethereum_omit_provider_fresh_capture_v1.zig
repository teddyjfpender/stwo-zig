//! Verifier-owned query/opening custody for one successful degree-five
//! Ethereum provider shard. Artifact bytes and commitment digests alone cannot
//! construct this value.

const std = @import("std");
const core_verifier = @import("stwo_core").verifier;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const aggregation_hash = @import("../../aggregation/hash.zig");
const proof_capture_sha256 = @import("../proof_capture_sha256.zig");
const relation_challenges = @import("../../air/relation_challenges.zig");
const proof_authority = @import("joint_proof_authority.zig");
const binding = @import("degree5_ethereum_omit_provider_authority_v1.zig");

const proof_commitment_count: usize = 4;
const capture_domain =
    "stwo-zig/riscv/d5-ethereum-provider-capture/v1\x00";

pub fn CaptureV1(comptime Engine: type) type {
    return struct {
        proof: core_verifier.ProofCapture(Engine.Hasher),
        relation_draws: [relation_challenges.DRAW_COUNT]QM31,
        statement_identity: binding.Digest,
        fresh_claim_identity: binding.Digest,
        proof_commitments_identity: binding.Digest,
        proof_root_sha256: [32]u8,
        proof_capture_sha256: [32]u8,
        verifier_program_authority_sha256: [32]u8,
        protocol_profile_sha256: [32]u8,
        identity: [32]u8,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        pub fn validateAgainst(
            self: *const Self,
            statement: binding.ProviderStatementV1,
            fresh: binding.FreshDegree5ProviderClaimV1,
            program: binding.VerifierProgramAuthorityV2,
            profile: anytype,
            expected_relation_draws: *const [relation_challenges.DRAW_COUNT]QM31,
        ) !void {
            requireSupportedProfile(@TypeOf(profile));
            try fresh.validate();
            try profile.validate(program.base);
            try validateRelationDraws(
                &self.relation_draws,
                expected_relation_draws,
            );
            if (self.proof.commitments.len != proof_commitment_count or
                !aggregation_hash.eql(
                    statement.identity,
                    binding.statementIdentity(statement),
                ) or !aggregation_hash.eql(
                statement.air_program_identity,
                program.air_program_identity,
            ) or !aggregation_hash.eql(
                fresh.provider.statement_identity,
                statement.identity,
            ) or !aggregation_hash.eql(
                fresh.air_program_identity,
                program.air_program_identity,
            ) or !aggregation_hash.eql(
                fresh.execution_profile_identity,
                profile.identity,
            ) or
                !aggregation_hash.eql(self.statement_identity, statement.identity) or
                !aggregation_hash.eql(self.fresh_claim_identity, fresh.identity) or
                !aggregation_hash.eql(
                    self.proof_commitments_identity,
                    fresh.provider.proof_commitments_identity,
                ) or !aggregation_hash.eql(
                self.proof_commitments_identity,
                proof_authority.commitmentsIdentity(
                    Engine,
                    self.proof.commitments,
                ),
            ) or !std.mem.eql(
                u8,
                &self.proof_root_sha256,
                &commitmentsSha256(Engine, self.proof.commitments),
            ) or !std.mem.eql(
                u8,
                &self.proof_capture_sha256,
                &proof_capture_sha256.compute(&self.proof),
            ) or !std.mem.eql(
                u8,
                &self.verifier_program_authority_sha256,
                &verifierProgramAuthoritySha256(program),
            ) or !std.mem.eql(
                u8,
                &self.protocol_profile_sha256,
                &executionProfileSha256(profile),
            ) or !std.mem.eql(
                u8,
                &self.identity,
                &captureIdentity(self),
            )) return error.InvalidFreshDegree5ProviderCapture;
        }
    };
}

pub fn init(
    comptime Engine: type,
    proof: core_verifier.ProofCapture(Engine.Hasher),
    relation_draws: [relation_challenges.DRAW_COUNT]QM31,
    statement: binding.ProviderStatementV1,
    fresh: binding.FreshDegree5ProviderClaimV1,
    program: binding.VerifierProgramAuthorityV2,
    profile: anytype,
) !CaptureV1(Engine) {
    requireSupportedProfile(@TypeOf(profile));
    var result = CaptureV1(Engine){
        .proof = proof,
        .relation_draws = relation_draws,
        .statement_identity = statement.identity,
        .fresh_claim_identity = fresh.identity,
        .proof_commitments_identity = fresh.provider.proof_commitments_identity,
        .proof_root_sha256 = commitmentsSha256(Engine, proof.commitments),
        .proof_capture_sha256 = proof_capture_sha256.compute(&proof),
        .verifier_program_authority_sha256 = verifierProgramAuthoritySha256(program),
        .protocol_profile_sha256 = executionProfileSha256(profile),
        .identity = undefined,
    };
    result.identity = captureIdentity(&result);
    try result.validateAgainst(
        statement,
        fresh,
        program,
        profile,
        &relation_draws,
    );
    return result;
}

pub fn validateRelationDraws(
    actual: *const [relation_challenges.DRAW_COUNT]QM31,
    expected: *const [relation_challenges.DRAW_COUNT]QM31,
) !void {
    if (!std.meta.eql(actual.*, expected.*))
        return error.InvalidFreshDegree5ProviderRelationDraws;
}

pub fn verifierProgramAuthoritySha256(
    program: binding.VerifierProgramAuthorityV2,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/riscv/d5-ethereum-provider-verifier-program/v1\x00",
    );
    hash.update(&program.air_program_identity);
    return hash.finalResult();
}

pub fn executionProfileSha256(
    profile: anytype,
) [32]u8 {
    requireSupportedProfile(@TypeOf(profile));
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/d5-ethereum-provider-profile/v1\x00");
    hash.update(&profile.identity);
    return hash.finalResult();
}

fn requireSupportedProfile(comptime Profile: type) void {
    if (Profile != binding.ExecutionProfileV1 and
        Profile != binding.ExecutionProfileV2)
    {
        @compileError("unsupported degree-five provider capture profile");
    }
}

pub fn commitmentsSha256(
    comptime Engine: type,
    commitments: []const Engine.Hasher.Hash,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/d5-ethereum-provider-roots/v1\x00");
    hashInt(&hash, u32, @intCast(commitments.len));
    for (commitments) |root| hashRoot(&hash, root);
    return hash.finalResult();
}

fn captureIdentity(capture: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(capture_domain);
    hash.update(&capture.statement_identity);
    hash.update(&capture.fresh_claim_identity);
    hash.update(&capture.proof_commitments_identity);
    hash.update(&capture.proof_root_sha256);
    hash.update(&capture.proof_capture_sha256);
    hash.update(&capture.verifier_program_authority_sha256);
    hash.update(&capture.protocol_profile_sha256);
    for (capture.relation_draws) |value|
        for (value.toM31Array()) |limb|
            hashInt(&hash, u32, limb.toU32());
    return hash.finalResult();
}

fn hashRoot(hash: *std.crypto.hash.sha2.Sha256, root: anytype) void {
    const Root = @TypeOf(root);
    switch (@typeInfo(Root)) {
        .array => |array| switch (@typeInfo(array.child)) {
            .int => {},
            else => @compileError("provider commitment hash must be an integer array"),
        },
        else => @compileError("provider commitment hash must be an integer array"),
    }
    for (root) |word| hashInt(hash, @TypeOf(word), word);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
