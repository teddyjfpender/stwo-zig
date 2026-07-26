//! Shared protocol types for RISC-V proving and verification.

const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const core_proof = @import("stwo_core").proof;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_engine = @import("stwo_prover_impl").engine;
const public_data_mod = @import("../air/public_data.zig");
const statement_mod = @import("../air/statement.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");

pub const PublicData = public_data_mod.PublicData;
pub const Hasher = blake2_merkle.Blake2sMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;

pub const FamilyComponentDesc = statement_mod.FamilyComponentDesc;
pub const InfraKind = statement_mod.InfraKind;
pub const InfraComponentDesc = statement_mod.InfraComponentDesc;
pub const RiscVStatement = statement_mod.RiscVStatement;
pub const RiscVInteractionClaim = statement_mod.RiscVInteractionClaim;
pub const MAX_COMPONENTS = statement_mod.MAX_COMPONENTS;
pub const MAX_INFRA_COMPONENTS = statement_mod.MAX_INFRA_COMPONENTS;

pub const Proof = core_proof.StarkProof(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);
pub const OwnedRiscVStatement = @import("../owned_statement.zig").OwnedRiscVStatement;
pub const RelationDiagnostic = relation_diagnostic.Output;

pub const RunMode = enum { prove, relation_diagnostic };

pub fn RunOutput(comptime mode: RunMode) type {
    return if (mode == .prove) ProveOutput else RelationDiagnostic;
}

pub const ProveOutput = struct {
    statement: RiscVStatement,
    proof: Proof,
    interaction_claim: *RiscVInteractionClaim,

    /// Release the boxed interaction claim after ownership of `proof` has
    /// moved into the verifier.
    pub fn deinitAfterProofMoved(self: ProveOutput, allocator: std.mem.Allocator) void {
        allocator.destroy(self.interaction_claim);
    }

    pub fn deinit(self: *ProveOutput, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        allocator.destroy(self.interaction_claim);
        self.* = undefined;
    }
};

/// Complete proving-engine substitution point.
///
/// The frontend owns statement construction and portable trace columns. The
/// engine owns commitment state, commitment execution, composition, FRI,
/// decommitment, and proof assembly. `Scheme` is intentionally opaque to the
/// frontend so a device backend can store a resident arena and command graph.
pub const assertProverEngine = prover_engine.assertProverEngine;

/// Binds a caller-selected backend to this frontend's protocol types.
///
/// Concrete backend selection belongs to an integration or tool boundary.
pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

pub const ProverError = error{
    EmptyTrace,
    InvalidLogSize,
    InvalidStatement,
    InvalidPreprocessedCommitment,
    InvalidInteractionClaim,
    ProvingFailed,
    TooManyOpcodeComponents,
    TooManyInfrastructureComponents,
};
