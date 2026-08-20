//! Shared protocol types for RISC-V proving and verification.

const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const core_proof = @import("stwo_core").proof;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_engine = @import("stwo_prover_engine").engine;
const public_data_mod = @import("../air/public_data.zig");
const statement_mod = @import("../air/statement.zig");
const statement_v2_mod = @import("../air/statement_v2.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");

pub const PublicData = public_data_mod.PublicData;
pub const Hasher = blake2_merkle.Blake2sMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;

pub const FamilyComponentDesc = statement_mod.FamilyComponentDesc;
pub const InfraKind = statement_mod.InfraKind;
pub const InfraComponentDesc = statement_mod.InfraComponentDesc;
pub const RiscVStatement = statement_mod.RiscVStatement;
pub const RiscVStatementV2 = statement_v2_mod.RiscVStatementV2;
pub const RiscVInteractionClaim = statement_mod.RiscVInteractionClaim;
pub const MAX_COMPONENTS = statement_mod.MAX_COMPONENTS;
pub const MAX_INFRA_COMPONENTS = statement_mod.MAX_INFRA_COMPONENTS;

pub fn ProofForHasher(comptime H: type) type {
    return core_proof.StarkProof(H);
}

/// Compatibility helper for narrow test engines that predate the explicit
/// protocol-type surface.  Every admitted production engine declares
/// `Hasher`; the fallback keeps ownership/failure unit tests focused on the
/// stage contract they model.
pub fn HasherForEngine(comptime Engine: type) type {
    return if (@hasDecl(Engine, "Hasher")) Engine.Hasher else Hasher;
}

pub fn ProofForEngine(comptime Engine: type) type {
    return ProofForHasher(HasherForEngine(Engine));
}

pub const Proof = ProofForHasher(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);
pub const OwnedRiscVStatement = @import("../owned_statement.zig").OwnedRiscVStatement;
pub const RelationDiagnostic = relation_diagnostic.Output;

pub const RunMode = enum { prove, relation_diagnostic };

pub fn RunOutput(comptime mode: RunMode) type {
    return if (mode == .prove) ProveOutput else RelationDiagnostic;
}

pub fn RunOutputForEngine(comptime Engine: type, comptime mode: RunMode) type {
    return if (mode == .prove) ProveOutputForEngine(Engine) else RelationDiagnostic;
}

pub fn ProveOutputForEngine(comptime Engine: type) type {
    return ProveOutputForHasher(HasherForEngine(Engine));
}

pub fn ProveOutputV2ForEngine(comptime Engine: type) type {
    return ProveOutputV2ForHasher(HasherForEngine(Engine));
}

pub fn ProveOutputV2ForHasher(comptime H: type) type {
    return struct {
        statement: RiscVStatementV2,
        proof: ProofForHasher(H),
        interaction_claim: *RiscVInteractionClaim,

        const Self = @This();

        pub fn deinitAfterProofMoved(self: Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.interaction_claim);
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            allocator.destroy(self.interaction_claim);
            self.* = undefined;
        }
    };
}

pub const ProveOutputV2 = ProveOutputV2ForHasher(Hasher);

pub fn ProveOutputForHasher(comptime H: type) type {
    return struct {
        statement: RiscVStatement,
        proof: ProofForHasher(H),
        interaction_claim: *RiscVInteractionClaim,

        const Self = @This();

        /// Release the boxed interaction claim after ownership of `proof` has
        /// moved into the verifier.
        pub fn deinitAfterProofMoved(self: Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.interaction_claim);
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            allocator.destroy(self.interaction_claim);
            self.* = undefined;
        }
    };
}

pub const ProveOutput = ProveOutputForHasher(Hasher);

/// Complete proving-engine substitution point.
///
/// The frontend owns statement construction and portable trace columns. The
/// engine owns commitment state, commitment execution, composition, FRI,
/// decommitment, and proof assembly. `Scheme` is intentionally opaque to the
/// frontend so a device backend can store a resident arena and command graph.
pub const assertProverEngine = @import("stwo_prover_api").assertProverEngine;

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
