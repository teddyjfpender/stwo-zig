//! Allocation-safe ingress for Poseidon-native recursive leaf proofs.
//!
//! A postcard `StarkProof` contains attacker-controlled length prefixes.  The
//! ordinary decoder must therefore never see external bytes until this module
//! has reconstructed the exact tree geometry from an independently validated
//! RISC-V statement and walked the complete wire without allocating.

const std = @import("std");
const stwo_core = @import("stwo_core");
const postcard = @import("interop_postcard");
const statement_mod = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const statement_validation = @import("../prover/statement_validation.zig");
const prover_types = @import("../prover/types.zig");
const engine = @import("engine.zig");
const protocol = @import("protocol.zig");

/// Exact authenticated retirement authority accepted by the additive V2
/// proof-shape preflight below. Exporting the type here keeps integration
/// callers on the stable recursion facade rather than reaching into prover
/// implementation modules.
pub const RetirementSupplementV2 =
    statement_validation.RetirementSupplementV2;

const qm31 = stwo_core.fields.qm31;
const verifier_types = stwo_core.verifier_types;

pub const DEFAULT_MAX_PROOF_BYTES: usize = 128 * 1024 * 1024;

pub const Error = prover_types.ProverError || statement_v2.Error ||
    postcard.proof_preflight.Error || error{
    InvalidProofResourceLimit,
    InvalidProofShape,
};

/// Derive the only postcard shape admitted for a base RISC-V leaf.
///
/// Every count comes from the validated statement or the frozen recursion PCS
/// profile.  No field is read from proof bytes and no allocation is required.
pub fn preflightShape(
    statement: statement_mod.RiscVStatement,
    max_wire_bytes: usize,
) Error!postcard.proof_preflight.Shape {
    return preflightShapeForVerifierConfig(
        statement,
        protocol.PCS_CONFIG,
        max_wire_bytes,
    );
}

/// Derives an allocation-free postcard shape for an explicitly verifier-owned
/// PCS configuration.  This is the measurement/versioned-profile seam: proof
/// bytes still cannot choose any geometry, while a caller evaluating a future
/// protocol profile can exercise the same ingress boundary as frozen V1.
pub fn preflightShapeForVerifierConfig(
    statement: statement_mod.RiscVStatement,
    pcs_config: stwo_core.pcs.PcsConfig,
    max_wire_bytes: usize,
) Error!postcard.proof_preflight.Shape {
    if (max_wire_bytes == 0) return error.InvalidProofResourceLimit;
    try statement_validation.validate(statement, .proof);

    return preflightShapeFromValidatedCore(
        statement,
        pcs_config,
        max_wire_bytes,
    );
}

fn preflightShapeFromValidatedCore(
    statement: statement_mod.RiscVStatement,
    pcs_config: stwo_core.pcs.PcsConfig,
    max_wire_bytes: usize,
) Error!postcard.proof_preflight.Shape {
    var maximum_log_size: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        maximum_log_size = @max(maximum_log_size, descriptor.log_size);
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        maximum_log_size = @max(maximum_log_size, descriptor.log_size);
    }

    const composition_columns = verifier_types.compositionColumnCount(
        verifier_types.COMPOSITION_LOG_SPLIT,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidProofShape;

    return .{
        .config = .{
            .pow_bits = pcs_config.pow_bits,
            .log_blowup_factor = pcs_config.fri_config.log_blowup_factor,
            .n_queries = pcs_config.fri_config.n_queries,
            .log_last_layer_degree_bound = pcs_config.fri_config.log_last_layer_degree_bound,
            .fold_step = pcs_config.fri_config.fold_step,
            .lifting_log_size = pcs_config.lifting_log_size,
        },
        .tree_columns = .{
            statement.nPreprocessedColumns(),
            statement.nMainColumns(),
            statement.nInteractionColumns(),
            std.math.cast(u32, composition_columns) orelse
                return error.InvalidProofShape,
        },
        .max_column_log_size = maximum_log_size,
        .hash_size = @sizeOf(engine.Hasher.Hash),
        .hash_encoding = .canonical_m31_words,
        .max_wire_bytes = max_wire_bytes,
    };
}

/// V2 keeps the native proof geometry in its authenticated compatibility
/// projection while replacing the public statement transcript. Both layers
/// are revalidated before that projection is allowed to size external bytes.
pub fn preflightShapeV2(
    statement: *const statement_v2.RiscVStatementV2,
    max_wire_bytes: usize,
) Error!postcard.proof_preflight.Shape {
    return preflightShapeV2ForVerifierConfig(
        statement,
        protocol.PCS_CONFIG,
        max_wire_bytes,
    );
}

pub fn preflightShapeV2ForVerifierConfig(
    statement: *const statement_v2.RiscVStatementV2,
    pcs_config: stwo_core.pcs.PcsConfig,
    max_wire_bytes: usize,
) Error!postcard.proof_preflight.Shape {
    if (max_wire_bytes == 0) return error.InvalidProofResourceLimit;
    try statement_validation.validateV2(statement, .proof);
    return preflightShapeFromValidatedCore(
        statement.core,
        pcs_config,
        max_wire_bytes,
    );
}

/// Derive the same V2 proof shape after authenticating an exact heterogeneous
/// external-retirement supplement. The ordinary entry point above remains
/// closed: only an extension owner that supplies the independently validated
/// row and memory-relation totals can admit a joined statement here.
pub fn preflightShapeV2WithRetirementSupplementV2ForVerifierConfig(
    statement: *const statement_v2.RiscVStatementV2,
    supplement: RetirementSupplementV2,
    pcs_config: stwo_core.pcs.PcsConfig,
    max_wire_bytes: usize,
) Error!postcard.proof_preflight.Shape {
    if (max_wire_bytes == 0) return error.InvalidProofResourceLimit;
    if (supplement.rows == 0) {
        if (supplement.extra_memory_terms != 0 or
            supplement.expected_memory_relation_terms != 0)
        {
            return error.InvalidStatement;
        }
        try statement_validation.validateV2(statement, .proof);
    } else {
        try statement_validation.validateV2WithRetirementSupplementV2(
            statement,
            .proof,
            supplement,
        );
    }
    return preflightShapeFromValidatedCore(
        statement.core,
        pcs_config,
        max_wire_bytes,
    );
}

/// Allocation-free validation of one external Poseidon proof wire.
pub fn validate(
    raw: []const u8,
    statement: statement_mod.RiscVStatement,
    max_wire_bytes: usize,
) Error!void {
    try validateForVerifierConfig(
        raw,
        statement,
        protocol.PCS_CONFIG,
        max_wire_bytes,
    );
}

/// Allocation-free validation under an explicitly verifier-owned candidate
/// profile.  The ordinary V1 entry point above remains frozen.
pub fn validateForVerifierConfig(
    raw: []const u8,
    statement: statement_mod.RiscVStatement,
    pcs_config: stwo_core.pcs.PcsConfig,
    max_wire_bytes: usize,
) Error!void {
    const shape = try preflightShapeForVerifierConfig(
        statement,
        pcs_config,
        max_wire_bytes,
    );
    try postcard.proof_preflight.validate(raw, shape);
}

/// Allocation-free validation of one external native V2 proof. No decoder
/// allocation is reachable until both the V2 authority and exact wire shape
/// have been authenticated.
pub fn validateV2(
    raw: []const u8,
    statement: *const statement_v2.RiscVStatementV2,
    max_wire_bytes: usize,
) Error!void {
    try validateV2ForVerifierConfig(
        raw,
        statement,
        protocol.PCS_CONFIG,
        max_wire_bytes,
    );
}

pub fn validateV2ForVerifierConfig(
    raw: []const u8,
    statement: *const statement_v2.RiscVStatementV2,
    pcs_config: stwo_core.pcs.PcsConfig,
    max_wire_bytes: usize,
) Error!void {
    const shape = try preflightShapeV2ForVerifierConfig(
        statement,
        pcs_config,
        max_wire_bytes,
    );
    try postcard.proof_preflight.validate(raw, shape);
}

comptime {
    if (engine.Hasher.Hash != [8]u32)
        @compileError("recursive proof ingress assumes eight canonical M31 hash words");
    if (@sizeOf(engine.Hasher.Hash) != 32)
        @compileError("recursive proof ingress hash width drifted");
}
