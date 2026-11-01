//! Receiver-owned security-claim accounting, not a cryptographic verifier.
//! No whole-protocol 128-bit certificate is admitted by this authority yet.
//! The native benchmark suite and proof acceptance path are unchanged.
const std = @import("std");

pub const Claim = enum { benchmark_control_only, whole_protocol_128 };
pub const Protocol = enum { native_q70_p26_qm31_control_v1, unimplemented_128_candidate_v1 };
pub const Certificate = enum { none, nominal_control_only_v1 };
pub const Hash = enum {
    blake2s_256,
    blake2s_eight_m31_words,
    poseidon2_m31_width16_rate8_digest8,
    unimplemented_reviewed_128_hash,

    /// Generic collision-strength ceiling, not a lower-bound certificate.
    pub fn collisionBitsCeiling(self: Hash) u16 {
        return switch (self) {
            .blake2s_256, .unimplemented_reviewed_128_hash => 128,
            // (2^31-1)^8 < 2^248, so collision strength is strictly below124.
            .blake2s_eight_m31_words, .poseidon2_m31_width16_rate8_digest8 => 124,
        };
    }
};
pub const Algebra = enum {
    single_qm31,
    gkr_only_repetition,
    independent_whole_algebraic_repetition,
    wider_secure_field,
    phase_specific_grinding,
};

/// Every applicable term needs a bound. "not_used" also needs a reviewed
/// receiver-owned protocol identity; a producer may not delete a term.
pub const Argument = enum {
    tuple_fingerprinting,
    local_logup,
    global_ram_logup,
    service_io_logup,
    gkr_sumcheck_and_input_binding,
    constraint_composition,
    oods_identity,
    deep_batching,
    fri_folding,
    fri_queries,
    fiat_shamir_and_commitment_binding,
    recursive_verifier_and_outer_proofs,
};
pub const ARGUMENT_COUNT = @typeInfo(Argument).@"enum".fields.len;
pub const Bound = union(enum) {
    unknown,
    not_used,
    /// Claimed *total* upper bound for this term, including all relations,
    /// shards and recursion layers in scope. No PoW/repetition is inferred.
    error_at_most_2_neg_bits: u16,
};
pub const Budget = struct {
    terms: [ARGUMENT_COUNT]Bound = @splat(.unknown),

    /// Conservative dyadic union bound, no floating point or underflow.
    /// This checks accounting only; supplied numbers are not proof authority.
    pub fn requireUnionBound(self: Budget, target_bits: u16) !void {
        if (target_bits == 0 or target_bits > 512) return error.InvalidSecurityTarget;
        var used: u16 = 0;
        for (self.terms) |term| switch (term) {
            .unknown => return error.UnboundedSecurityTerm,
            .not_used => {},
            .error_at_most_2_neg_bits => |bits| {
                if (bits == 0 or bits > 4096) return error.InvalidSecurityBound;
                used += 1;
            },
        };
        if (used == 0) return error.EmptySecurityBudget;
        const union_margin = std.math.log2_int_ceil(u16, used);
        const needed = @as(u32, target_bits) + union_margin;
        for (self.terms) |term| switch (term) {
            .error_at_most_2_neg_bits => |bits| if (bits < needed) return error.InsufficientUnionBound,
            else => {},
        };
    }
};

pub const Profile = struct {
    protocol: Protocol,
    queries: u16,
    query_pow_bits: u8,
    secure_extension_degree: u8,
    algebra: Algebra,
    independent_repetitions: u8,
    // All false in the current control. These describe candidates only;
    // booleans cannot authorize a certificate at the final registry gate.
    covers_all_algebraic_arguments: bool,
    pre_challenge_grinding_implemented: bool,
    native_merkle: Hash,
    native_transcript: Hash,
    recursive_inner_merkle: Hash,
    recursive_inner_transcript: Hash,
    recursive_root_merkle: Hash,
    recursive_root_transcript: Hash,
    budget: Budget = .{},
};

pub fn benchmarkControl() Profile {
    return .{
        .protocol = .native_q70_p26_qm31_control_v1,
        .queries = 70,
        .query_pow_bits = 26,
        .secure_extension_degree = 4,
        .algebra = .single_qm31,
        .independent_repetitions = 1,
        .covers_all_algebraic_arguments = false,
        .pre_challenge_grinding_implemented = false,
        .native_merkle = .blake2s_256,
        .native_transcript = .blake2s_256,
        .recursive_inner_merkle = .blake2s_256,
        .recursive_inner_transcript = .blake2s_eight_m31_words,
        .recursive_root_merkle = .blake2s_256,
        .recursive_root_transcript = .blake2s_256,
    };
}

/// Only checks necessary architecture/accounting conditions; never certifies
/// the candidate. PoW at query sampling is deliberately absent from these
/// algebraic conditions because it is too late for earlier bad challenges.
pub fn requireCandidate128Conditions(profile: Profile) !void {
    if (profile.native_merkle.collisionBitsCeiling() < 128 or
        profile.recursive_inner_merkle.collisionBitsCeiling() < 128 or
        profile.recursive_root_merkle.collisionBitsCeiling() < 128)
        return error.CommitmentCollisionCeilingBelowTarget;
    // A reduced FS state is not a reduced Merkle commitment. Its generic
    // collision ceiling alone is not an end-to-end attack. Until an applicable
    // concrete ROM bound is reviewed, reject the *claim*, not current proofs;
    // this does not prescribe replacing the channel.
    if (profile.native_transcript.collisionBitsCeiling() < 128 or
        profile.recursive_inner_transcript.collisionBitsCeiling() < 128 or
        profile.recursive_root_transcript.collisionBitsCeiling() < 128)
        return error.UnreviewedReducedTranscriptBound;
    if (profile.queries == 0 or profile.queries > 4096 or
        profile.query_pow_bits > 64 or profile.independent_repetitions == 0 or
        profile.independent_repetitions > 16)
        return error.InvalidSecurityProfile;
    switch (profile.algebra) {
        .single_qm31, .gkr_only_repetition => return error.IncompleteAlgebraicSecurityCoverage,
        .independent_whole_algebraic_repetition => {
            if (profile.secure_extension_degree != 4 or profile.independent_repetitions < 2 or
                !profile.covers_all_algebraic_arguments)
                return error.IncompleteAlgebraicSecurityCoverage;
        },
        .wider_secure_field => {
            if (profile.secure_extension_degree < 8 or profile.secure_extension_degree > 16 or
                !profile.covers_all_algebraic_arguments)
                return error.IncompleteAlgebraicSecurityCoverage;
        },
        .phase_specific_grinding => {
            if (!profile.pre_challenge_grinding_implemented or !profile.covers_all_algebraic_arguments)
                return error.IncompleteAlgebraicSecurityCoverage;
        },
    }
    try profile.budget.requireUnionBound(128);
}

/// Certificate IDs are receiver-owned code authority, never inferred from a
/// bundle's numeric budget. There is intentionally no qualified128 registry
/// entry. Adding one requires protocol, formal-bound and recursion review.
pub fn requireClaim(profile: Profile, certificate: Certificate, claim: Claim) !void {
    switch (claim) {
        .benchmark_control_only => {
            if (certificate != .nominal_control_only_v1 or !std.meta.eql(profile, benchmarkControl()))
                return error.UnrecognizedBenchmarkControl;
        },
        .whole_protocol_128 => {
            try requireCandidate128Conditions(profile);
            return error.NoReviewedWholeProtocol128Certificate;
        },
    }
}
