const std = @import("std");
const P = @import("security_policy.zig");

fn candidate() P.Profile {
    var p = P.benchmarkControl();
    p.protocol = .unimplemented_128_candidate_v1;
    p.recursive_inner_transcript = .unimplemented_reviewed_128_hash;
    p.algebra = .independent_whole_algebraic_repetition;
    p.independent_repetitions = 2;
    p.covers_all_algebraic_arguments = true;
    p.budget.terms = @splat(.{ .error_at_most_2_neg_bits = 132 });
    return p;
}
test "security policy preserves exact benchmark control without whole128 claim" {
    try P.requireClaim(P.benchmarkControl(), .nominal_control_only_v1, .benchmark_control_only);
    try std.testing.expectError(error.UnreviewedReducedTranscriptBound, P.requireClaim(P.benchmarkControl(), .nominal_control_only_v1, .whole_protocol_128));
}
test "security policy rejects relabeled q-only profiles even with larger PoW" {
    var p = candidate();
    p.queries = 102;
    p.query_pow_bits = 64;
    p.algebra = .single_qm31;
    try std.testing.expectError(error.IncompleteAlgebraicSecurityCoverage, P.requireClaim(p, .nominal_control_only_v1, .whole_protocol_128));
}
test "security policy rejects GKR-only repetitions with global and OODS left single" {
    var p = candidate();
    p.algebra = .gkr_only_repetition;
    p.independent_repetitions = 16;
    try std.testing.expectError(error.IncompleteAlgebraicSecurityCoverage, P.requireClaim(p, .none, .whole_protocol_128));
}
test "security policy distinguishes reduced inner FS from unreduced Merkle commitments" {
    var p = candidate();
    p.recursive_inner_transcript = .blake2s_eight_m31_words;
    try std.testing.expectEqual(P.Hash.blake2s_256, p.recursive_inner_merkle);
    try std.testing.expectError(error.UnreviewedReducedTranscriptBound, P.requireCandidate128Conditions(p));
}
test "security policy Poseidon digest8 remains below target wherever selected" {
    inline for (.{ "native_merkle", "recursive_inner_merkle", "recursive_root_merkle" }) |field| {
        var p = candidate();
        @field(p, field) = .poseidon2_m31_width16_rate8_digest8;
        try std.testing.expectError(error.CommitmentCollisionCeilingBelowTarget, P.requireCandidate128Conditions(p));
    }
}
test "security policy unknown arguments fail closed before certificate gate" {
    var p = candidate();
    for (0..P.ARGUMENT_COUNT) |i| {
        p.budget.terms[i] = .unknown;
        try std.testing.expectError(error.UnboundedSecurityTerm, P.requireCandidate128Conditions(p));
        p.budget.terms[i] = .{ .error_at_most_2_neg_bits = 132 };
    }
}
test "security policy union error is not weakest term security" {
    var p = candidate();
    p.budget.terms = @splat(.{ .error_at_most_2_neg_bits = 128 });
    try std.testing.expectError(error.InsufficientUnionBound, P.requireCandidate128Conditions(p));
    p.budget.terms = @splat(.{ .error_at_most_2_neg_bits = 132 });
    try P.requireCandidate128Conditions(p);
}
test "security policy numeric budgets cannot manufacture reviewed authority" {
    var p = candidate();
    p.budget.terms = @splat(.{ .error_at_most_2_neg_bits = 4096 });
    inline for (std.meta.tags(P.Certificate)) |certificate|
        try std.testing.expectError(error.NoReviewedWholeProtocol128Certificate, P.requireClaim(p, certificate, .whole_protocol_128));
}
test "security policy repetitions need complete coverage and conditional independence review" {
    var p = candidate();
    p.covers_all_algebraic_arguments = false;
    try std.testing.expectError(error.IncompleteAlgebraicSecurityCoverage, P.requireCandidate128Conditions(p));
    p.covers_all_algebraic_arguments = true;
    p.independent_repetitions = 1;
    try std.testing.expectError(error.IncompleteAlgebraicSecurityCoverage, P.requireCandidate128Conditions(p));
}
test "security policy wider field is a candidate not a certificate" {
    var p = candidate();
    p.algebra = .wider_secure_field;
    p.secure_extension_degree = 4;
    try std.testing.expectError(error.IncompleteAlgebraicSecurityCoverage, P.requireCandidate128Conditions(p));
    p.secure_extension_degree = 8;
    try P.requireCandidate128Conditions(p);
    try std.testing.expectError(error.NoReviewedWholeProtocol128Certificate, P.requireClaim(p, .none, .whole_protocol_128));
}
test "security policy query grind cannot impersonate phase-specific grinding" {
    var p = candidate();
    p.algebra = .phase_specific_grinding;
    p.query_pow_bits = 64;
    try std.testing.expectError(error.IncompleteAlgebraicSecurityCoverage, P.requireCandidate128Conditions(p));
    p.pre_challenge_grinding_implemented = true;
    try std.testing.expectError(error.NoReviewedWholeProtocol128Certificate, P.requireClaim(p, .none, .whole_protocol_128));
}
test "security policy budget rejects empty invalid and missing bound terms" {
    var b: P.Budget = .{};
    try std.testing.expectError(error.UnboundedSecurityTerm, b.requireUnionBound(128));
    b.terms = @splat(.not_used);
    try std.testing.expectError(error.EmptySecurityBudget, b.requireUnionBound(128));
    b.terms[0] = .{ .error_at_most_2_neg_bits = 0 };
    try std.testing.expectError(error.InvalidSecurityBound, b.requireUnionBound(128));
    b.terms[0] = .{ .error_at_most_2_neg_bits = 128 };
    try b.requireUnionBound(128);
    try std.testing.expectError(error.InvalidSecurityTarget, b.requireUnionBound(0));
}
test "security policy no producer mutation of nominal control is admitted" {
    var p = P.benchmarkControl();
    p.queries += 1;
    try std.testing.expectError(error.UnrecognizedBenchmarkControl, P.requireClaim(p, .nominal_control_only_v1, .benchmark_control_only));
    try std.testing.expectError(error.UnrecognizedBenchmarkControl, P.requireClaim(P.benchmarkControl(), .none, .benchmark_control_only));
}
test "security policy bounded profile parameters reject malformed candidates" {
    var p = candidate();
    p.independent_repetitions = 17;
    try std.testing.expectError(error.InvalidSecurityProfile, P.requireCandidate128Conditions(p));
    p = candidate();
    p.queries = 0;
    try std.testing.expectError(error.InvalidSecurityProfile, P.requireCandidate128Conditions(p));
}

test "single-draw M31 field-size bound refuses nominal 128 bits for QM31 even at degree one" {
    // (2^31-1)^4 is strictly below 2^124; increasing query PoW does
    // not strengthen the independent algebraic field draw.
    try std.testing.expectError(error.SingleDrawAlgebraicBudgetInsufficient, P.requireSingleDrawAlgebraicBudget(4, 1, 128));
    try std.testing.expectError(error.SingleDrawAlgebraicBudgetInsufficient, P.requireSingleDrawAlgebraicBudget(4, 1, 124));
    try P.requireSingleDrawAlgebraicBudget(4, 1, 123);
    // A degree-eight extension is a mathematical candidate, not a reviewed
    // protocol: the receiver-owned certificate gate still rejects whole128.
    try P.requireSingleDrawAlgebraicBudget(8, 1 << 24, 132);
    try std.testing.expectError(error.NoReviewedWholeProtocol128Certificate, P.requireClaim(candidate(), .none, .whole_protocol_128));
}
test "single-draw algebraic budget scales by actual polynomial degree and rejects nonsensical bounds" {
    try std.testing.expectError(error.SingleDrawAlgebraicBudgetInsufficient, P.requireSingleDrawAlgebraicBudget(4, 1 << 24, 123));
    try P.requireSingleDrawAlgebraicBudget(4, 1 << 24, 99);
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireSingleDrawAlgebraicBudget(0, 1, 128));
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireSingleDrawAlgebraicBudget(4, 0, 128));
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireSingleDrawAlgebraicBudget(4, 1, 0));
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireSingleDrawAlgebraicBudget(17, 1, 128));
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireSingleDrawAlgebraicBudget(8, 1, 257));
}

fn conditionalTerms() [P.ARGUMENT_COUNT]P.ConditionalTerm {
    var out: [P.ARGUMENT_COUNT]P.ConditionalTerm = undefined;
    inline for (std.meta.tags(P.Argument), 0..) |tag, i| {
        out[i] = .{ .argument = tag, .max_degree = 1, .draws = 1 };
    }
    return out;
}

test "conditional algebraic union model exposes insufficiency of QM31 even for one draw per phase" {
    const terms = conditionalTerms();
    try std.testing.expectError(error.ConditionalAlgebraicBudgetInsufficient, P.requireConditionalAlgebraicBudget(4, &terms, 128));
    const wider = try P.requireConditionalAlgebraicBudget(8, &terms, 128);
    try std.testing.expectEqual(@as(u512, P.ARGUMENT_COUNT), wider.total_degree_weight);
    try std.testing.expectEqual(@as(u16, 128), wider.requested_bits);
    try std.testing.expect(wider.field_size > wider.total_degree_weight);
    // The conditional union check never promotes a new whole-protocol
    // certificate, even when the arithmetic inequality happens to hold.
    try std.testing.expectError(error.NoReviewedWholeProtocol128Certificate, P.requireClaim(candidate(), .none, .whole_protocol_128));
}

test "conditional algebraic budget requires every proof argument to be accounted for exactly once" {
    var terms = conditionalTerms();
    try std.testing.expectError(error.MissingAlgebraicArguments, P.requireConditionalAlgebraicBudget(8, terms[0 .. terms.len - 1], 128));
    terms[1].argument = terms[0].argument;
    try std.testing.expectError(error.DuplicateAlgebraicArgument, P.requireConditionalAlgebraicBudget(8, &terms, 128));
    terms = conditionalTerms();
    terms[3].applicable = false;
    try std.testing.expectError(error.InvalidConditionalTerm, P.requireConditionalAlgebraicBudget(8, &terms, 128));
    terms[3].max_degree = 0;
    terms[3].draws = 0;
    _ = try P.requireConditionalAlgebraicBudget(8, &terms, 128);
    for (&terms) |*term| {
        term.applicable = false;
        term.max_degree = 0;
        term.draws = 0;
    }
    try std.testing.expectError(error.EmptyAlgebraicBudget, P.requireConditionalAlgebraicBudget(8, &terms, 128));
}

test "conditional algebraic budget uses exact total degree times repetitions, not post-challenge PoW" {
    var terms = conditionalTerms();
    terms[0].draws = 10000;
    terms[0].max_degree = 1 << 24;
    const estimate = try P.requireConditionalAlgebraicBudget(8, &terms, 128);
    try std.testing.expect(estimate.total_degree_weight > @as(u512, 10000) * (1 << 24));
    try std.testing.expectError(error.ConditionalAlgebraicBudgetInsufficient, P.requireConditionalAlgebraicBudget(4, &terms, 120));
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireConditionalAlgebraicBudget(0, &terms, 128));
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireConditionalAlgebraicBudget(8, &terms, 257));
}

fn moduloTerms() [P.ARGUMENT_COUNT]P.ConditionalTerm {
    var terms: [P.ARGUMENT_COUNT]P.ConditionalTerm = undefined;
    inline for (std.meta.tags(P.Argument), 0..) |argument, i| terms[i] = .{ .argument = argument, .applicable = false, .max_degree = 0, .draws = 0 };
    return terms;
}

test "raw modulo budget counts the exact maximum raw preimages" {
    var terms = moduloTerms();
    terms[@intFromEnum(P.Argument.local_logup)] = .{ .argument = .local_logup, .max_degree = 1 << 27, .draws = 1 };
    _ = try P.requireRawModuloConditionalBudget(4, &terms, 94);
    try std.testing.expectError(error.ConditionalAlgebraicBudgetInsufficient, P.requireRawModuloConditionalBudget(4, &terms, 95));
    const wide = try P.requireRawModuloConditionalBudget(8, &terms, 216);
    try std.testing.expectEqual(@as(u512, 6561), wide.max_preimages_per_element);
    try std.testing.expectEqual(@as(u16, 256), wide.raw_bits);
    try std.testing.expectError(error.ConditionalAlgebraicBudgetInsufficient, P.requireRawModuloConditionalBudget(8, &terms, 217));
    try std.testing.expectError(error.ConditionalAlgebraicBudgetInsufficient, P.requireRawModuloConditionalBudget(4, &terms, 128));
}

test "raw modulo budget includes every declared argument and conditional draw" {
    var terms = moduloTerms();
    for (&terms) |*term| {
        term.applicable = true;
        term.max_degree = 1 << 27;
        term.draws = 1;
    }
    _ = try P.requireRawModuloConditionalBudget(8, &terms, 212);
    try std.testing.expectError(error.ConditionalAlgebraicBudgetInsufficient, P.requireRawModuloConditionalBudget(8, &terms, 213));
    try std.testing.expectError(error.MissingAlgebraicArguments, P.requireRawModuloConditionalBudget(8, terms[0 .. terms.len - 1], 128));
    terms[1].argument = terms[0].argument;
    try std.testing.expectError(error.DuplicateAlgebraicArgument, P.requireRawModuloConditionalBudget(8, &terms, 128));
}

test "raw modulo budget fails closed at empty unsupported and maximum inputs" {
    var terms = moduloTerms();
    try std.testing.expectError(error.EmptyAlgebraicBudget, P.requireRawModuloConditionalBudget(8, &terms, 128));
    try std.testing.expectError(error.InvalidAlgebraicBudget, P.requireRawModuloConditionalBudget(16, &terms, 128));
    for (&terms) |*term| {
        term.applicable = true;
        term.max_degree = std.math.maxInt(u64);
        term.draws = std.math.maxInt(u64);
    }
    try std.testing.expectError(error.ConditionalAlgebraicBudgetInsufficient, P.requireRawModuloConditionalBudget(8, &terms, 256));
}
