const std = @import("std");
const core = @import("stwo_core");
const C = @import("om31_security_candidate.zig");
test "assumption qualified target is explicit metadata and cannot authorize certification" {
    try std.testing.expectEqualStrings("128-bit security target under documented assumptions", C.ASSUMPTION_TARGET.label);
    try std.testing.expectEqual(@as(u16, 128), C.ASSUMPTION_TARGET.target_bits);
    try std.testing.expect(C.ASSUMPTION_TARGET.bounded_engineering_review_complete);
    try std.testing.expect(!C.ASSUMPTION_TARGET.independent_security_audit_complete);
    try std.testing.expect(!C.ASSUMPTION_TARGET.whole_protocol_128_certified);
    try std.testing.expectError(error.Om31CandidateReviewIncomplete, C.requireWholeProtocolPromotion(.{}));
}
test "candidate pins receiver configuration sampler and scope identity" {
    try C.requireParameters(C.config());
    try C.requireIdentity(C.identity());
    var changed = C.identity();
    changed[0] ^= 1;
    try std.testing.expectError(error.UnrecognizedOm31CandidateIdentity, C.requireIdentity(changed));
    var cfg = C.config();
    cfg.fri_config.log_blowup_factor = 1;
    try std.testing.expectError(error.UnrecognizedOm31CandidateParameters, C.requireParameters(cfg));
    cfg = C.config();
    cfg.fri_config.n_queries = 70;
    try std.testing.expectError(error.UnrecognizedOm31CandidateParameters, C.requireParameters(cfg));
    cfg = C.config();
    cfg.pow_bits = 26;
    try std.testing.expectError(error.UnrecognizedOm31CandidateParameters, C.requireParameters(cfg));
    try C.admitNative(C.O, C.Channel, C.Hasher, C.config(), C.identity(), C.Facts.caps());
    try std.testing.expectError(error.UnrecognizedOm31CandidateAuthorities, C.admitNative(core.fields.qm31.QM31, C.Channel, C.Hasher, C.config(), C.identity(), C.Facts.caps()));
    try C.requireBenchmarkControlUnchanged();
    try std.testing.expect(C.Channel.SecureField == core.fields.om31.OM31);
}
test "candidate conditional complete-native ledger fits admitted cap but is never certificate" {
    const f = C.Facts.caps();
    const ledger = try C.ledger(f);
    try std.testing.expectEqual(C.Basis.unreviewed_fri_envelope, C.basis(.fri_folding));
    try std.testing.expectEqual(C.Basis.circle_pcs_theorem_required, C.basis(.deep_batching));
    try std.testing.expectEqual(C.Basis.binding_theorem_required, C.basis(.gkr_late_binding));
    for (ledger.degree_weight) |weight| try std.testing.expect(weight > 0);
    std.debug.print("OM31_SECURITY_CANDIDATE identity={x} conditional_weight={d}\n", .{ C.identity(), try ledger.total() });
    try ledger.requireRawModuloBits(151);
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, ledger.requireRawModuloBits(248));
    try C.requireQueryBits(f, 151);
    try std.testing.expectError(error.Om31CandidateQueryBudgetInsufficient, C.requireQueryBits(f, 200));
    try C.requireConditionalRomBudget(f, 120);
    try std.testing.expectError(error.Om31CandidateUnreviewedWorkRange, C.requireConditionalRomBudget(f, 128));
    try std.testing.expectError(error.Om31CandidateReviewIncomplete, C.requireWholeProtocolPromotion(.{}));
    var reviews = C.Reviews{};
    inline for (@typeInfo(C.Reviews).@"struct".fields) |field| @field(reviews, field.name) = true;
    try std.testing.expectError(error.NoReviewedWholeProtocol128Certificate, C.requireWholeProtocolPromotion(reviews));
}
test "candidate rejects characteristic wrap geometry and oversized source scope" {
    var f = C.Facts.caps();
    f.max_positive_mass = core.fields.m31.Modulus;
    try std.testing.expectError(error.Om31CandidateCharacteristicBoundExceeded, C.ledger(f));
    f = C.Facts.caps();
    f.max_negative_mass = core.fields.m31.Modulus;
    try std.testing.expectError(error.Om31CandidateCharacteristicBoundExceeded, C.ledger(f));
    f = C.Facts.caps();
    f.max_multiplicity = core.fields.m31.Modulus;
    try std.testing.expectError(error.Om31CandidateCharacteristicBoundExceeded, C.ledger(f));
    f = C.Facts.caps();
    f.native_proofs += 1;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, C.ledger(f));
    f = C.Facts.caps();
    f.max_gkr_variables += 1;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, C.ledger(f));
    f = C.Facts.caps();
    f.transcript_rounds += 1;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, C.ledger(f));
}
test "candidate binds receiver facts to native raw transcript before dependent challenges" {
    var first = C.Channel.init();
    var second = C.Channel.init();
    try C.begin(&first, C.Facts.caps());
    var f = C.Facts.caps();
    f.native_proofs -= 1;
    try C.begin(&second, f);
    try std.testing.expect(!std.mem.eql(u8, &first.digestBytes(), &second.digestBytes()));
    try std.testing.expect(!first.drawSecureFelt().eql(second.drawSecureFelt()));
}

test "candidate local relation roster matches production raw fraction authority" {
    const actual = @import("../word16_global_execution/services/gkr_local/fractions.zig").Relation;
    try std.testing.expectEqual(C.LOCAL_RELATIONS, @typeInfo(actual).@"enum".fields.len);
}

test "candidate arithmetic rejects arbitrary overflowing budget values" {
    var l = C.Ledger{ .degree_weight = @splat(std.math.maxInt(u512)) };
    try std.testing.expectError(error.Om31CandidateBudgetOverflow, l.requireRawModuloBits(128));
    l.degree_weight = @splat(0);
    l.degree_weight[0] = std.math.maxInt(u512);
    try std.testing.expectError(error.Om31CandidateBudgetOverflow, l.requireRawModuloBits(128));
}

test "candidate raw modulo exact integer entropy and union threshold reject uniform substitution" {
    const sampler = core.channel.raw_mod_m31;
    try std.testing.expectEqual(@as(u32, 8), sampler.om31_profile.degree);
    try std.testing.expectEqual(@as(u32, 3), sampler.MAX_PREIMAGES);
    try std.testing.expectEqual(@as(u64, 1) << 32, sampler.RAW_ORDER);
    var max_preimages: u512 = 1;
    var field_order: u512 = 1;
    for (0..sampler.om31_profile.degree) |_| {
        max_preimages *= sampler.MAX_PREIMAGES;
        field_order *= core.fields.m31.Modulus;
    }
    try std.testing.expectEqual(@as(u512, 6561), max_preimages);
    // Point mass is exactly6561/2^256 under a fresh uniform256-bit RO block.
    // This establishes floor(min-entropy)=243 without floating-point logs.
    try std.testing.expect(max_preimages << 243 <= @as(u512, 1) << 256);
    try std.testing.expect(max_preimages << 244 > @as(u512, 1) << 256);
    var l = C.Ledger{ .degree_weight = @splat(0) };
    l.degree_weight[0] = 1;
    try l.requireRawModuloBits(243);
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, l.requireRawModuloBits(244));
    // Exact density over uniform OM31 is (3*p)^8/2^256, strictly between1
    // and(3/2)^8. The latter comparison uses integers with no rounded bits.
    const density_numerator = max_preimages * field_order;
    try std.testing.expect(density_numerator > @as(u512, 1) << 256);
    try std.testing.expect(density_numerator * 256 < max_preimages * (@as(u512, 1) << 256));
    // Largest union weight admitted at128bits, then one beyond it. The latter
    // still passes a WRONG uniform-field calculation: pin this regression.
    l.degree_weight[0] = (@as(u512, 1) << 128) / max_preimages;
    try l.requireRawModuloBits(128);
    l.degree_weight[0] += 1;
    try std.testing.expect(l.degree_weight[0] << 128 <= field_order);
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, l.requireRawModuloBits(128));
}

// ---- M7 candidate profiles (stream profiles, off by default) ----
test "m7 candidate profiles are 128 conjectured bits, never weaker under Johnson, off by default" {
    const baseline = C.baselineJohnsonBitsTimes2();
    try std.testing.expectEqual(@as(u32, 148), baseline);
    for (C.CANDIDATE_PROFILES, 0..) |p, k| {
        const s = C.candidateSpec(p);
        // ethSTARK conjecture: log_blowup * queries + pow == 128 exactly (no over/under-provisioning).
        try std.testing.expectEqual(@as(u32, 128), C.candidateConjecturedBits(p));
        try std.testing.expectEqual(@as(u32, 128), s.log_blowup * s.queries + s.pow_bits);
        // Weaker (Johnson, sqrt(rho)) regime: no candidate below today's native default.
        try std.testing.expect(C.candidateJohnsonBitsTimes2(p) >= baseline);
        // Config is a valid FRI config with the declared log2 fold arity.
        const c = C.candidateConfig(p);
        try std.testing.expectEqual(s.log_blowup, c.fri_config.log_blowup_factor);
        try std.testing.expectEqual(@as(usize, s.queries), c.fri_config.n_queries);
        try std.testing.expectEqual(s.fold_step, c.fri_config.fold_step);
        try std.testing.expect(s.fold_step >= 3 and s.fold_step <= 4);
        // OFF BY DEFAULT: not an admitted native profile, not parseable, not the default.
        try C.requireCandidateNotAdmitted(p);
        try std.testing.expectError(error.UnknownOm31CandidateProfile, C.Profile.parse(p.name()));
        for (C.PROFILES) |admitted| {
            try std.testing.expect(!std.meta.eql(C.configFor(admitted), c));
            try std.testing.expect(!std.mem.eql(u8, &C.profileIdentity(admitted), &C.candidateIdentity(p)));
        }
        // Distinct identities and domains across candidates.
        for (C.CANDIDATE_PROFILES[k + 1 ..]) |q| {
            try std.testing.expect(!std.mem.eql(u8, &C.candidateIdentity(p), &C.candidateIdentity(q)));
            try std.testing.expect(!std.mem.eql(u8, s.domain, C.candidateSpec(q).domain));
        }
    }
    try std.testing.expectEqual(C.Profile.conjectured128_b2_q108_p20_fold4, C.DEFAULT_PROFILE);
    try std.testing.expectEqual(@as(usize, 2), C.PROFILES.len);
}
test "m7 candidate layers pin plan parameters (D2, recsize outer, C1, C2 fold 8/16)" {
    const d2 = C.candidateSpec(.d2_native_b4_q54_p20_fold4);
    try std.testing.expectEqual(C.Layer.native, d2.layer);
    try std.testing.expectEqual(@as(u32, 2), d2.log_blowup);
    try std.testing.expectEqual(@as(u32, 54), d2.queries);
    // D2 differs from today's native only in rate and query count (same pow, fold, last layer).
    const today = C.configFor(.conjectured128_b2_q108_p20_fold4);
    const d2c = C.candidateConfig(.d2_native_b4_q54_p20_fold4);
    try std.testing.expectEqual(today.pow_bits, d2c.pow_bits);
    try std.testing.expectEqual(today.fri_config.fold_step, d2c.fri_config.fold_step);
    try std.testing.expectEqual(today.fri_config.log_last_layer_degree_bound, d2c.fri_config.log_last_layer_degree_bound);
    // Outer m3 = recsize 5d68d0f01 protocol.zig `m3_b4_q51_p26_fold4` (blowup 2^2, 51 q, 26 pow, fold 4, same domain string).
    const m3 = C.candidateSpec(.m3_outer_b4_q51_p26_fold4);
    try std.testing.expectEqual(C.Layer.outer, m3.layer);
    try std.testing.expectEqual(@as(u32, 2), m3.log_blowup);
    try std.testing.expectEqual(@as(u32, 51), m3.queries);
    try std.testing.expectEqual(@as(u32, 26), m3.pow_bits);
    try std.testing.expectEqual(@as(u32, 4), m3.fold_step);
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m3-b4-q51-p26-fold4/lens-v1", m3.domain);
    const c1 = C.candidateSpec(.c1_b8_q36_p20_fold4);
    try std.testing.expectEqual(C.Layer.compress1, c1.layer);
    try std.testing.expectEqual(@as(u32, 3), c1.log_blowup);
    // C2: fold_step is log2 arity: 3 -> 8-to-1, 4 -> 16-to-1 per FRI layer.
    const c2a = C.candidateSpec(.c2_b16_q27_p20_fold3);
    const c2b = C.candidateSpec(.c2_b16_q27_p20_fold4);
    try std.testing.expectEqual(@as(u32, 4), c2a.log_blowup);
    try std.testing.expectEqual(@as(u32, 8), @as(u32, 1) << @intCast(c2a.fold_step));
    try std.testing.expectEqual(@as(u32, 16), @as(u32, 1) << @intCast(c2b.fold_step));
    // FRI layer count for a 2^20-row C2 trace: ceil(20/3)=7 vs ceil(20/4)=5 (core nFoldSteps rule).
    try std.testing.expectEqual(@as(usize, 7), core.fri.nFoldSteps(20, c2a.fold_step));
    try std.testing.expectEqual(@as(usize, 5), core.fri.nFoldSteps(20, c2b.fold_step));
}
test "m7 outer LogUp-GKR ledger: OM31 challenges clear 128+23 bits at caps, QM31 would not" {
    const caps = C.OuterGkrFacts.caps();
    // Same reserve as requireConditionalRomBudget: TARGET + 2 (category union) + 21 (round cap).
    try C.requireOuterGkrBits(caps, C.TARGET_BITS + 2 + 21);
    try C.requireOuterGkrBits(caps, 191); // [D] 191.3 bits at caps
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, C.requireOuterGkrBits(caps, 192));
    // QM31 challenges: 72.0 bits at caps; 87.4 at a realistic M7 request
    // (40 outer proofs, 16 instances, 2^24 rows, arity 8). Both below 128.
    try C.requireOuterGkrBitsQm31(caps, 71);
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, C.requireOuterGkrBitsQm31(caps, 73));
    const real = C.OuterGkrFacts{ .outer_proofs = 40, .instances = 16, .max_variables = 24, .max_tuple_arity = 8 };
    try C.requireOuterGkrBits(real, 206);
    try C.requireOuterGkrBitsQm31(real, 87);
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, C.requireOuterGkrBitsQm31(real, 88));
    var bad = caps;
    bad.max_variables = C.MAX_GKR_VARIABLES + 1;
    try std.testing.expectError(error.Om31CandidateScopeExceeded, C.requireOuterGkrBits(bad, 128));
}
test "m7 outer LogUp characteristic bound: caps would wrap p, realistic M7 facts do not" {
    // Review 1: the field-size ledger says nothing about multiplicity wrap mod p.
    // At caps (128 instances x 2^30 rows feeding one relation) the conservative
    // mass is 2^37 >= p, so caps are NOT admissible without a measured
    // per-relation mass; the realistic M7 facts (16 x 2^24 = 2^28) are.
    const caps = C.OuterGkrFacts.caps();
    try std.testing.expectEqual(@as(u64, 1) << 37, try C.outerGkrMassBound(caps));
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireOuterGkrCharacteristic(caps, null));
    const real = C.OuterGkrFacts{ .outer_proofs = 40, .instances = 16, .max_variables = 24, .max_tuple_arity = 8 };
    try C.requireOuterGkrCharacteristic(real, null);
    // A measured per-relation mass overrides the conservative bound, and is itself bounded by p.
    try C.requireOuterGkrCharacteristic(caps, (@as(u64, 1) << 31) - 2);
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireOuterGkrCharacteristic(caps, (@as(u64, 1) << 31) - 1));
}
