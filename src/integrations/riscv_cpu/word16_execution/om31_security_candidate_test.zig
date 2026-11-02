const std = @import("std");
const core = @import("stwo_core");
const C = @import("om31_security_candidate.zig");
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
