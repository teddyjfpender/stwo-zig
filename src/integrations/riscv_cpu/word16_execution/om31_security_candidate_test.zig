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
    // M6 P4: the production roster is 10 (byte_pair, 63728c3f8). The admitted
    // identities keep hashing the FROZEN 9 (proof bytes of the M5 default), the
    // ledger counts the real 10, and every new native version hashes 10.
    const actual = @import("../word16_global_execution/services/gkr_local/fractions.zig").Relation;
    const roster: u64 = @typeInfo(actual).@"enum".fields.len;
    try std.testing.expectEqual(C.ROSTER_LOCAL_RELATIONS, roster);
    try std.testing.expectEqual(C.M5_LOCAL_RELATIONS, roster);
    try std.testing.expectEqual(@as(u64, 9), C.LOCAL_RELATIONS);
    for (C.FORMAT_VERSIONS) |v| {
        const s = C.formatSpec(v);
        if (s.layer == .native) try std.testing.expectEqual(roster, s.local_relations);
    }
    // The ledger's local-relation terms scale with the real roster: (p*10+3)/(p*9+3) for local_rational_identity.
    const f = C.Facts.caps();
    const l = try C.ledger(f);
    try std.testing.expectEqual(@as(u512, f.native_proofs) * roster * (@as(u512, f.max_positive_mass) + f.max_negative_mass), l.degree_weight[@intFromEnum(C.AlgebraicTerm.local_rational_identity)]);
}
test "admitted native identities are byte-identical to the M5 default (golden, proof-neutral M6 edits)" {
    try std.testing.expectEqualSlices(u8, &GOLDEN_PROVEN_IDENTITY, &C.identity());
    try std.testing.expectEqualSlices(u8, &GOLDEN_CONJECTURED_IDENTITY, &C.profileIdentity(.conjectured128_b2_q108_p20_fold4));
    try std.testing.expectEqualSlices(u8, &C.identity(), &C.profileIdentity(.proven_beta2_q256_p0_fold4));
    // M5 format identities did not move when the M6 composite fields were added.
    for (GOLDEN_M5_FORMATS, 0..) |g, k| try std.testing.expectEqualSlices(u8, &g, &C.formatIdentity(C.FORMAT_VERSIONS[k]));
}
fn hex32(comptime text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}
/// [M] computed 2026-11-05 on the pod from 95d40063d (M5 default) and this tree: equal.
const GOLDEN_PROVEN_IDENTITY = hex32("dd85fa95f35d7a3aaaadf301e53570cc8d5fea7cd8eef93a7b68377a30b59b91");
const GOLDEN_CONJECTURED_IDENTITY = hex32("55c37941b9b243ba910eb2044b6be3a27e4cd5e89df39ebf42e3a8d209a640b2");
const GOLDEN_M5_FORMATS = [_][32]u8{ hex32("5d6615e9dd6bb9f17e7049ec52f6d0980bdbe67941724f58bce93d3cf816b0e4"), hex32("869be851e35fabb84951b4b409f65497632be42e2bc11dc2bde28688e4656df4"), hex32("4f789cef16ee53487b2778f17fa6e92749122b8c123dedfc4e36d52b0c2d3c14"), hex32("378fbe1ac35fda12c7accde31d17116be3f12550c1fcf4ea9e2657fb488d8c58"), hex32("5f2b954cd46980232d5210bed0c38b6000d860c214815de2f29c9da58c4eaa68") };

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
    // M6 framing (rv64-m7-compress-profiles.md): no caps anywhere (net loss under the core multiproof [D]);
    // C2 stops FRI at degree 8 (log_last_layer 3): a 2^17 C2 trace folds a degree ratio of 14.
    for (C.CANDIDATE_PROFILES) |p| try std.testing.expectEqual(@as(u32, 0), C.candidateSpec(p).merkle_cap_log);
    try std.testing.expectEqual(@as(u32, 0), c1.log_last_layer);
    try std.testing.expectEqual(@as(u32, 3), c2a.log_last_layer);
    try std.testing.expectEqual(@as(u32, 3), C.candidateConfig(.c2_b16_q27_p20_fold3).fri_config.log_last_layer_degree_bound);
    try std.testing.expectEqual(@as(usize, 5), core.fri.nFoldSteps(17 - c2a.log_last_layer, c2a.fold_step));
    try std.testing.expectEqual(@as(usize, 4), core.fri.nFoldSteps(17 - c2b.log_last_layer, c2b.fold_step));
    // Binary Merkle only: arity 4 needs a new hasher and a new profile id.
    for (C.CANDIDATE_PROFILES) |p| try std.testing.expectEqual(@as(u32, 1), C.candidateSpec(p).merkle_arity_log);
    try std.testing.expect(!std.mem.eql(u8, &C.candidateIdentity(.c2_b16_q27_p20_fold3), &C.candidateIdentity(.c2_b16_q27_p20_fold4)));
    // M6 model picks: C2 b64 q18 (6*18 + 20 = 128, Johnson x2 18*6 + 40 = 148) and C1 b16 q27 (4*27 + 20 = 128, 148).
    const c2m = C.candidateSpec(.c2_b64_q18_p20_fold3);
    try std.testing.expectEqual(C.Layer.compress2, c2m.layer);
    try std.testing.expectEqual(@as(u32, 128), C.candidateConjecturedBits(.c2_b64_q18_p20_fold3));
    try std.testing.expectEqual(@as(u32, 148), C.candidateJohnsonBitsTimes2(.c2_b64_q18_p20_fold3));
    try std.testing.expectEqual(@as(u32, 3), c2m.fold_step);
    try std.testing.expectEqual(@as(u32, 3), c2m.log_last_layer);
    try std.testing.expectEqual(C.Layer.compress1, C.candidateSpec(.c1_b16_q27_p20_fold4).layer);
    try std.testing.expectEqual(@as(u32, 148), C.candidateJohnsonBitsTimes2(.c1_b16_q27_p20_fold4));
    // b64 is inside the core FRI config range (LOG_MAX_BLOWUP_FACTOR = 16).
    try std.testing.expectEqual(@as(u32, 6), C.candidateConfig(.c2_b64_q18_p20_fold3).fri_config.log_blowup_factor);
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

// ---- M5/M7 named format versions and NS reference models (stream profiles, review 2) ----
const ADMITTED_OUTER_DOMAINS = [_][]const u8{ "stwo/circuit/native-om31/q108-p20-fold4/lens-v1", "stwo/circuit/native-om31/m3-b4-q51-p26-fold4/lens-v1", "stwo/circuit/native-om31/m3-b8-q34-p26-fold4/lens-v1" };
test "m5 format versions keep 128 conjectured bits of their base PCS, distinct domains and identities, off by default" {
    const baseline = C.baselineJohnsonBitsTimes2();
    for (C.FORMAT_VERSIONS, 0..) |v, k| {
        const s = C.formatSpec(v);
        // Hand arithmetic: 1*108 + 20 = 2*51 + 26 = 128; Johnson x2: 108 + 40 = 148, 102 + 52 = 154.
        try std.testing.expectEqual(@as(u32, 128), C.formatConjecturedBits(v));
        try std.testing.expect(C.formatJohnsonBitsTimes2(v) >= baseline);
        try std.testing.expectEqual(@as(u32, 4), s.pcs.fold_step);
        // Its base PCS is an existing named profile: admitted native default, r1 outer, or the m3 candidate.
        switch (s.layer) {
            .native => {
                const today = C.configFor(C.DEFAULT_PROFILE);
                try std.testing.expectEqual(today.fri_config.log_blowup_factor, s.pcs.log_blowup);
                try std.testing.expectEqual(@as(u32, @intCast(today.fri_config.n_queries)), s.pcs.queries);
                try std.testing.expectEqual(today.pow_bits, s.pcs.pow_bits);
                // The M5 native version must not hash an identity with different caps under the old domain.
                try std.testing.expect(!std.mem.eql(u8, s.domain, C.CONJECTURED_ID_DOMAIN));
                try std.testing.expectEqual(@as(u64, 10), s.local_relations);
            },
            .outer => {
                const m3 = C.candidateSpec(.m3_outer_b4_q51_p26_fold4);
                const is_r1 = s.pcs.log_blowup == 1 and s.pcs.queries == 108 and s.pcs.pow_bits == 20;
                const is_m3 = s.pcs.log_blowup == m3.log_blowup and s.pcs.queries == m3.queries and s.pcs.pow_bits == m3.pow_bits;
                try std.testing.expect(is_r1 or is_m3);
                for (ADMITTED_OUTER_DOMAINS) |d| try std.testing.expect(!std.mem.eql(u8, s.domain, d));
            },
            else => return error.TestUnexpectedResult,
        }
        for (C.PROFILES) |admitted| try std.testing.expect(!std.mem.eql(u8, &C.profileIdentity(admitted), &C.formatIdentity(v)));
        for (C.CANDIDATE_PROFILES) |c| {
            try std.testing.expect(!std.mem.eql(u8, &C.candidateIdentity(c), &C.formatIdentity(v)));
            try std.testing.expect(!std.mem.eql(u8, C.candidateSpec(c).domain, s.domain));
        }
        for (C.FORMAT_VERSIONS[k + 1 ..]) |w| {
            try std.testing.expect(!std.mem.eql(u8, &C.formatIdentity(v), &C.formatIdentity(w)));
            try std.testing.expect(!std.mem.eql(u8, s.domain, C.formatSpec(w).domain));
        }
        // Off by default: not parseable as an admitted native profile.
        try std.testing.expectError(error.UnknownOm31CandidateProfile, C.Profile.parse(v.name()));
    }
    // Admitted registry untouched.
    try std.testing.expectEqual(@as(usize, 2), C.PROFILES.len);
    try std.testing.expectEqual(C.Profile.conjectured128_b2_q108_p20_fold4, C.DEFAULT_PROFILE);
}
test "m5 native format version hashes the production local relation count (fixes the 9-vs-10 drift)" {
    const actual = @import("../word16_global_execution/services/gkr_local/fractions.zig").Relation;
    try std.testing.expectEqual(C.M5_LOCAL_RELATIONS, @typeInfo(actual).@"enum".fields.len);
    try std.testing.expectEqual(C.M5_LOCAL_RELATIONS, C.formatSpec(.m5_native_chi_chain_v1_b2_q108_p20_fold4).local_relations);
}
test "m7 outer-gkr format version clears the GKR ledger at realistic facts and refuses caps on characteristic" {
    const real = C.OuterGkrFacts{ .outer_proofs = 40, .instances = 16, .max_variables = 24, .max_tuple_arity = 8 };
    var seen: usize = 0;
    for (C.FORMAT_VERSIONS) |v| {
        if (!C.formatSpec(v).outer_gkr) continue;
        seen += 1;
        try C.requireOuterGkrBits(real, C.TARGET_BITS + 2 + 21);
        try C.requireOuterGkrCharacteristic(real, null);
        try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireOuterGkrCharacteristic(C.OuterGkrFacts.caps(), null));
    }
    // m7_outer_gkr + the four M6 diet entries (r1, m3, two fold-v3 composites) + the staged gkr-setv2-kary entry.
    try std.testing.expectEqual(@as(usize, 6), seen);
}
test "recsize m3_b8 outer candidate: 3*34 + 26 = 128, Johnson x2 = 154" {
    try std.testing.expectEqual(@as(u32, 128), C.candidateConjecturedBits(.m3_outer_b8_q34_p26_fold4));
    try std.testing.expectEqual(@as(u32, 154), C.candidateJohnsonBitsTimes2(.m3_outer_b8_q34_p26_fold4));
    try std.testing.expectEqualStrings("stwo/circuit/native-om31/m3-b8-q34-p26-fold4/lens-v1", C.candidateSpec(.m3_outer_b8_q34_p26_fold4).domain);
}
test "corpus M09 outer GKR challenges must be OM31: QM31 draws fail the 128-bit gate at every fact set" {
    const real = C.OuterGkrFacts{ .outer_proofs = 40, .instances = 16, .max_variables = 24, .max_tuple_arity = 8 };
    for ([_]C.OuterGkrFacts{ C.OuterGkrFacts.caps(), real }) |f| {
        try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, C.requireOuterGkrBitsQm31(f, 124));
        try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, C.requireOuterGkrBitsQm31(f, 88));
        try C.requireOuterGkrBits(f, C.TARGET_BITS);
    }
}
test "reference Z04: NS mass folds as integers; two children of p-1 are refused, an M31 sum would hide it" {
    const p = core.fields.m31.Modulus;
    const big = [_]u64{ p - 1, 0, 0 };
    try std.testing.expectError(error.M5MassCharacteristicWrap, C.m5FoldMass(&.{ big, big }));
    // The field sum wraps to p - 2 < p: exactly the bug review 1 F6 names.
    try std.testing.expectEqual(@as(u64, p - 2), C.m5FieldMassForTesting(&.{ big, big })[0]);
    // Per-child canonical check, then integer sum.
    try std.testing.expectError(error.M5ChildMassNoncanonical, C.m5FoldMass(&.{ .{ p, 0, 0 }, .{ 0, 0, 0 } }));
    const ok = try C.m5FoldMass(&.{ .{ 1, 2, 3 }, .{ 4, 5, 6 }, .{ 7, 8, 9 }, .{ 10, 11, 12 } });
    try std.testing.expectEqual([_]u64{ 22, 26, 30 }, ok);
    try std.testing.expectError(error.M5FoldArity, C.m5FoldMass(&.{.{ 0, 0, 0 }}));
    // Caps arithmetic [D]: 256 CPU leaves with ls = 2^23 - 1 carry ram mass 2 * ls each: total about 2^32 > p.
    try std.testing.expect(256 * 2 * ((@as(u64, 1) << 23) - 1) > p);
}
test "reference L05: one-sided upper range check admits k = p - 1; two-sided refuses it" {
    const p: u32 = @intCast(core.fields.m31.Modulus);
    try std.testing.expect(C.m5LeafIndexAdmits(p - 1, false)); // MAX - 1 - (p - 1) = MAX in M31
    try std.testing.expect(!C.m5LeafIndexAdmits(p - 1, true));
    try std.testing.expect(C.m5LeafIndexAdmits(0, true));
    try std.testing.expect(C.m5LeafIndexAdmits(@intCast(C.MAX_PROOFS - 1), true));
    try std.testing.expect(!C.m5LeafIndexAdmits(@intCast(C.MAX_PROOFS), true));
}
test "reference BG08: fused Blake2s byte-XOR lookup mass at census sizes stays far below p" {
    // Byte-XOR model: 10 rounds x 8 G x 4 xors x 4 bytes + final 16 xors x 4 bytes = 1344 per compression.
    const per = 10 * 8 * 4 * 4 + 16 * 4;
    try std.testing.expectEqual(@as(u64, 1344), per);
    // [D] recsize census: r1 arity-4 fold = 7,538,960 Blake G = 94,237 compressions -> 1.27e8 < p.
    try C.requireBlakeLookupMass(7_538_960 / 80, per);
    // Largest admissible count is (p - 1) / 1344 = 1,597,830 compressions per proof and table.
    const max = (core.fields.m31.Modulus - 1) / per;
    try C.requireBlakeLookupMass(max, per);
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireBlakeLookupMass(max + 1, per));
}
test "reference outer r1 AIR characteristic bound from the 24628607 census: 1.9 bits of margin, a 4x leaf wraps" {
    // [D] leaf 0: 589,890,560 interaction cells; pairFractions puts 2 lookups per secure (4-cell) column per row.
    const lookups: u64 = 589_890_560 / 4 * 2;
    try std.testing.expectEqual(@as(u64, 294_945_280), lookups);
    // Absolute mass <= uses + yields = 2 x use entries (unit-multiplicity uses assumed; canon-vk confirms).
    const facts = C.OuterGkrFacts{ .outer_proofs = 33, .instances = 16, .max_variables = 24, .max_tuple_arity = 8 };
    try C.requireOuterGkrCharacteristic(facts, 2 * lookups);
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireOuterGkrCharacteristic(facts, 4 * 2 * lookups));
}
test "m5/m7 format versions name the owning stream's component version (outer-gkr section, fused Blake2s AIR, chi chain)" {
    try std.testing.expectEqualStrings("stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v1", C.formatSpec(.m7_outer_gkr_m3_b4_q51_p26_fold4_v1).component);
    try std.testing.expectEqualStrings("fused_blake2s_v1", C.formatSpec(.m7_outer_fused_blake_m3_b4_q51_p26_fold4_v1).component);
    try std.testing.expectEqualStrings("rv64-m5-native-chi-chain/v1", C.formatSpec(.m5_native_chi_chain_v1_b2_q108_p20_fold4).component);
    // Every version that adds a component names it; the canonical-only outer versions add none.
    for (C.FORMAT_VERSIONS) |v| {
        const s = C.formatSpec(v);
        if (s.outer_gkr or s.layer == .native) try std.testing.expect(s.component.len > 0);
    }
}

// ---- M6 named versions (stream profiles, M6-INTERFACES.md P1) ----
test "m6 reserved names pin the published domains and owners" {
    const Row = struct { v: C.FormatVersion, owner: []const u8, domain: []const u8 };
    const rows = [_]Row{
        .{ .v = .m6_native_v2_b2_q108_p20_fold4, .owner = "native-format", .domain = "rv64-m6-native-chi-chain/v2/conjectured128_b2_q108_p20_fold4\x00" },
        .{ .v = .m6_native_v2_gkr_b2_q108_p20_fold4, .owner = "native-format", .domain = "rv64-m6-native-chi-chain/v2+native-gkr/v1/conjectured128_b2_q108_p20_fold4\x00" },
        .{ .v = .m6_outer_fold_v3_r1_b2_q108_p20_fold4_v1, .owner = "fold-v3", .domain = "stwo/circuit/native-om31/m6-fold-v3-q108-p20-fold4/lens-v1" },
        .{ .v = .m6_outer_diet_r1_b2_q108_p20_fold4_v1, .owner = "diet-wire", .domain = "stwo/circuit/native-om31/m6-diet-q108-p20-fold4/lens-v1" },
        .{ .v = .m6_outer_diet_m3_b4_q51_p26_fold4_v1, .owner = "diet-wire", .domain = "stwo/circuit/native-om31/m6-diet-m3-b4-q51-p26-fold4/lens-v1" },
        .{ .v = .m6_outer_diet_fold_v3_r1_b2_q108_p20_fold4_v1, .owner = "integrate", .domain = "stwo/circuit/native-om31/m6-diet-fold-v3-q108-p20-fold4/lens-v1" },
        .{ .v = .m6_outer_diet_fold_v3_m3_b4_q51_p26_fold4_v1, .owner = "integrate", .domain = "stwo/circuit/native-om31/m6-diet-fold-v3-m3-b4-q51-p26-fold4/lens-v1" },
        .{ .v = .m6_outer_setv2_kary_r1_b2_q108_p20_fold4_v1, .owner = "diet-wire", .domain = "stwo/circuit/native-om31/m6-setv2-kary-q108-p20-fold4/lens-v1" },
        .{ .v = .m6_outer_gkr_setv2_kary_r1_b2_q108_p20_fold4_v1, .owner = "diet-wire", .domain = "stwo/circuit/native-om31/m6-gkr-setv2-kary-q108-p20-fold4/lens-v1" },
    };
    for (rows) |r| {
        const s = C.formatSpec(r.v);
        try std.testing.expectEqualStrings(r.owner, s.owner);
        try std.testing.expectEqualStrings(r.domain, s.domain);
        // Hand arithmetic per row: r1 1*108 + 20 = 128 (Johnson x2 148), m3 2*51 + 26 = 128 (Johnson x2 154).
        const is_m3 = s.pcs.log_blowup == 2;
        try std.testing.expectEqual(@as(u32, 128), C.formatConjecturedBits(r.v));
        try std.testing.expectEqual(@as(u32, if (is_m3) 154 else 148), C.formatJohnsonBitsTimes2(r.v));
    }
}
test "m6 diet entries carry outer GKR + one-instance fused Blake + set-v2 + k-ary, composites are supersets" {
    for ([_]C.FormatVersion{ .m6_outer_diet_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_m3_b4_q51_p26_fold4_v1, .m6_outer_diet_fold_v3_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_fold_v3_m3_b4_q51_p26_fold4_v1 }) |v| {
        const s = C.formatSpec(v);
        try std.testing.expect(s.outer_gkr and s.fused_blake);
        // DW-1 [M]: 4-ary folds OOM (blake_g_gate 8,680,080 rows > 2^23); 3-ary is the shipped bound.
        try std.testing.expectEqual(@as(u32, 3), s.max_fold_arity);
        try std.testing.expectEqualStrings(C.OUTER_GKR_COMPONENT, s.component);
        try std.testing.expectEqualStrings(C.FUSED_BLAKE_ONE_INSTANCE_COMPONENT, s.extra_components[0]);
        try std.testing.expectEqualStrings(C.SET_V2_COMPONENT, s.extra_components[1]);
        try std.testing.expectEqualStrings(C.KARY_COMPONENT, s.extra_components[2]);
    }
    for ([_]C.FormatVersion{ .m6_outer_diet_fold_v3_r1_b2_q108_p20_fold4_v1, .m6_outer_diet_fold_v3_m3_b4_q51_p26_fold4_v1 }) |v| {
        const s = C.formatSpec(v);
        try std.testing.expectEqual(@as(usize, 4), s.extra_components.len);
        try std.testing.expectEqualStrings(C.FOLD_V3_COMPONENT, s.extra_components[3]);
    }
    // The diet outer GKR component is the same section version as the M7 m3 entry (one GKR section format).
    try std.testing.expectEqualStrings(C.formatSpec(.m7_outer_gkr_m3_b4_q51_p26_fold4_v1).component, C.OUTER_GKR_COMPONENT);
    // fold v3 alone: no GKR, no fused Blake, k-ary.
    const f3 = C.formatSpec(.m6_outer_fold_v3_r1_b2_q108_p20_fold4_v1);
    try std.testing.expect(!f3.outer_gkr and !f3.fused_blake);
    try std.testing.expectEqualStrings(C.FOLD_V3_COMPONENT, f3.component);
    // Native v2 (NF0/NF4): protocol rv64-m6-native/v2, profile v2-strict | v2-gkr (+ native GKR section v2).
    const nv = C.formatSpec(.m6_native_v2_b2_q108_p20_fold4);
    const ng = C.formatSpec(.m6_native_v2_gkr_b2_q108_p20_fold4);
    try std.testing.expectEqualStrings("rv64-m6-native/v2", nv.component);
    try std.testing.expectEqualStrings("v2-strict", nv.extra_components[0]);
    try std.testing.expectEqualStrings("rv64-m6-native/v2", ng.component);
    try std.testing.expectEqualStrings("v2-gkr", ng.extra_components[0]);
    try std.testing.expectEqualStrings("stwo/rv64/native-gkr/om31-strict-draw/lane-major/v2", ng.extra_components[1]);
    // Staged diet entries: set-v2 + k-ary first, then + outer GKR.
    const st = C.formatSpec(.m6_outer_setv2_kary_r1_b2_q108_p20_fold4_v1);
    try std.testing.expect(!st.outer_gkr and !st.fused_blake);
    const sg = C.formatSpec(.m6_outer_gkr_setv2_kary_r1_b2_q108_p20_fold4_v1);
    try std.testing.expect(sg.outer_gkr and !sg.fused_blake);
    try std.testing.expectEqualStrings(C.OUTER_GKR_COMPONENT, sg.component);
    try std.testing.expect(!std.mem.eql(u8, &C.formatIdentity(.m6_native_v2_b2_q108_p20_fold4), &C.formatIdentity(.m5_native_chi_chain_v1_b2_q108_p20_fold4)));
}
test "m6 composite identity: changing any one extra component, its order, or the fold arity changes the identity" {
    // diet vs diet+fold-v3 differ only by one appended extra component (and the domain).
    const a = C.formatIdentity(.m6_outer_diet_r1_b2_q108_p20_fold4_v1);
    const b = C.formatIdentity(.m6_outer_diet_fold_v3_r1_b2_q108_p20_fold4_v1);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    // Same components, other PCS: distinct.
    try std.testing.expect(!std.mem.eql(u8, &a, &C.formatIdentity(.m6_outer_diet_m3_b4_q51_p26_fold4_v1)));
    // Every identity in the registry is distinct (also covered by the M5 loop; restated for the 14 entries).
    for (C.FORMAT_VERSIONS, 0..) |v, i| for (C.FORMAT_VERSIONS[i + 1 ..]) |w|
        try std.testing.expect(!std.mem.eql(u8, &C.formatIdentity(v), &C.formatIdentity(w)));
    try std.testing.expectEqual(@as(usize, 14), C.FORMAT_VERSIONS.len);
}
test "m6 diet outer GKR clears 128+23 bits at the 24628607 node count; r1 vs m3 equal under the GKR ledger" {
    // [D] M5 integrate: 33 outer nodes on 24628607 (28 leaves + folds + root); 16 batched instances of <= 2^24 rows.
    const real = C.OuterGkrFacts{ .outer_proofs = 33, .instances = 16, .max_variables = 24, .max_tuple_arity = 8 };
    try C.requireOuterGkrBits(real, C.TARGET_BITS + 2 + 21);
    try C.requireOuterGkrCharacteristic(real, null);
    // The ledger is PCS-independent: the r1 diet entry carries the same algebraic bound as m3; its query
    // term is the base PCS (1*108 + 20 = 128).
    try std.testing.expectEqual(C.formatConjecturedBits(.m6_outer_diet_r1_b2_q108_p20_fold4_v1), C.formatConjecturedBits(.m6_outer_diet_m3_b4_q51_p26_fold4_v1));
}
test "corpus BG08 m6 one-instance fused Blake: XOR8 table mass over ALL consumers stays below p" {
    // [D] gadget 704 XOR8 lookups per compression; recsize census largest r1 fold 94,237 compressions;
    // other consumers of the same table bounded by every lookup of the node (r1 leaf 0: 294,945,280).
    const gadget = 94_237 * 704;
    try C.requireBlakeTableMass(&.{ gadget, 294_945_280 });
    // A single consumer at the edge, then one over.
    try C.requireBlakeTableMass(&.{core.fields.m31.Modulus - 1});
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireBlakeTableMass(&.{ core.fields.m31.Modulus - 1, 1 }));
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireBlakeTableMass(&.{ std.math.maxInt(u64), 2 }));
}
test "m6 k-ary diet folds: integer mass fold at arity 4 (bound) refuses a wrap an M31 sum hides" {
    const p = core.fields.m31.Modulus;
    const q = (p - 1) / 4 + 1;
    const four = [_][C.NS_MASS_RELATIONS]u64{ .{ q, 0, 0 }, .{ q, 0, 0 }, .{ q, 0, 0 }, .{ q, 0, 0 } };
    try std.testing.expectError(error.M5MassCharacteristicWrap, C.m5FoldMass(&four));
    try std.testing.expect(C.m5FieldMassForTesting(&four)[0] < p);
    const five = four ++ [_][C.NS_MASS_RELATIONS]u64{.{ 0, 0, 0 }};
    try std.testing.expectError(error.M5FoldArity, C.m5FoldMass(&five));
}
test "native v2-gkr GKR section at its declared bounds (NF4): OM31 clears 151 bits, conservative mass wraps p" {
    // [D] NF4 bounds: <= 128 instances, <= 28 variables, per proof; union over MAX_PROOFS native proofs.
    // Same five-term model as the outer section (sumcheck, mix, binding, tuple, poles); tuple arity <= MAX_TUPLE_ARITY.
    const nf4 = C.OuterGkrFacts{ .outer_proofs = C.MAX_PROOFS, .instances = 128, .max_variables = 28, .max_tuple_arity = C.MAX_TUPLE_ARITY };
    try C.requireOuterGkrBits(nf4, C.TARGET_BITS + 2 + 21);
    // QM31 draws would fail: the native section must draw OM31 (as NF4 says, strict draws).
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, C.requireOuterGkrBitsQm31(nf4, 124));
    // Characteristic: 128 x 2^28 = 2^35 >= p, so requireNativeGkrSecurity MUST use the per-relation
    // source-bound mass (NF4 says M4 source bounds); the conservative bound is refused.
    try std.testing.expectEqual(@as(u64, 1) << 35, try C.outerGkrMassBound(nf4));
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, C.requireOuterGkrCharacteristic(nf4, null));
}
