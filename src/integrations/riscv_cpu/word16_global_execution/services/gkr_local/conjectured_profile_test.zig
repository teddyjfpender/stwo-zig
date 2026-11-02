//! Named PCS/security profile gates of the OM31 local-GKR candidate route:
//! the conjectured128 b2/q108/P20/fold4 profile proves and verifies end to end
//! from receiver-owned fixed authority; receivers holding another profile,
//! a tampered PoW nonce, a changed query count and unregistered configs fail.
const std = @import("std");
const F = @import("coordinator_fixture.zig");
const Original = @import("../fixture.zig");
const C = @import("coordinator.zig");
const Fixed = @import("fixed_authority.zig");
const FixedSet = @import("fixed_authority_set.zig").Set;
const Candidate = @import("../../../word16_execution/om31_security_candidate.zig");
const W = @import("worker_protocol.zig");
const a = std.testing.allocator;

test "named candidate profiles: selection, exact parameters, identities" {
    const conj = Candidate.configFor(.conjectured128_b2_q108_p20_fold4);
    try std.testing.expectEqual(@as(u32, 1), conj.fri_config.log_blowup_factor);
    try std.testing.expectEqual(@as(usize, 108), conj.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 20), conj.pow_bits);
    try std.testing.expectEqual(@as(u32, 4), conj.fri_config.fold_step);
    try std.testing.expectEqual(@as(u32, 0), conj.fri_config.log_last_layer_degree_bound);
    try std.testing.expectEqual(@as(u32, 128), Candidate.conjecturedBits(.conjectured128_b2_q108_p20_fold4));
    try std.testing.expectEqual(Candidate.Profile.conjectured128_b2_q108_p20_fold4, Candidate.DEFAULT_PROFILE);
    // The proven profile keeps its historical config and identity bytes.
    try std.testing.expect(std.meta.eql(Candidate.config(), Candidate.configFor(.proven_beta2_q256_p0_fold4)));
    try std.testing.expectEqualSlices(u8, &Candidate.identity(), &Candidate.profileIdentity(.proven_beta2_q256_p0_fold4));
    try std.testing.expect(!std.mem.eql(u8, &Candidate.identity(), &Candidate.profileIdentity(.conjectured128_b2_q108_p20_fold4)));
    for (Candidate.PROFILES) |p| {
        try std.testing.expectEqual(p, try Candidate.Profile.parse(p.name()));
        try std.testing.expectEqual(p, try Candidate.profileFor(Candidate.configFor(p)));
        try W.validateCandidateConfig(Candidate.configFor(p));
    }
    try std.testing.expectError(error.UnknownOm31CandidateProfile, Candidate.Profile.parse("conjectured128"));
    try std.testing.expectError(error.UnknownOm31CandidateProfile, Candidate.Profile.parse(""));
    // Every single-parameter deviation at blowup 2 (rate 1) is unregistered
    // and refused; the conjectured profile is the ONLY admitted rate-1 config.
    var bad = [_]@TypeOf(conj){ conj, conj, conj, conj, conj, conj };
    bad[0].fri_config.n_queries = 107;
    bad[1].pow_bits = 19;
    bad[2].fri_config.fold_step = 1;
    bad[3].pow_bits = 0;
    bad[4].fri_config.n_queries = 256;
    bad[5].pow_bits = 26;
    for (bad) |config| {
        try std.testing.expectError(error.UnrecognizedOm31CandidateParameters, Candidate.profileFor(config));
        try std.testing.expectError(error.UnsupportedWideServicesConfig, W.validateCandidateConfig(config));
        try std.testing.expectEqual(@as(?Candidate.Profile, null), W.candidateProfile(config));
    }
    // Blowup-2 deviations are not named profiles: they stay in the legacy
    // beta2 structural family (no profile identity, historical bytes).
    var mixed = Candidate.config();
    mixed.pow_bits = 20;
    try std.testing.expectError(error.UnrecognizedOm31CandidateParameters, Candidate.profileFor(mixed));
    try std.testing.expectEqual(@as(?Candidate.Profile, null), W.candidateProfile(mixed));
    try std.testing.expectEqual(@as(?Candidate.Profile, .proven_beta2_q256_p0_fold4), W.candidateProfile(Candidate.config()));
}

fn tamperCpuProof(bundle: *C.Bundle, index: usize, comptime edit: fn (*W.Proof) void) ![]u8 {
    var proof = try W.decodePhysical(a, bundle.cpus[index].bytes);
    defer proof.deinit(a);
    edit(&proof);
    const bytes = try W.encodePhysical(a, proof);
    const original = bundle.cpus[index].bytes;
    bundle.cpus[index].bytes = bytes;
    return original;
}
fn restore(bundle: *C.Bundle, index: usize, original: []u8) void {
    a.free(bundle.cpus[index].bytes);
    bundle.cpus[index].bytes = original;
}
fn bumpNonce(proof: *W.Proof) void {
    proof.commitment_scheme_proof.proof_of_work +%= 1;
}
fn dropQuery(proof: *W.Proof) void {
    proof.commitment_scheme_proof.config.fri_config.n_queries -= 1;
}
fn provenConfig(proof: *W.Proof) void {
    proof.commitment_scheme_proof.config = Candidate.config();
}

test "conjectured128 profile proves, verifies from fresh authority, and fails closed across profiles" {
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const config = Candidate.configFor(.conjectured128_b2_q108_p20_fold4);
    const expected = Original.expectedFor(captured.program.identity);
    var cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var authority = try FixedSet.init(a, &cache, &keys.pointers(), &keys.truths(), config);
    defer authority.deinit();
    try std.testing.expectEqual(@as(?Candidate.Profile, .conjectured128_b2_q108_p20_fold4), authority.at(0).profile);
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try C.Store.initFullyParked(path, 256 << 20);
    defer store.deinit();
    var bundle = try C.produceWithAuthority(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, config, .{ .gkr_budget = 2 << 30, .retained_store = &store, .max_workers = 32, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 } }, &authority);
    defer bundle.deinit(a);
    // The proof carries the profile's PCS parameters and a real 20-bit PoW.
    {
        var proof = try W.decodePhysical(a, bundle.cpus[0].bytes);
        defer proof.deinit(a);
        try std.testing.expect(std.meta.eql(proof.commitment_scheme_proof.config, config));
    }
    // Fresh receiver with independently derived conjectured authority accepts.
    var fresh = try F.Keys.init(a);
    defer fresh.deinit();
    var fresh_cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    defer fresh_cache.deinit();
    var receiver = try FixedSet.init(a, &fresh_cache, &fresh.pointers(), &fresh.truths(), config);
    defer receiver.deinit();
    const accepted = try bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &receiver);
    try std.testing.expect(accepted.completed);
    try std.testing.expectEqual(@as(u64, 7), accepted.total_steps);
    // Mismatched-profile receiver (proven beta2/q256/P0 authority) rejects.
    var proven_cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    defer proven_cache.deinit();
    var proven = try FixedSet.init(a, &proven_cache, &fresh.pointers(), &fresh.truths(), Candidate.config());
    defer proven.deinit();
    if (bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, Candidate.config(), &proven)) |_| return error.AcceptedConjecturedBundleUnderProvenProfile else |_| {}
    // A receiver config/authority pair that disagrees is refused before proofs.
    try std.testing.expectError(error.WideBeta2FixedInventoryMismatch, bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, Candidate.config(), &receiver));
    // Control (non-candidate) receivers never accept it either.
    if (bundle.verify(a, &fresh.pointers(), &fresh.truths(), expected, config)) |_| return error.AcceptedConjecturedBundleWithoutFixedAuthority else |_| {}
    // Query count is enforced: a receiver config with 107 queries is not a profile.
    var fewer = config;
    fewer.fri_config.n_queries = 107;
    try std.testing.expectError(error.UnsupportedWideServicesConfig, bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, fewer, &receiver));
    // ... and a proof whose embedded config claims fewer queries is rejected.
    {
        const original = try tamperCpuProof(&bundle, 0, dropQuery);
        defer restore(&bundle, 0, original);
        if (bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &receiver)) |_| return error.AcceptedProofWithFewerQueries else |_| {}
    }
    // A proof that claims the proven profile's parameters is rejected.
    {
        const original = try tamperCpuProof(&bundle, 0, provenConfig);
        defer restore(&bundle, 0, original);
        if (bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &receiver)) |_| return error.AcceptedProofClaimingProvenProfile else |_| {}
    }
    // Tampered PoW nonce is rejected (each CPU proof independently).
    for (0..bundle.cpus.len) |i| {
        const original = try tamperCpuProof(&bundle, i, bumpNonce);
        defer restore(&bundle, i, original);
        if (bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &receiver)) |_| return error.AcceptedTamperedPowNonce else |_| {}
    }
    // Untampered bundle still verifies after the restores.
    try std.testing.expectEqualDeep(accepted, try bundle.verifyWithAuthority(a, &fresh.pointers(), &fresh.truths(), expected, config, &receiver));
}

test "profile identity is bound into fixed-authority statement and channel" {
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    var cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var conj = try Fixed.Binding.acquire(&cache, &keys.cpus[0].key, Candidate.configFor(.conjectured128_b2_q108_p20_fold4));
    defer conj.deinit();
    var proven = try Fixed.Binding.acquire(&cache, &keys.cpus[0].key, Candidate.config());
    defer proven.deinit();
    // Different blowup -> different immutable fixed commitment identity.
    try std.testing.expect(!std.mem.eql(u8, &conj.fixed_identity, &proven.fixed_identity));
    const base = [_]u8{7} ** 32;
    // Same fixed fields but a different profile label changes the statement.
    var relabeled = conj;
    relabeled.profile = .proven_beta2_q256_p0_fold4;
    try std.testing.expect(!std.mem.eql(u8, &conj.statement(base), &relabeled.statement(base)));
    // Binding refuses a config of another profile.
    try std.testing.expectError(error.WideCandidateProfileMismatch, conj.require(&keys.cpus[0].key, Candidate.config()));
    try std.testing.expectError(error.WideCandidateProfileMismatch, proven.require(&keys.cpus[0].key, Candidate.configFor(.conjectured128_b2_q108_p20_fold4)));
}
