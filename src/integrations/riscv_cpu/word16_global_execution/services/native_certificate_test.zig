const std = @import("std");
const Certificate = @import("native_certificate.zig");
const F = @import("fixture.zig");
const a = std.testing.allocator;

test "native Word16 certificate authenticates real CPU Keccak and secp truth proofs with independent receiver" {
    var fixture = try F.Case.init(a);
    defer fixture.deinit();
    const setups = fixture.keys();
    const truths = fixture.truths();
    const first = try Certificate.verifyAndCommit(a, &setups, &truths, fixture.expected(), &fixture.bundle);
    const second = try Certificate.verifyPinned(a, &setups, &truths, fixture.expected(), &fixture.bundle, first.digest);
    try std.testing.expectEqualDeep(first, second);
    try std.testing.expectEqual(@as(u32, 2), first.cpu_proofs);
    try std.testing.expectEqual(@as(u32, 3), first.truth_proofs);
    try std.testing.expectEqual(@as(u64, 7), first.steps);
    try std.testing.expect(!Certificate.Certificate.recursively_verified);
    try std.testing.expect(!Certificate.Certificate.whole_protocol_128_qualified);

    var bad_digest = first.digest;
    bad_digest[0] ^= 1;
    try std.testing.expectError(error.NativeCertificateMismatch, Certificate.verifyPinned(a, &setups, &truths, fixture.expected(), &fixture.bundle, bad_digest));
    const saved_proof = fixture.bundle.truths[0].bytes[0];
    fixture.bundle.truths[0].bytes[0] ^= 1;
    if (Certificate.verifyAndCommit(a, &setups, &truths, fixture.expected(), &fixture.bundle)) |_|
        return error.AcceptedCorruptTruthProof
    else |_| {}
    fixture.bundle.truths[0].bytes[0] = saved_proof;
    const saved_cpu = fixture.bundle.cpus[0].bytes[0];
    fixture.bundle.cpus[0].bytes[0] ^= 1;
    if (Certificate.verifyAndCommit(a, &setups, &truths, fixture.expected(), &fixture.bundle)) |_|
        return error.AcceptedCorruptCpuProof
    else |_| {}
    fixture.bundle.cpus[0].bytes[0] = saved_cpu;
    _ = try Certificate.verifyPinned(a, &setups, &truths, fixture.expected(), &fixture.bundle, first.digest);
}

test "native Word16 certificate rejects incomplete or contradictory execution roster before statement publication" {
    var fixture = try F.Case.init(a);
    defer fixture.deinit();
    const setups = fixture.keys();
    const truths = fixture.truths();
    const good = try Certificate.verifyAndCommit(a, &setups, &truths, fixture.expected(), &fixture.bundle);

    var invalid = fixture.expected();
    invalid.program_identity[0] ^= 1;
    if (Certificate.verifyAndCommit(a, &setups, &truths, invalid, &fixture.bundle)) |_|
        return error.AcceptedDifferentExpectedProgram
    else |_| {}
    invalid = fixture.expected();
    invalid.final_pc += 4;
    if (Certificate.verifyAndCommit(a, &setups, &truths, invalid, &fixture.bundle)) |_|
        return error.AcceptedDifferentExpectedFinalPc
    else |_| {}

    var candidate = fixture.bundle;
    candidate.truths = fixture.bundle.truths[0..2];
    if (Certificate.verifyAndCommit(a, &setups, &truths, fixture.expected(), &candidate)) |_|
        return error.AcceptedOmittedTruth
    else |_| {}

    const saved_claim = fixture.bundle.cpus[0].claims.extras[0].truth;
    fixture.bundle.cpus[0].claims.extras[0].truth = saved_claim.add(@import("../protocol.zig").Q.one());
    if (Certificate.verifyAndCommit(a, &setups, &truths, fixture.expected(), &fixture.bundle)) |_|
        return error.AcceptedTamperedServiceClaim
    else |_| {}
    fixture.bundle.cpus[0].claims.extras[0].truth = saved_claim;
    _ = try Certificate.verifyPinned(a, &setups, &truths, fixture.expected(), &fixture.bundle, good.digest);
}
