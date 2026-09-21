//! Compatibility exports and focused transport checks for neutral leaf verification.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const verifier = @import("recursive_segment_v2_detached_verifier.zig");
const PublicData = frontend.air.public_data_v2.PublicDataV2;
const VERSION: u32 = 1;
const owner = frontend.recursion.detached_segment_command_v1;
pub const MAX_KEY_BYTES = owner.MAX_KEY_BYTES;
pub const MAX_INPUT_BYTES = owner.MAX_INPUT_BYTES;
pub const hash = owner.hash;
pub const OwnedKeyV1 = owner.OwnedKeyV1;
pub const OwnedExpectedV1 = owner.OwnedExpectedV1;
pub const encodeExpected = owner.encodeExpected;
pub const ClaimsFileV1 = owner.ClaimsFileV1;
pub const decodeClaims = owner.decodeClaims;
pub const CandidateHashesV1 = owner.CandidateHashesV1;
pub const retainCandidate = owner.retainCandidate;
pub const ReceiptV1 = owner.ReceiptV1;
pub const verifyDirectory = owner.verifyDirectory;
pub const ArgumentsV1 = owner.ArgumentsV1;
pub const parseArguments = owner.parseArguments;
pub const SingleRootReceiptV1 = owner.SingleRootReceiptV1;
pub const singleRootStatement = owner.singleRootStatement;
pub const verifyRoot = owner.verifyRoot;
pub const PairReceiptV1 = owner.PairReceiptV1;
pub const verifyPair = owner.verifyPair;
pub const main = owner.main;

test "SegmentV2 detached command requires separate circuit and statement authority" {
    const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const parsed = try parseArguments(&.{ "candidate", pin, "expected.json" });
    try std.testing.expectEqualStrings("expected.json", parsed.expected_wire_path);
    try std.testing.expectError(error.ExpectedDirectoryIndependentKeyAndPublicWire, parseArguments(&.{ "candidate", pin }));
    try std.testing.expectError(error.DetachedKeyHashMismatch, OwnedKeyV1.admit(std.testing.allocator, "{}", @splat(0)));
}

test "SegmentV2 detached command owns and canonically admits expected wire" {
    const fixture = try frontend.testing.public_data_v2_test_support.Fixture.initWithRegister7(0x01020304);
    const source = fixture.rightSource();
    const words = try frontend.testing.public_data_v2_test_support.encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const public = try PublicData.authenticate(words);
    try std.testing.expectError(error.DetachedSingleSegmentRequired, singleRootStatement(&public));
    const json = try encodeExpected(std.testing.allocator, &public);
    defer std.testing.allocator.free(json);
    var owned = try OwnedExpectedV1.decode(std.testing.allocator, json);
    defer owned.deinit();
    try std.testing.expect(owned.words.ptr != words.ptr);
    try std.testing.expectEqualDeep(try public.metadata(), try owned.data.metadata());
    try std.testing.expectError(error.DetachedNoncanonicalPublicWord, OwnedExpectedV1.decode(std.testing.allocator, "[2147483647]"));
    try std.testing.expectError(error.DetachedPublicInputSizeMismatch, OwnedExpectedV1.decode(std.testing.allocator, "[]"));
}

test "SegmentV2 detached command rejects unsupported claims version and empty proof" {
    const claims: verifier.ClaimsV1 = .{ .values = @splat(core.fields.qm31.QM31.zero()), .poseidon_partials = @splat(core.fields.qm31.QM31.zero()) };
    var input = ClaimsFileV1{ .claims = claims, .proof_bytes = 1, .proof_sha256 = @splat(0) };
    input.version = 2;
    const bad_version = try std.json.Stringify.valueAlloc(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(bad_version);
    try std.testing.expectError(error.DetachedClaimsVersionMismatch, decodeClaims(std.testing.allocator, bad_version));
    input.version = VERSION;
    input.proof_bytes = 0;
    const empty_proof = try std.json.Stringify.valueAlloc(std.testing.allocator, input, .{});
    defer std.testing.allocator.free(empty_proof);
    try std.testing.expectError(error.DetachedProofSizeMismatch, decodeClaims(std.testing.allocator, empty_proof));
}
