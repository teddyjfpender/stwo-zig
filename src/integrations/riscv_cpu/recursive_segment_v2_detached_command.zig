//! Compatibility exports and focused transport checks for neutral leaf verification.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const verifier = @import("recursive_segment_v2_detached_verifier.zig");
const PublicData = frontend.air.public_data_v2.PublicDataV2;
const VERSION: u32 = 1;
const owner = frontend.recursion.detached_segment_command_v1;
const CpuEngine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
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
pub fn verifyDirectory(allocator: std.mem.Allocator, directory: []const u8, independent_key_sha256: [32]u8, expected_wire_path: []const u8) !ReceiptV1 {
    return owner.verifyDirectoryWithNativeRoot(CpuEngine, allocator, directory, independent_key_sha256, expected_wire_path);
}
pub const ArgumentsV1 = owner.ArgumentsV1;
pub const parseArguments = owner.parseArguments;
pub const SingleRootReceiptV1 = owner.SingleRootReceiptV1;
pub const singleRootStatement = owner.singleRootStatement;
pub fn verifyRoot(allocator: std.mem.Allocator, input: ArgumentsV1) !SingleRootReceiptV1 {
    return owner.verifyRootWithNativeRoot(CpuEngine, allocator, input);
}
pub const PairReceiptV1 = owner.PairReceiptV1;
pub fn verifyPair(allocator: std.mem.Allocator, inputs: [2]ArgumentsV1) !PairReceiptV1 {
    return owner.verifyPairWithNativeRoot(CpuEngine, allocator, inputs);
}
pub fn main() !void {
    return owner.mainWithNativeRoot(CpuEngine);
}

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

test "SegmentV2 key admission independently regenerates native Tree0" {
    const allocator = std.testing.allocator;
    const descriptors = [_]frontend.air.statement.FamilyComponentDesc{.{
        .family = .lui,
        .log_size = 4,
        .n_rows = 1,
        .n_columns = 1,
    }};
    var key = try frontend.recursion.detached_segment_protocol_fixture_v1.testing.key(1000, 1);
    key.native_descriptors = .{ .components = &descriptors, .infrastructure = &.{} };
    key.native_preprocessed_root = try frontend.prover_mod.preprocessed.rootForDescriptors(
        CpuEngine,
        allocator,
        key.profile.nativePcsConfig(),
        &descriptors,
        &.{},
    );
    try key.validateNativePreprocessedRoot(CpuEngine, allocator);
    key.native_preprocessed_root[0] +%= 1;
    try std.testing.expectError(
        error.InvalidNativePreprocessedCommitment,
        key.validateNativePreprocessedRoot(CpuEngine, allocator),
    );
}

test "SegmentV2 detached catalog rejects changed native geometry with fixed public claim pin" {
    const allocator = std.testing.allocator;
    const descriptors = [_]frontend.air.statement.FamilyComponentDesc{.{
        .family = .lui,
        .log_size = 4,
        .n_rows = 1,
        .n_columns = 1,
    }};
    var key = try frontend.recursion.detached_segment_protocol_fixture_v1.testing.key(1000, 1);
    key.native_descriptors = .{ .components = &descriptors, .infrastructure = &.{} };
    key.native_preprocessed_root = try frontend.prover_mod.preprocessed.rootForDescriptors(
        CpuEngine,
        allocator,
        key.profile.nativePcsConfig(),
        &descriptors,
        &.{},
    );
    const admitted = try std.json.Stringify.valueAlloc(allocator, key, .{});
    defer allocator.free(admitted);
    const independent_pin = hash(admitted);
    const owned = try OwnedKeyV1.admitWithNativeRoot(CpuEngine, allocator, admitted, independent_pin);
    owned.deinit();

    const variants = [_]frontend.air.statement.FamilyComponentDesc{
        .{ .family = .lui, .log_size = 4, .n_rows = 2, .n_columns = 1 },
        .{ .family = .lui, .log_size = 5, .n_rows = 1, .n_columns = 1 },
        .{ .family = .lui, .log_size = 4, .n_rows = 1, .n_columns = 2 },
    };
    for (variants) |variant| {
        const changed = [_]frontend.air.statement.FamilyComponentDesc{variant};
        key.native_descriptors.components = &changed;
        const bytes = try std.json.Stringify.valueAlloc(allocator, key, .{});
        defer allocator.free(bytes);
        try std.testing.expectError(
            error.DetachedKeyHashMismatch,
            OwnedKeyV1.admitWithNativeRoot(CpuEngine, allocator, bytes, independent_pin),
        );
    }
}

test "SegmentV2 newly pinned catalog still matches the independently expected segment" {
    const allocator = std.testing.allocator;
    const fixture = try frontend.testing.public_data_v2_test_support.Fixture.initWithRegister7(0x01020304);
    const source = fixture.rightSource();
    const words = try frontend.testing.public_data_v2_test_support.encode(allocator, &source);
    defer allocator.free(words);
    const public = try PublicData.authenticate(words);
    const metadata = try public.metadata();
    const steps = metadata.global_cycle_end - metadata.global_cycle_start;
    try std.testing.expect(steps > 0 and steps < (1 << 16));

    var descriptor = [_]frontend.air.statement.FamilyComponentDesc{.{
        .family = .lui,
        .log_size = @max(@as(u32, 4), std.math.log2_int_ceil(u32, steps)),
        .n_rows = steps,
        .n_columns = 18,
    }};
    var key = try frontend.recursion.detached_segment_protocol_fixture_v1.testing.key(1000, 1);
    key.native_descriptors = .{ .components = &descriptor, .infrastructure = &.{} };
    const original = try std.json.Stringify.valueAlloc(allocator, key, .{});
    defer allocator.free(original);
    const owned = try OwnedKeyV1.admit(allocator, original, hash(original));
    defer owned.deinit();
    try owned.key().native_descriptors.validateAgainstExpected(&public);

    const variants = [_]frontend.air.statement.FamilyComponentDesc{
        .{ .family = .lui, .log_size = descriptor[0].log_size, .n_rows = steps + 1, .n_columns = 18 },
        .{ .family = .lui, .log_size = descriptor[0].log_size + 1, .n_rows = steps, .n_columns = 18 },
        .{ .family = .lui, .log_size = descriptor[0].log_size, .n_rows = steps, .n_columns = 19 },
    };
    for (variants) |variant| {
        descriptor[0] = variant;
        const bytes = try std.json.Stringify.valueAlloc(allocator, key, .{});
        defer allocator.free(bytes);
        // Even a newly independent SHA pin cannot make this descriptor agree
        // with the unchanged public claim. No proof or channel is present.
        const repinned = try OwnedKeyV1.admit(allocator, bytes, hash(bytes));
        defer repinned.deinit();
        try std.testing.expectError(
            error.InvalidNativeDescriptorGeometry,
            repinned.key().native_descriptors.validateAgainstExpected(&public),
        );
    }
}
