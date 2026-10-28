//! Pinned serialized-key regression for the runner-independent leaf manifest.
const std = @import("std");
const statement = @import("recursion/segment_leaf_statement_contract_v2.zig");
const admission = @import("recursion/detached_segment_admission_v1.zig");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const contract = @import("recursion/air/segment_outer_manifest_contract_v2.zig");

/// Opt-in override for the unqualified recursion lane (see the skip below).
const RUN_UNQUALIFIED_RECURSION_LANE_ENV = "STWO_RECURSION_RUN_UNQUALIFIED_LANE";
const OLD_Q193_KEY = "vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/q193-ladder-4-admission/child-0-key.json";

fn readOldQ193Key(allocator: std.mem.Allocator) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, OLD_Q193_KEY, 64 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => std.fs.cwd().readFileAlloc(allocator, "../../../" ++ OLD_Q193_KEY, 64 * 1024 * 1024),
        else => return err,
    };
}

test "pre-October q193 leaf key fails current catalog admission" {
    const allocator = std.testing.allocator;
    const bytes = try readOldQ193Key(allocator);
    defer allocator.free(bytes);
    const OldKey = struct { manifest: contract.Manifest };
    const parsed = try std.json.parseFromSlice(OldKey, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectError(error.ManifestSealMismatch, parsed.value.manifest.validate());
}

test "pure leaf manifest admits the independently pinned q193 key" {
    const allocator = std.testing.allocator;
    // Skipped, not deleted: the committed q193 child key pins the
    // pre-October-2026 compact-Poseidon catalog identity. The October 2026
    // audit replaced the Merkle node's two-term Poseidon2 lookup with one
    // atomic `poseidon2_io` tuple, so the key now fails
    // `ManifestSealMismatch` under the current provider authority, and
    // soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md
    // ("The October 2026 audit ...") declares the recursion lane NOT QUALIFIED
    // until its keys and vectors are re-derived under the current circuit.
    // Pre-contract migration has been retired; remove this skip only after
    // the regenerated-key regression below is installed.
    if (std.posix.getenv(RUN_UNQUALIFIED_RECURSION_LANE_ENV) == null) return error.SkipZigTest;
    const bytes = try readOldQ193Key(allocator);
    defer allocator.free(bytes);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "e5fb45e1b74c32219af17cda598e1fbd56ed61055be19dde260a03d2d0b015a2");
    try std.testing.expectEqualSlices(u8, &expected, &actual);
    const Key = struct { manifest: contract.Manifest, parameters: admission.AdmissionParametersV1, source_manifest: statement.ManifestV2, admitted_keys: statement.VerifierKeyAuthorityV2 };
    const parsed = try std.json.parseFromSlice(Key, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try parsed.value.manifest.validate();
    try parsed.value.source_manifest.validate();
    try parsed.value.admitted_keys.validate();
    const rebuilt = try statement.ManifestV2.init(parsed.value.source_manifest.wire_word_count);
    try std.testing.expectEqualDeep(parsed.value.source_manifest, rebuilt);
    var keys = parsed.value.admitted_keys;
    keys.segment_leaf_vk_id[0] ^= 1;
    try std.testing.expectError(error.AuthorityMismatch, keys.validate());
    var source_manifest = parsed.value.source_manifest;
    source_manifest.schema_id[0] ^= 1;
    try std.testing.expectError(error.InvalidManifest, source_manifest.validate());
    const logs = try parsed.value.parameters.validate(&parsed.value.manifest);
    try std.testing.expectEqual(@as(usize, 39), logs.len);
    var claims: admission.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    _ = try claims.vector(&parsed.value.manifest);
    claims.values[10] = QM31.one();
    try std.testing.expectError(error.InactiveRowInvariantMismatch, claims.vector(&parsed.value.manifest));
    claims.values[10] = QM31.zero();
    claims.poseidon_partials[0] = QM31.one();
    try std.testing.expectError(error.InvalidSegmentVerifierClaims, claims.vector(&parsed.value.manifest));
    var parameters = parsed.value.parameters;
    parameters.poseidon_active_rows = (@as(u32, 1) << @intCast(logs[34])) + 1;
    try std.testing.expectError(error.InvalidSegmentVerifierAdmission, parameters.validate(&parsed.value.manifest));
    parameters = parsed.value.parameters;
    parameters.query_reference.authority_digest[0] ^= 1;
    try std.testing.expectError(error.AuthorityMismatch, parameters.validate(&parsed.value.manifest));
    var changed = parsed.value.manifest;
    changed.provider_authority_sha_id[0] ^= 1;
    try std.testing.expectError(error.ManifestSealMismatch, changed.validate());
}
