//! Explicit benchmark custody tuple. This is not a proof-system admission key:
//! the CPU reference must already be freshly verified, and the Metal command
//! still freshly verifies the matching artifact before release.
const std = @import("std");

pub const environment = "STWO_ZIG_STAGE101_BENCHMARK_ADMISSION_V2";
pub const schema = "stwo.stage101-benchmark-admission.v2";
pub const max_artifact_bytes = 256 * 1024 * 1024;

pub const Admission = struct {
    version: u8,
    artifact_bytes: usize,
    artifact_sha256: [32]u8,
    claim_schema: u32,
    manifest_sha256: [32]u8,
    metallib_sha256: [32]u8,
    /// Exact execution placement pin for this reference artifact. Old tuples
    /// retain the original tiny-fixture allowance; real full-size leaves pin0.
    small_circle_host_placements: u64 = 3,

    pub fn validateReference(self: Admission, bytes: []const u8, claim_schema: u32) !void {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (bytes.len != self.artifact_bytes or !std.mem.eql(u8, &digest, &self.artifact_sha256))
            return error.Stage101ReferenceArtifactMismatch;
        if (claim_schema != self.claim_schema)
            return error.Stage101BenchmarkClaimAdmissionMismatch;
    }
};

const Encoded = struct {
    schema: []const u8,
    artifact_bytes: usize,
    artifact_sha256: []const u8,
    claim_schema: u32,
    manifest_sha256: []const u8,
    metallib_sha256: []const u8,
    small_circle_host_placements: u64 = 3,
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Admission {
    const parsed = try std.json.parseFromSlice(Encoded, allocator, bytes, .{});
    defer parsed.deinit();
    const value = parsed.value;
    if (!std.mem.eql(u8, value.schema, schema) or value.artifact_bytes == 0 or
        value.artifact_bytes > max_artifact_bytes or value.claim_schema < 2 or value.claim_schema > 5)
        return error.InvalidStage101BenchmarkAdmission;
    return .{
        .version = 2,
        .artifact_bytes = value.artifact_bytes,
        .artifact_sha256 = try parseDigest(value.artifact_sha256),
        .claim_schema = value.claim_schema,
        .manifest_sha256 = try parseDigest(value.manifest_sha256),
        .metallib_sha256 = try parseDigest(value.metallib_sha256),
        .small_circle_host_placements = value.small_circle_host_placements,
    };
}

fn parseDigest(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidStage101BenchmarkAdmission;
    for (hex) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidStage101BenchmarkAdmission;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch return error.InvalidStage101BenchmarkAdmission;
    if (std.mem.allEqual(u8, &result, 0)) return error.InvalidStage101BenchmarkAdmission;
    return result;
}

const fixture =
    \\{"schema":"stwo.stage101-benchmark-admission.v2","artifact_bytes":3,"artifact_sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","claim_schema":4,"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","metallib_sha256":"2222222222222222222222222222222222222222222222222222222222222222"}
;

test "Stage101 explicit benchmark tuple binds reference bytes and claim schema" {
    const admitted = try parse(std.testing.allocator, fixture);
    try admitted.validateReference("abc", 4);
    try std.testing.expectError(error.Stage101ReferenceArtifactMismatch, admitted.validateReference("abd", 4));
    try std.testing.expectError(error.Stage101BenchmarkClaimAdmissionMismatch, admitted.validateReference("abc", 3));
    try std.testing.expectEqual(@as(u8, 2), admitted.version);
    try std.testing.expectEqual([_]u8{0x11} ** 32, admitted.manifest_sha256);
    try std.testing.expectEqual([_]u8{0x22} ** 32, admitted.metallib_sha256);
}

test "Stage101 explicit benchmark tuple rejects unknown versions and malformed digests" {
    const allocator = std.testing.allocator;
    const changed = try allocator.dupe(u8, fixture);
    defer allocator.free(changed);
    const version = std.mem.indexOf(u8, changed, ".v2").? + 2;
    changed[version] = '3';
    try std.testing.expectError(error.InvalidStage101BenchmarkAdmission, parse(allocator, changed));
    changed[version] = '2';
    const hash = std.mem.indexOf(u8, changed, "ba7816").?;
    changed[hash] = 'B';
    try std.testing.expectError(error.InvalidStage101BenchmarkAdmission, parse(allocator, changed));
    try std.testing.expectError(error.InvalidStage101BenchmarkAdmission, parseDigest("0" ** 64));
}

test "Stage101 benchmark tuple explicitly pins small circle placement and preserves legacy default" {
    const allocator = std.testing.allocator;
    const old = try parse(allocator, fixture);
    try std.testing.expectEqual(@as(u64, 3), old.small_circle_host_placements);
    const explicit = try std.fmt.allocPrint(allocator, "{s},\"small_circle_host_placements\":0}}", .{fixture[0 .. fixture.len - 1]});
    defer allocator.free(explicit);
    const real = try parse(allocator, explicit);
    try std.testing.expectEqual(@as(u64, 0), real.small_circle_host_placements);
    try real.validateReference("abc", 4);
    try std.testing.expectEqualDeep(old.artifact_sha256, real.artifact_sha256);
}

test "Stage101 benchmark tuple explicitly admits fixed program schema five without changing legacy" {
    const allocator = std.testing.allocator;
    const encoded = try allocator.dupe(u8, fixture);
    defer allocator.free(encoded);
    const position = std.mem.indexOf(u8, encoded, "claim_schema\":4").? + "claim_schema\":".len;
    encoded[position] = '5';
    const admitted = try parse(allocator, encoded);
    try admitted.validateReference("abc", 5);
    try std.testing.expectError(error.Stage101BenchmarkClaimAdmissionMismatch, admitted.validateReference("abc", 4));
    encoded[position] = '6';
    try std.testing.expectError(error.InvalidStage101BenchmarkAdmission, parse(allocator, encoded));
}
