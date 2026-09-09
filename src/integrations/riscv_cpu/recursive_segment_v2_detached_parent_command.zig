//! Detached parent artifact custody: a bundle never supplies its own admission.
const std = @import("std");
const core = @import("stwo_core");
const verifier = @import("recursive_segment_v2_detached_parent_verifier.zig");
const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
pub const MAX_KEY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 128 * 1024;
pub fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
pub const OwnedKeyV1 = opaque {
    const Storage = struct { allocator: std.mem.Allocator, parsed: std.json.Parsed(verifier.KeyV1) };
    pub fn admit(allocator: std.mem.Allocator, bytes: []const u8, independent_sha256: [32]u8) !*OwnedKeyV1 {
        if (bytes.len == 0 or bytes.len > MAX_KEY_BYTES) return error.DetachedParentKeySizeMismatch;
        if (!std.meta.eql(hash(bytes), independent_sha256)) return error.DetachedParentKeyHashMismatch;
        const parsed = try std.json.parseFromSlice(verifier.KeyV1, allocator, bytes, .{ .allocate = .alloc_always });
        errdefer parsed.deinit();
        try parsed.value.validate();
        const storage = try allocator.create(Storage);
        storage.* = .{ .allocator = allocator, .parsed = parsed };
        return @ptrCast(storage);
    }
    pub fn key(self: *const OwnedKeyV1) *const verifier.KeyV1 {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        return &storage.parsed.value;
    }
    pub fn deinit(self: *OwnedKeyV1) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        const allocator = storage.allocator;
        storage.parsed.deinit();
        allocator.destroy(storage);
    }
};
pub fn decodeExpected(allocator: std.mem.Allocator, bytes: []const u8) !verifier.ExpectedV1 {
    if (bytes.len == 0 or bytes.len > MAX_INPUT_BYTES) return error.DetachedParentInputSizeMismatch;
    const parsed = try std.json.parseFromSlice([@typeInfo(verifier.ExpectedV1).array.len]u32, allocator, bytes, .{});
    defer parsed.deinit();
    var result: verifier.ExpectedV1 = undefined;
    for (parsed.value, &result) |word, *field| {
        if (word >= core.fields.m31.Modulus) return error.DetachedParentNonCanonicalField;
        field.* = core.fields.m31.M31.fromCanonical(word);
    }
    try protocol.validateExpected(&result);
    return result;
}
pub fn encodeExpected(allocator: std.mem.Allocator, expected: *const verifier.ExpectedV1) ![]u8 {
    try protocol.validateExpected(expected);
    var words: [@typeInfo(verifier.ExpectedV1).array.len]u32 = undefined;
    for (expected, &words) |word, *value| value.* = word.toU32();
    return std.json.Stringify.valueAlloc(allocator, words, .{});
}
pub const ClaimsFileV1 = struct {
    version: u32 = protocol.VERSION,
    claims: verifier.ClaimsV1,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};
pub fn decodeClaims(allocator: std.mem.Allocator, bytes: []const u8) !ClaimsFileV1 {
    if (bytes.len == 0 or bytes.len > MAX_INPUT_BYTES) return error.DetachedParentInputSizeMismatch;
    const parsed = try std.json.parseFromSlice(ClaimsFileV1, allocator, bytes, .{});
    defer parsed.deinit();
    const value = parsed.value;
    if (value.version != protocol.VERSION or value.proof_bytes == 0 or value.proof_bytes > verifier.MAX_PROOF_BYTES)
        return error.DetachedParentClaimsEnvelopeMismatch;
    return value;
}
pub const CandidateHashesV1 = struct { key_sha256: [32]u8, claims_sha256: [32]u8, proof_sha256: [32]u8, proof_bytes: usize };
/// New directory only. These hashes describe a candidate; they do not admit it.
pub fn retainCandidate(allocator: std.mem.Allocator, directory: []const u8, key_json: []const u8, claims: verifier.ClaimsV1, proof: []const u8) !CandidateHashesV1 {
    if (key_json.len == 0 or key_json.len > MAX_KEY_BYTES or proof.len == 0 or proof.len > verifier.MAX_PROOF_BYTES)
        return error.DetachedParentCandidateSizeMismatch;
    const proof_sha256 = hash(proof);
    const claims_json = try std.json.Stringify.valueAlloc(allocator, ClaimsFileV1{ .claims = claims, .proof_bytes = proof.len, .proof_sha256 = proof_sha256 }, .{});
    defer allocator.free(claims_json);
    if (claims_json.len > MAX_INPUT_BYTES) return error.DetachedParentInputSizeMismatch;
    try std.fs.cwd().makeDir(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    inline for (.{ "key.json", "claims.json", "proof.bin" }, .{ key_json, claims_json, proof }) |name, bytes| {
        var file = try dir.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
    }
    return .{ .key_sha256 = hash(key_json), .claims_sha256 = hash(claims_json), .proof_sha256 = proof_sha256, .proof_bytes = proof.len };
}
pub const ReceiptV1 = struct {
    endpoint: []const u8 = "verified_segment_v2_detached_two_child_parent_development_q3",
    development_only: bool = true,
    verified: bool = true,
    native_inputs_used: bool = false,
    key_sha256: [32]u8,
    expected_root_sha256: [32]u8,
    claims_sha256: [32]u8,
    proof_sha256: [32]u8,
    proof_bytes: usize,
    request_ns: u64,
    verify_ns: u64,
    transcript_digest: [8]u32,
};
pub fn verifyDirectory(allocator: std.mem.Allocator, directory: []const u8, independent_key_sha256: [32]u8, expected_path: []const u8) !ReceiptV1 {
    var timer = try std.time.Timer.start();
    var receipt = try verifyDirectoryInner(allocator, directory, independent_key_sha256, expected_path);
    receipt.request_ns = timer.read(); // Includes all owner/file/proof cleanup.
    return receipt;
}
fn verifyDirectoryInner(allocator: std.mem.Allocator, directory: []const u8, independent_key_sha256: [32]u8, expected_path: []const u8) !ReceiptV1 {
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const key_json = try dir.readFileAlloc(allocator, "key.json", MAX_KEY_BYTES);
    defer allocator.free(key_json);
    const key = try OwnedKeyV1.admit(allocator, key_json, independent_key_sha256);
    defer key.deinit();
    const expected_json = try std.fs.cwd().readFileAlloc(allocator, expected_path, MAX_INPUT_BYTES);
    defer allocator.free(expected_json);
    const expected = try decodeExpected(allocator, expected_json);
    const claims_json = try dir.readFileAlloc(allocator, "claims.json", MAX_INPUT_BYTES);
    defer allocator.free(claims_json);
    const claims = try decodeClaims(allocator, claims_json);
    const proof = try dir.readFileAlloc(allocator, "proof.bin", claims.proof_bytes);
    defer allocator.free(proof);
    if (proof.len != claims.proof_bytes or !std.meta.eql(hash(proof), claims.proof_sha256)) return error.DetachedParentProofIdentityMismatch;
    var timer = try std.time.Timer.start();
    const terminal = try verifier.verify(allocator, key.key(), &expected, claims.claims, proof);
    return .{ .key_sha256 = independent_key_sha256, .expected_root_sha256 = hash(expected_json), .claims_sha256 = hash(claims_json), .proof_sha256 = claims.proof_sha256, .proof_bytes = proof.len, .request_ns = 0, .verify_ns = timer.read(), .transcript_digest = terminal };
}
pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 5 and std.mem.eql(u8, args[1], "--derive-expected")) {
        const expected = try deriveExpected(allocator, .{ args[2], args[3] });
        const json = try encodeExpected(allocator, &expected);
        defer allocator.free(json);
        var file = try std.fs.cwd().createFile(args[4], .{ .exclusive = true });
        defer file.close();
        try file.writeAll(json);
        return;
    }
    if (args.len != 4 or args[1].len == 0 or args[2].len != 64 or args[3].len == 0) return error.ExpectedBundleIndependentKeyAndRootWords;
    var key_sha256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key_sha256, args[2]);
    const receipt = try verifyDirectory(allocator, args[1], key_sha256, args[3]);
    const json = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

/// Derive the expected root from caller-owned public inputs only. No candidate
/// key, proof, claim or producer-generated root participates in this operation.
pub fn deriveExpected(allocator: std.mem.Allocator, paths: [2][]const u8) !verifier.ExpectedV1 {
    const child = @import("recursive_segment_v2_detached_command.zig");
    const frontend = @import("stwo_riscv_frontend");
    var inputs: [2]child.OwnedExpectedV1 = undefined;
    var initialized: usize = 0;
    defer for (inputs[0..initialized]) |*input| input.deinit();
    for (paths, &inputs) |path, *input| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, child.MAX_INPUT_BYTES);
        defer allocator.free(bytes);
        input.* = try child.OwnedExpectedV1.decode(allocator, bytes);
        initialized += 1;
    }
    _ = try frontend.air.public_data_v2.PublicDataV2.authenticateAdjacent(&inputs[0].data, &inputs[1].data);
    const left = try inputs[0].data.authenticatedView();
    const right = try inputs[1].data.authenticatedView();
    const span = frontend.recursion.span_statement;
    const folded = try span.SpanStatement.fold(try left.statement.base(), try right.statement.base());
    _ = try span.RootStatement.init(folded);
    return folded.canonicalWords();
}
