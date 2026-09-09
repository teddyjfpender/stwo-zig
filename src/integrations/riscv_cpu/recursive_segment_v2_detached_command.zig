//! Durable small SegmentV2 proof transport. The caller supplies circuit admission
//! and expected statement separately; candidate storage confers no authority.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const verifier = @import("recursive_segment_v2_detached_verifier.zig");
const M31 = core.fields.m31.M31;
const PublicData = frontend.air.public_data_v2.PublicDataV2;
pub const MAX_KEY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 128 * 1024;
const VERSION: u32 = 1;

pub fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

pub const OwnedKeyV1 = opaque {
    const Storage = struct { allocator: std.mem.Allocator, parsed: std.json.Parsed(verifier.KeyV1) };
    pub fn admit(allocator: std.mem.Allocator, bytes: []const u8, independent_sha256: [32]u8) !*OwnedKeyV1 {
        if (bytes.len == 0 or bytes.len > MAX_KEY_BYTES) return error.DetachedKeySizeMismatch;
        if (!std.meta.eql(hash(bytes), independent_sha256)) return error.DetachedKeyHashMismatch;
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

pub const OwnedExpectedV1 = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    data: PublicData,
    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !OwnedExpectedV1 {
        if (bytes.len == 0 or bytes.len > MAX_INPUT_BYTES) return error.DetachedPublicInputSizeMismatch;
        const parsed = try std.json.parseFromSlice([]const u32, allocator, bytes, .{});
        defer parsed.deinit();
        if (parsed.value.len == 0) return error.DetachedPublicInputSizeMismatch;
        const words = try allocator.alloc(M31, parsed.value.len);
        errdefer allocator.free(words);
        for (parsed.value, words) |value, *word| {
            if (value >= core.fields.m31.Modulus) return error.DetachedNoncanonicalPublicWord;
            word.* = M31.fromCanonical(value);
        }
        return .{ .allocator = allocator, .words = words, .data = try PublicData.authenticate(words) };
    }
    pub fn deinit(self: *OwnedExpectedV1) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }
};

pub fn encodeExpected(allocator: std.mem.Allocator, expected: *const PublicData) ![]u8 {
    _ = try expected.metadata();
    const words = try allocator.alloc(u32, expected.words().len);
    defer allocator.free(words);
    for (expected.words(), words) |word, *value| value.* = word.toU32();
    const bytes = try std.json.Stringify.valueAlloc(allocator, words, .{});
    errdefer allocator.free(bytes);
    if (bytes.len > MAX_INPUT_BYTES) return error.DetachedPublicInputSizeMismatch;
    return bytes;
}

pub const ClaimsFileV1 = struct {
    version: u32 = VERSION,
    claims: verifier.ClaimsV1,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

pub fn decodeClaims(allocator: std.mem.Allocator, bytes: []const u8) !ClaimsFileV1 {
    if (bytes.len == 0 or bytes.len > MAX_INPUT_BYTES) return error.DetachedClaimsSizeMismatch;
    const parsed = try std.json.parseFromSlice(ClaimsFileV1, allocator, bytes, .{});
    defer parsed.deinit();
    const value = parsed.value;
    if (value.version != VERSION) return error.DetachedClaimsVersionMismatch;
    if (value.proof_bytes == 0 or value.proof_bytes > verifier.MAX_PROOF_BYTES) return error.DetachedProofSizeMismatch;
    return value; // Fixed arrays and scalars only; AIR claim admission follows.
}

pub const CandidateHashesV1 = struct {
    key_sha256: [32]u8,
    claims_sha256: [32]u8,
    proof_sha256: [32]u8,
    proof_bytes: usize,
};

/// Creates a new explicit directory. Hashes describe stored bytes, never an
/// independent circuit admission. Failed candidates remain available to debug.
pub fn retainCandidate(allocator: std.mem.Allocator, directory: []const u8, key_json: []const u8, claims: verifier.ClaimsV1, proof: []const u8) !CandidateHashesV1 {
    if (key_json.len == 0 or key_json.len > MAX_KEY_BYTES) return error.DetachedKeySizeMismatch;
    if (proof.len == 0 or proof.len > verifier.MAX_PROOF_BYTES) return error.DetachedProofSizeMismatch;
    const proof_sha256 = hash(proof);
    const claims_json = try std.json.Stringify.valueAlloc(allocator, ClaimsFileV1{ .claims = claims, .proof_bytes = proof.len, .proof_sha256 = proof_sha256 }, .{});
    defer allocator.free(claims_json);
    if (claims_json.len > MAX_INPUT_BYTES) return error.DetachedClaimsSizeMismatch;
    try std.fs.cwd().makeDir(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    try writeNew(dir, "key.json", key_json);
    try writeNew(dir, "claims.json", claims_json);
    try writeNew(dir, "proof.bin", proof);
    return .{ .key_sha256 = hash(key_json), .claims_sha256 = hash(claims_json), .proof_sha256 = proof_sha256, .proof_bytes = proof.len };
}

fn writeNew(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try dir.createFile(name, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
}

pub const ReceiptV1 = struct {
    endpoint: []const u8 = "verified_segment_v2_detached_development_q3",
    development_only: bool = true,
    verified: bool = true,
    native_inputs_used: bool = false,
    key_sha256: [32]u8,
    expected_wire_sha256: [32]u8,
    claims_sha256: [32]u8,
    proof_sha256: [32]u8,
    proof_bytes: usize,
    request_ns: u64,
    verify_ns: u64,
    transcript_digest: [8]u32,
};

pub fn verifyDirectory(allocator: std.mem.Allocator, directory: []const u8, independent_key_sha256: [32]u8, expected_wire_path: []const u8) !ReceiptV1 {
    var request_timer = try std.time.Timer.start();
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const key_json = try dir.readFileAlloc(allocator, "key.json", MAX_KEY_BYTES);
    defer allocator.free(key_json);
    const key = try OwnedKeyV1.admit(allocator, key_json, independent_key_sha256);
    defer key.deinit();
    const expected_json = try std.fs.cwd().readFileAlloc(allocator, expected_wire_path, MAX_INPUT_BYTES);
    defer allocator.free(expected_json);
    var expected = try OwnedExpectedV1.decode(allocator, expected_json);
    defer expected.deinit();
    const claims_json = try dir.readFileAlloc(allocator, "claims.json", MAX_INPUT_BYTES);
    defer allocator.free(claims_json);
    const input = try decodeClaims(allocator, claims_json);
    const proof = try dir.readFileAlloc(allocator, "proof.bin", input.proof_bytes);
    defer allocator.free(proof);
    if (proof.len != input.proof_bytes or !std.meta.eql(hash(proof), input.proof_sha256)) return error.DetachedProofIdentityMismatch;
    var timer = try std.time.Timer.start();
    const terminal = try verifier.verify(allocator, key.key(), &expected.data, input.claims, proof);
    const verify_ns = timer.read();
    return .{ .endpoint = switch (key.key().profile) {
        .development_q3_v1 => "verified_segment_v2_detached_development_q3",
        .recursive_q193_v1 => "verified_segment_v2_detached_q193",
    }, .key_sha256 = independent_key_sha256, .expected_wire_sha256 = hash(expected_json), .claims_sha256 = hash(claims_json), .proof_sha256 = input.proof_sha256, .proof_bytes = proof.len, .request_ns = request_timer.read(), .verify_ns = verify_ns, .transcript_digest = terminal };
}

pub const ArgumentsV1 = struct { directory: []const u8, independent_key_sha256: [32]u8, expected_wire_path: []const u8 };
pub fn parseArguments(args: []const []const u8) !ArgumentsV1 {
    if (args.len != 3 or args[0].len == 0 or args[1].len != 64 or args[2].len == 0 or std.mem.startsWith(u8, args[0], "--")) return error.ExpectedDirectoryIndependentKeyAndPublicWire;
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, args[1]);
    return .{ .directory = args[0], .independent_key_sha256 = key, .expected_wire_path = args[2] };
}

pub const PairReceiptV1 = struct {
    endpoint: []const u8 = "verified_segment_v2_pair_development_q3",
    development_only: bool = true,
    verified: bool = true,
    recursive_parent_proof: bool = false,
    native_inputs_used: bool = false,
    children: [2]ReceiptV1,
    adjacency: frontend.recursion.segment_statement_v2.AdjacentReceiptV2,
    root: frontend.recursion.span_statement.RootStatement,
};

/// Verify each proof independently, then authenticate exact sparse memory,
/// register clocks, global position and complete-job coverage from the expected
/// public wires. This is a verified two-proof bundle, not a recursive parent.
pub fn verifyPair(allocator: std.mem.Allocator, inputs: [2]ArgumentsV1) !PairReceiptV1 {
    var receipts: [2]ReceiptV1 = undefined;
    var expected: [2]OwnedExpectedV1 = undefined;
    var initialized: usize = 0;
    defer for (expected[0..initialized]) |*value| value.deinit();
    for (inputs, 0..) |input, index| {
        receipts[index] = try verifyDirectory(allocator, input.directory, input.independent_key_sha256, input.expected_wire_path);
        const bytes = try std.fs.cwd().readFileAlloc(allocator, input.expected_wire_path, MAX_INPUT_BYTES);
        defer allocator.free(bytes);
        if (!std.meta.eql(hash(bytes), receipts[index].expected_wire_sha256))
            return error.DetachedExpectedWireChanged;
        expected[index] = try OwnedExpectedV1.decode(allocator, bytes);
        initialized += 1;
    }
    const adjacency = try PublicData.authenticateAdjacent(&expected[0].data, &expected[1].data);
    const left = try expected[0].data.authenticatedView();
    const right = try expected[1].data.authenticatedView();
    const span = frontend.recursion.span_statement;
    const folded = try span.SpanStatement.fold(try left.statement.base(), try right.statement.base());
    return .{ .children = receipts, .adjacency = adjacency, .root = try span.RootStatement.init(folded) };
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const json = if (args.len == 8 and std.mem.eql(u8, args[1], "--pair")) blk: {
        const inputs: [2]ArgumentsV1 = .{ try parseArguments(args[2..5]), try parseArguments(args[5..8]) };
        break :blk try std.json.Stringify.valueAlloc(allocator, try verifyPair(allocator, inputs), .{});
    } else blk: {
        const input = try parseArguments(args[1..]);
        break :blk try std.json.Stringify.valueAlloc(allocator, try verifyDirectory(allocator, input.directory, input.independent_key_sha256, input.expected_wire_path), .{});
    };
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
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
